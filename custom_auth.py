from litellm.proxy._types import UserAPIKeyAuth, LitellmUserRoles
from fastapi import Request
import os
import json
import base64
from typing import Optional, Dict, Any
import httpx


def extract_jwt_token_from_cookies(cookies: str) -> Optional[str]:
    """Extract JWT token from cookie string."""
    if "token=" not in cookies:
        return None

    token_start = cookies.find("token=") + 6
    token_end = cookies.find(";", token_start)
    return cookies[token_start:token_end] if token_end != -1 else cookies[token_start:]


def decode_jwt_payload(token: str) -> Optional[Dict[str, Any]]:
    """Decode JWT payload without verification."""
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return None

        # Decode base64 payload with proper padding
        payload = parts[1]
        payload += "=" * (4 - len(payload) % 4)
        decoded_payload = base64.b64decode(payload)
        return json.loads(decoded_payload.decode("utf-8"))
    except Exception as e:
        print(f"JWT decode error: {e}")
        return None


async def user_api_key_auth(request: Request, api_key: str) -> UserAPIKeyAuth:
    """
    Custom authentication hook for LiteLLM proxy.

    Handles:
    1. Direct master key authentication
    2. Admin UI session tokens (via JWT in cookies)
    3. Regular user authentication
    """
    try:

        print(f"Request headers: {dict(request.headers)}")

        cookies = request.headers.get("cookie", "")
        if cookies:
            jwt_token = extract_jwt_token_from_cookies(cookies)
            if jwt_token:
                jwt_payload = decode_jwt_payload(jwt_token)

                if (
                    jwt_payload
                    and jwt_payload.get("user_role") == LitellmUserRoles.PROXY_ADMIN
                ):
                    print("Admin session detected from JWT")
                    return UserAPIKeyAuth(
                        api_key=api_key,
                        user_role=LitellmUserRoles.PROXY_ADMIN,
                        user_id=jwt_payload.get("user_id", "admin_user"),
                        user_email=jwt_payload.get("user_email"),
                    )

        # request.headers = {'x-api-key': 'sk-PIw_aAROlj8wT8L26oZMvg', 'x-user-id': '687cf1a7602732b770f1e57e', 'x-user-email': 'malka2039@gmail.com', 'x-target': 'LibreChat'}
        headers = {str(k).lower(): v for k, v in request.headers.items()}

        print(f"Request headers 2: {dict(headers)}")
        if headers.get("x-target") == "LibreChat":
            print("LibreChat Header")
            user_email = headers.get("x-user-email")
            print(f"User Email LibreChat: {user_email}")
            if user_email:
                try:
                    supabase_key = (
                        os.getenv("SUPABASE_SERVICE_ROLE_KEY")
                        or os.getenv("SUPABASE_ANON_KEY")
                        or os.getenv("SUPABASE_API_KEY")
                    )
                    print(f"supabase key: {supabase_key}")
                    if not supabase_key:
                        raise Exception(
                            "Missing Supabase credentials: set SUPABASE_SERVICE_ROLE_KEY (preferred) or SUPABASE_ANON_KEY"
                        )
                    async with httpx.AsyncClient(timeout=10) as client:
                        supabase_response = await client.post(
                            "https://teeajhrpdxxzgwuyfumk.supabase.co/functions/v1/get_litellm_api_key_by_email",
                            json={"email": user_email},
                            headers={
                                "Content-Type": "application/json",
                                "apikey": supabase_key,
                                "Authorization": f"Bearer {supabase_key}",
                            },
                        )
                        supabase_response.raise_for_status()
                        response_data = supabase_response.json()
                        print(f"response_data: {response_data}")
                        fetched_api_key = response_data.get("api_key")
                        if fetched_api_key:
                            print(
                                f"api_key set from Supabase function: {fetched_api_key}"
                            )
                            return UserAPIKeyAuth(
                                api_key=fetched_api_key,
                                metadata={"source": "LibreChat"},
                            )
                        raise Exception("Supabase response missing api_key")
                except Exception as supabase_error:
                    print(f"Failed to fetch api key from Supabase: {supabase_error}")
                    raise
            else:
                raise Exception("LibreChat request missing x-user-email header")

        # Handle internal API keys (sk-api prefix)
        if api_key.startswith("sk-api"):
            print(f"Internal API key detected: {api_key[:10]}...")
            try:
                supabase_key = (
                    os.getenv("SUPABASE_SERVICE_ROLE_KEY")
                    or os.getenv("SUPABASE_ANON_KEY")
                    or os.getenv("SUPABASE_API_KEY")
                )
                if not supabase_key:
                    raise Exception(
                        "Missing Supabase credentials: set SUPABASE_SERVICE_ROLE_KEY (preferred) or SUPABASE_ANON_KEY"
                    )
                
                async with httpx.AsyncClient(timeout=10) as client:
                    # Query internal_keys table joined with members table
                    supabase_response = await client.get(
                        "https://teeajhrpdxxzgwuyfumk.supabase.co/rest/v1/internal_keys",
                        params={
                            "key": f"eq.{api_key}",
                            "select": "member_id,members(litellm_api_key)"
                        },
                        headers={
                            "apikey": supabase_key,
                            "Authorization": f"Bearer {supabase_key}",
                        },
                    )
                    supabase_response.raise_for_status()
                    response_data = supabase_response.json()
                    print(f"Internal key lookup response: {response_data}")
                    
                    if response_data and len(response_data) > 0:
                        member_data = response_data[0].get("members")
                        if member_data and member_data.get("litellm_api_key"):
                            litellm_api_key = member_data["litellm_api_key"]
                            print(f"Replacing internal key with member's LiteLLM key: {litellm_api_key[:10]}...")
                            return UserAPIKeyAuth(
                                api_key=litellm_api_key,
                                metadata={"source": "API"}
                            )
                        raise Exception("Member data or litellm_api_key not found")
                    raise Exception("Internal key not found in database")
            except Exception as internal_key_error:
                print(f"Failed to process internal API key: {internal_key_error}")
                raise
        
        # if api_key starts with "sk-addon"
        
        print("Regular user authentication")
        return UserAPIKeyAuth(api_key=api_key)

    except Exception as e:
        print(f"Authentication failed: {e}")
        raise Exception("Authentication failed")
