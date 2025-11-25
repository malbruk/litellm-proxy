from litellm.integrations.custom_logger import CustomLogger
from litellm.proxy.proxy_server import UserAPIKeyAuth, DualCache
from litellm.types.utils import ModelResponseStream
from typing import Any, AsyncGenerator, Optional, Literal

from pathlib import Path

def load_system_prompt(path: str = "/app/system_prompt.txt") -> str:
    file_path = Path(path)
    if file_path.exists():
        print("system prompt file exists")
        return file_path.read_text(encoding="utf-8").strip()
    return ""  # fallback

class MyCustomHandler(CustomLogger):
    def __init__(self):
        super().__init__()
        print("CustomHandler initialized")
        self.system_prompt = load_system_prompt()
        print(f"system_prompt {self.system_prompt}")

    async def async_pre_call_hook(
        self,
        user_api_key_dict: UserAPIKeyAuth,
        cache: DualCache,
        data: dict,
        call_type: Literal[
            "completion",
            "text_completion",
            "embeddings",
            "image_generation",
            "moderation",
            "audio_transcription",
        ],
    ):
        print(
            f"Pre call hook: call_type={call_type}, user={user_api_key_dict!r}, data_keys={list(data.keys())}"
        )

        # Only run for requests coming from LibreChat: read header from injected request context
        headers = (data.get("proxy_server_request", {}) or {}).get("headers", {})
        # Normalize header keys to lowercase for simple, case-insensitive lookup
        headers_ci = {str(k).lower(): v for k, v in headers.items()}
        x_target = headers_ci.get("x-target")

        if x_target == "LibreChat":
            if "messages" not in data or not isinstance(data["messages"], list):
                data["messages"] = []

            replaced = False
            for msg in data["messages"]:
                if msg.get("role") == "system":
                    msg["content"] = self.system_prompt
                    replaced = True
                    break

            if not replaced:
                data["messages"].insert(0, {"role": "system", "content": self.system_prompt})

            print(
                f"System prompt injected: replaced={replaced}, total_messages={len(data['messages'])}"
            )
        else:
            print("Skipping system prompt injection (x-target != LibreChat)")

        return data

    async def async_post_call_failure_hook(
        self, request_data: dict, original_exception: Exception,
        user_api_key_dict: UserAPIKeyAuth, traceback_str: Optional[str] = None,
    ):
        print(f"Post call failure hook: user={user_api_key_dict.user_id}, exception={original_exception}, traceback={traceback_str}")

    async def async_post_call_success_hook(
        self, data: dict, user_api_key_dict: UserAPIKeyAuth, response,
    ):
        print(f"Post call success hook: user={user_api_key_dict.user_id}, data_keys={list(data.keys())}, response_type={type(response)}")

    async def async_moderation_hook(
        self, data: dict, user_api_key_dict: UserAPIKeyAuth,
        call_type: Literal["completion", "embeddings", "image_generation", "moderation", "audio_transcription"],
    ):
        print(f"Moderation hook: user={user_api_key_dict.user_id}, call_type={call_type}, data_keys={list(data.keys())}")

    async def async_post_call_streaming_hook(
        self, user_api_key_dict: UserAPIKeyAuth, response: str,
    ):
        print(f"Post call streaming hook: user={user_api_key_dict.user_id}, response_preview={response[:100]}")

    async def async_post_call_streaming_iterator_hook(
        self, user_api_key_dict: UserAPIKeyAuth,
        response: Any, request_data: dict,
    ) -> AsyncGenerator[ModelResponseStream, None]:
        print(f"Streaming iterator hook: user={user_api_key_dict.user_id}, request_data_keys={list(request_data.keys())}")
        async for item in response:
            print(f"Streaming item: {item}")
            yield item


proxy_handler_instance = MyCustomHandler()
