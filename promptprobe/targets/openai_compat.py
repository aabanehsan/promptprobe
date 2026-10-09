"""Any server that speaks the OpenAI Chat Completions format.

Works with OpenAI, Azure OpenAI (via base_url), Groq, Together, OpenRouter,
and local servers like Ollama (http://localhost:11434/v1), LM Studio,
vLLM and llama.cpp.
"""

from __future__ import annotations

from ..models import Message
from .base import HTTPTarget, TargetError


class OpenAICompatTarget(HTTPTarget):
    @property
    def _base(self) -> str:
        return self.cfg.get("base_url", "https://api.openai.com/v1").rstrip("/")

    def _key(self) -> str | None:
        is_local = any(h in self._base for h in ("localhost", "127.0.0.1", "0.0.0.0"))
        return self.api_key("OPENAI_API_KEY", required=not is_local)

    def validate(self) -> None:
        self._key()

    async def chat(self, messages: list[Message]) -> str:
        base = self._base
        key = self._key()

        headers = {"Content-Type": "application/json"}
        if key:
            headers["Authorization"] = f"Bearer {key}"
        headers.update(self.cfg.get("headers", {}))

        body = {
            "model": self.cfg["model"],
            "messages": [m.to_dict() for m in messages],
            "temperature": self.cfg.get("temperature", 0.7),
            "max_tokens": self.cfg.get("max_tokens", 512),
        }
        data = await self.post_json(f"{base}/chat/completions", headers, body)
        try:
            return data["choices"][0]["message"]["content"] or ""
        except (KeyError, IndexError, TypeError) as e:
            raise TargetError(f"unexpected response shape: {str(data)[:300]}") from e
