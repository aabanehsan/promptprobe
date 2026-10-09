"""Anthropic Messages API."""

from __future__ import annotations

from ..models import Message
from .base import HTTPTarget, TargetError


class AnthropicTarget(HTTPTarget):
    def validate(self) -> None:
        self.api_key("ANTHROPIC_API_KEY")

    async def chat(self, messages: list[Message]) -> str:
        key = self.api_key("ANTHROPIC_API_KEY")
        system = "\n\n".join(m.content for m in messages if m.role == "system")
        convo = [m.to_dict() for m in messages if m.role != "system"]

        body = {
            "model": self.cfg["model"],
            "max_tokens": self.cfg.get("max_tokens", 512),
            "temperature": self.cfg.get("temperature", 0.7),
            "messages": convo,
        }
        if system:
            body["system"] = system

        headers = {
            "x-api-key": key or "",
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }
        base = self.cfg.get("base_url", "https://api.anthropic.com").rstrip("/")
        data = await self.post_json(f"{base}/v1/messages", headers, body)
        try:
            return "".join(b.get("text", "") for b in data["content"] if b.get("type") == "text")
        except (KeyError, TypeError) as e:
            raise TargetError(f"unexpected response shape: {str(data)[:300]}") from e
