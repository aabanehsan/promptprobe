"""Target interface. A target takes a conversation and returns the model's reply."""

from __future__ import annotations

import asyncio
import os
import random
from abc import ABC, abstractmethod
from typing import Any

import httpx

from ..models import Message


class TargetError(RuntimeError):
    pass


class Target(ABC):
    def __init__(self, cfg: dict[str, Any]):
        self.cfg = cfg
        self.timeout = float(cfg.get("timeout", 60))
        self.max_retries = int(cfg.get("max_retries", 3))

    @property
    def label(self) -> str:
        return f"{self.cfg.get('type')}:{self.cfg.get('model', '')}".rstrip(":")

    def validate(self) -> None:
        """Raise TargetError early (before any requests) if the config can't work."""

    @abstractmethod
    async def chat(self, messages: list[Message]) -> str: ...

    async def aclose(self) -> None:  # pragma: no cover - overridden where needed
        pass


class HTTPTarget(Target):
    """Shared plumbing for HTTP targets: client, API keys and retries."""

    def __init__(self, cfg: dict[str, Any]):
        super().__init__(cfg)
        self._client = httpx.AsyncClient(timeout=self.timeout)

    def api_key(self, default_env: str | None = None, required: bool = True) -> str | None:
        env = self.cfg.get("api_key_env", default_env)
        key = self.cfg.get("api_key") or (os.environ.get(env) if env else None)
        if required and not key:
            raise TargetError(f"no API key found: set the {env} environment variable")
        return key

    async def post_json(self, url: str, headers: dict[str, str], body: dict[str, Any]) -> Any:
        delay = 1.0
        for attempt in range(self.max_retries + 1):
            try:
                r = await self._client.post(url, headers=headers, json=body)
            except httpx.TransportError as e:
                if attempt == self.max_retries:
                    raise TargetError(f"network error: {e}") from e
            else:
                if r.status_code < 400:
                    return r.json()
                if r.status_code not in (408, 409, 429, 500, 502, 503, 504) or attempt == self.max_retries:
                    raise TargetError(f"HTTP {r.status_code}: {r.text[:300]}")
                retry_after = r.headers.get("retry-after")
                if retry_after and retry_after.replace(".", "").isdigit():
                    delay = max(delay, float(retry_after))
            await asyncio.sleep(delay + random.random() * 0.5)
            delay = min(delay * 2, 30)
        raise TargetError("retries exhausted")  # pragma: no cover

    async def aclose(self) -> None:
        await self._client.aclose()
