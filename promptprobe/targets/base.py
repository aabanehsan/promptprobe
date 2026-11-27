"""Target interface. A target takes a conversation and returns the model's reply."""

from __future__ import annotations

import asyncio
import os
import random
import time
from abc import ABC, abstractmethod
from email.utils import parsedate_to_datetime
from typing import Any

import httpx

from ..models import Message


class TargetError(RuntimeError):
    pass


RETRY_STATUSES = frozenset({408, 409, 429, 500, 502, 503, 504})
MAX_DELAY = 30.0


def parse_retry_after(value: str | None, now: float | None = None) -> float | None:
    """Return the wait in seconds from a Retry-After header, or None if unusable.

    Accepts both forms from RFC 9110: delay-seconds ("120") and an HTTP-date
    ("Wed, 21 Oct 2026 07:28:00 GMT"). Negative or unparseable values give None.
    """
    if not value:
        return None
    value = value.strip()
    try:
        secs = float(value)
    except ValueError:
        try:
            when = parsedate_to_datetime(value)
        except (TypeError, ValueError):
            return None
        if when is None:
            return None
        secs = when.timestamp() - (time.time() if now is None else now)
    if secs != secs or secs < 0:  # NaN or in the past
        return None
    return secs


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
        """POST JSON and return the decoded reply, retrying transient failures.

        Retries network errors and HTTP 408/409/429/5xx up to ``max_retries``
        times with exponential backoff (1s, 2s, 4s ... capped at 30s) plus
        jitter. A Retry-After header raises the wait for that attempt, still
        capped at 30s so one bad header can't stall a whole run.
        """
        delay = float(self.cfg.get("backoff_base", 1.0))
        last = "no attempts made"
        for attempt in range(self.max_retries + 1):
            wait = delay
            try:
                r = await self._client.post(url, headers=headers, json=body)
            except httpx.TransportError as e:
                last = f"network error: {e}"
            else:
                if r.status_code < 400:
                    try:
                        return r.json()
                    except ValueError as e:
                        raise TargetError(f"response was not JSON: {r.text[:300]}") from e
                if r.status_code not in RETRY_STATUSES:
                    raise TargetError(f"HTTP {r.status_code}: {r.text[:300]}")
                last = f"HTTP {r.status_code}: {r.text[:300]}"
                hinted = parse_retry_after(r.headers.get("retry-after"))
                if hinted is not None:
                    wait = max(wait, hinted)
            if attempt == self.max_retries:
                break
            await asyncio.sleep(min(wait, MAX_DELAY) + random.random() * 0.5)
            delay = min(delay * 2, MAX_DELAY)
        tries = self.max_retries + 1
        raise TargetError(f"{last} (gave up after {tries} attempt{'s' if tries != 1 else ''})")

    async def aclose(self) -> None:
        await self._client.aclose()
