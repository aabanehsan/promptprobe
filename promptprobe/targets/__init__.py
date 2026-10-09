from __future__ import annotations

from typing import Any

from .anthropic import AnthropicTarget
from .base import Target, TargetError
from .http_generic import GenericHTTPTarget
from .mock import MockTarget
from .openai_compat import OpenAICompatTarget

TARGET_TYPES: dict[str, type[Target]] = {
    "openai": OpenAICompatTarget,
    "ollama": OpenAICompatTarget,
    "anthropic": AnthropicTarget,
    "http": GenericHTTPTarget,
    "mock": MockTarget,
}


def make_target(cfg: dict[str, Any]) -> Target:
    kind = cfg.get("type", "mock")
    if kind == "ollama":
        cfg = {"base_url": "http://localhost:11434/v1", **cfg}
    try:
        cls = TARGET_TYPES[kind]
    except KeyError:
        raise TargetError(f"unknown target type '{kind}'. Choose from: {', '.join(TARGET_TYPES)}") from None
    if kind in ("openai", "ollama", "anthropic") and not cfg.get("model"):
        raise TargetError(f"target type '{kind}' needs a 'model'")
    if kind == "http" and not cfg.get("url"):
        raise TargetError("target type 'http' needs a 'url'")
    target = cls(cfg)
    target.validate()
    return target


__all__ = ["Target", "TargetError", "make_target", "TARGET_TYPES"]
