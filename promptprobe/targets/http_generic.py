"""Generic HTTP target for testing your own app's chat endpoint.

This is the one to use when you're testing a real product (a support bot,
a RAG app) instead of a raw model API, because it goes through the app's own
system prompt, retrieval and filtering.

Config example::

    target:
      type: http
      url: http://localhost:8000/api/chat
      headers: {Authorization: "Bearer ${MY_APP_TOKEN}"}
      body:                       # any JSON; placeholders are substituted
        message: "{{last_user}}"
        history: "{{messages}}"
      response_path: data.reply   # dotted path to the reply text
      send_system_prompt: false   # the app has its own system prompt

Placeholders: {{last_user}} (string), {{messages}} (list of {role, content}),
{{system}} (string). ${ENV_VAR} in headers is expanded from the environment.
"""

from __future__ import annotations

import copy
import os
import re
from typing import Any

from ..models import Message
from .base import HTTPTarget, TargetError


def _expand_env(value: str) -> str:
    return re.sub(r"\$\{(\w+)\}", lambda m: os.environ.get(m.group(1), ""), value)


def _fill(node: Any, values: dict[str, Any]) -> Any:
    if isinstance(node, str):
        for key, val in values.items():
            token = "{{" + key + "}}"
            if node == token:
                return val  # keep non-string types (e.g. lists) intact
            if token in node:
                node = node.replace(token, val if isinstance(val, str) else str(val))
        return node
    if isinstance(node, list):
        return [_fill(n, values) for n in node]
    if isinstance(node, dict):
        return {k: _fill(v, values) for k, v in node.items()}
    return node


def dig(data: Any, path: str) -> Any:
    cur = data
    for part in path.split("."):
        if isinstance(cur, list):
            cur = cur[int(part)]
        else:
            cur = cur[part]
    return cur


class GenericHTTPTarget(HTTPTarget):
    @property
    def label(self) -> str:
        return f"http:{self.cfg.get('url')}"

    async def chat(self, messages: list[Message]) -> str:
        if not self.cfg.get("send_system_prompt", True):
            messages = [m for m in messages if m.role != "system"]
        user_msgs = [m.content for m in messages if m.role == "user"]
        values = {
            "messages": [m.to_dict() for m in messages],
            "last_user": user_msgs[-1] if user_msgs else "",
            "system": "\n".join(m.content for m in messages if m.role == "system"),
        }
        body = _fill(copy.deepcopy(self.cfg.get("body", {"messages": "{{messages}}"})), values)
        headers = {"Content-Type": "application/json"}
        headers.update({k: _expand_env(str(v)) for k, v in self.cfg.get("headers", {}).items()})

        data = await self.post_json(self.cfg["url"], headers, body)
        try:
            out = dig(data, self.cfg.get("response_path", "reply"))
        except (KeyError, IndexError, ValueError, TypeError) as e:
            raise TargetError(
                f"response_path '{self.cfg.get('response_path')}' not found in: {str(data)[:300]}"
            ) from e
        return out if isinstance(out, str) else str(out)
