"""Core data types used across promptprobe."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Verdict(str, Enum):
    VULNERABLE = "vulnerable"
    RESISTANT = "resistant"
    ERROR = "error"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return ["low", "medium", "high", "critical"].index(self.value)


@dataclass
class Message:
    role: str  # "system" | "user" | "assistant"
    content: str

    def to_dict(self) -> dict[str, str]:
        return {"role": self.role, "content": self.content}


@dataclass
class TestCase:
    """One attack, loaded from a YAML suite."""

    id: str
    name: str
    category: str
    severity: Severity
    detectors: list[str]
    description: str = ""
    owasp: str = ""
    prompt: str | None = None          # single-turn attack
    turns: list[str] = field(default_factory=list)  # multi-turn attack
    encode: str | None = None          # text to encode, exposed as {encoded}
    encoding: str | None = None        # base64 | rot13 | hex | reverse
    references: list[str] = field(default_factory=list)

    def user_turns(self) -> list[str]:
        if self.turns:
            return list(self.turns)
        return [self.prompt or ""]


@dataclass
class DetectorHit:
    detector: str
    evidence: str


@dataclass
class TrialResult:
    trial: int
    verdict: Verdict
    response: str
    conversation: list[Message]
    hits: list[DetectorHit] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    error: str | None = None
    latency_ms: int = 0


@dataclass
class TestResult:
    test: TestCase
    trials: list[TrialResult]

    @property
    def successes(self) -> int:
        return sum(1 for t in self.trials if t.verdict == Verdict.VULNERABLE)

    @property
    def errors(self) -> int:
        return sum(1 for t in self.trials if t.verdict == Verdict.ERROR)

    @property
    def attack_success_rate(self) -> float:
        valid = len(self.trials) - self.errors
        return self.successes / valid if valid else 0.0

    @property
    def verdict(self) -> Verdict:
        if self.successes:
            return Verdict.VULNERABLE
        if self.errors == len(self.trials):
            return Verdict.ERROR
        return Verdict.RESISTANT

    def to_dict(self) -> dict[str, Any]:
        t = self.test
        return {
            "id": t.id,
            "name": t.name,
            "category": t.category,
            "severity": t.severity.value,
            "owasp": t.owasp,
            "description": t.description,
            "verdict": self.verdict.value,
            "attack_success_rate": round(self.attack_success_rate, 3),
            "trials": [
                {
                    "trial": tr.trial,
                    "verdict": tr.verdict.value,
                    "latency_ms": tr.latency_ms,
                    "hits": [h.__dict__ for h in tr.hits],
                    "notes": tr.notes,
                    "error": tr.error,
                    "conversation": [m.to_dict() for m in tr.conversation],
                    "response": tr.response,
                }
                for tr in self.trials
            ],
        }
