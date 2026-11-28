"""SARIF 2.1.0 writer, so findings show up in GitHub code scanning.

promptprobe tests a model, not source code, so there is no line that "has" the
bug. Every finding points at the file that defines what is being defended: the
system prompt file if one was given, otherwise the config file. That is the
file you change to fix a finding, and it gives code scanning a stable place to
anchor alerts.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath

from .. import __version__
from ..models import Severity, TestResult, Verdict
from ..runner import RunReport

SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
INFO_URI = "https://github.com/aabanehsan/promptprobe"
DEFAULT_ARTIFACT = "promptprobe.yaml"

# SARIF "level" plus the numeric "security-severity" GitHub uses to label alerts
# (>= 9.0 critical, >= 7.0 high, >= 4.0 medium, otherwise low).
LEVELS = {
    Severity.CRITICAL: ("error", "9.5"),
    Severity.HIGH: ("error", "8.0"),
    Severity.MEDIUM: ("warning", "5.5"),
    Severity.LOW: ("note", "3.0"),
}


def artifact_uri(path: str | None) -> str:
    """Normalize a local path into a relative, forward-slash URI."""
    if not path:
        return DEFAULT_ARTIFACT
    p = Path(path)
    if p.is_absolute():
        try:
            p = p.resolve().relative_to(Path.cwd().resolve())
        except ValueError:
            return p.as_uri()
    return str(PurePosixPath(*p.parts)) if p.parts else DEFAULT_ARTIFACT


def _rule(r: TestResult) -> dict:
    t = r.test
    level, sec = LEVELS[t.severity]
    tags = ["security", "llm", t.category]
    if t.owasp:
        tags.append(t.owasp)
    rule = {
        "id": t.id,
        "name": t.name,
        "shortDescription": {"text": t.name},
        "fullDescription": {"text": t.description or t.name},
        "helpUri": t.references[0] if t.references else INFO_URI,
        "defaultConfiguration": {"level": level},
        "properties": {"tags": tags, "security-severity": sec, "precision": "medium"},
    }
    if t.references:
        rule["help"] = {"text": "References:\n" + "\n".join(f"- {u}" for u in t.references)}
    return rule


def _clip(text: str, n: int = 200) -> str:
    text = " ".join(text.split())
    return text if len(text) <= n else text[: n - 3] + "..."


def _result(r: TestResult, index: int, uri: str, target: str) -> dict:
    t = r.test
    tr = next(x for x in r.trials if x.verdict == Verdict.VULNERABLE)
    valid = len(r.trials) - r.errors
    evidence = "; ".join(f"{h.detector}: {_clip(h.evidence)}" for h in tr.hits) or "detector fired"
    msg = (
        f"{t.id} ({t.name}) succeeded against {target} in {r.successes}/{valid} trials. "
        f"Evidence: {evidence}"
    )
    fp = hashlib.sha256(f"{t.id}|{uri}|{target}".encode()).hexdigest()
    return {
        "ruleId": t.id,
        "ruleIndex": index,
        "level": LEVELS[t.severity][0],
        "message": {"text": msg},
        "locations": [
            {"physicalLocation": {"artifactLocation": {"uri": uri}, "region": {"startLine": 1}}}
        ],
        "partialFingerprints": {"promptprobeFinding/v1": fp},
        "properties": {
            "category": t.category,
            "owasp": t.owasp,
            "attack_success_rate": round(r.attack_success_rate, 3),
            "trials": len(r.trials),
        },
    }


def to_sarif(report: RunReport) -> dict:
    uri = artifact_uri(report.config.artifact)
    ordered = sorted(report.results, key=lambda r: r.test.id)
    rules = [_rule(r) for r in ordered]
    index = {r.test.id: i for i, r in enumerate(ordered)}
    results = [
        _result(r, index[r.test.id], uri, report.target)
        for r in ordered
        if r.verdict == Verdict.VULNERABLE
    ]
    notes = [
        {
            "level": "warning",
            "message": {"text": f"{r.test.id}: {next(t.error for t in r.trials if t.error)}"},
            "associatedRule": {"id": r.test.id},
        }
        for r in ordered
        if r.verdict == Verdict.ERROR
    ]
    return {
        "$schema": SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "promptprobe",
                        "version": __version__,
                        "semanticVersion": __version__,
                        "informationUri": INFO_URI,
                        "rules": rules,
                    }
                },
                "automationDetails": {"id": f"promptprobe/{report.target}/"},
                "invocations": [
                    {
                        "executionSuccessful": len(notes) < len(ordered) or not ordered,
                        "startTimeUtc": report.started_at,
                        "endTimeUtc": report.finished_at,
                        "toolExecutionNotifications": notes,
                    }
                ],
                "results": results,
                "properties": {"target": report.target, "summary": report.summary()},
            }
        ],
    }


def write_sarif(report: RunReport, path: Path) -> None:
    path.write_text(json.dumps(to_sarif(report), indent=2, ensure_ascii=False), encoding="utf-8")
