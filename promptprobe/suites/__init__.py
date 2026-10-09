"""Load attack suites from YAML."""

from __future__ import annotations

from importlib import resources
from pathlib import Path
from typing import Any, Iterable

import yaml

from ..detectors import REGISTRY
from ..models import Severity, TestCase


class SuiteError(ValueError):
    pass


def builtin_suite_files() -> list[Path]:
    root = resources.files(__package__)
    return sorted(Path(str(p)) for p in root.iterdir() if str(p).endswith(".yaml"))


def _parse(doc: dict[str, Any], source: str) -> list[TestCase]:
    category = doc.get("category")
    if not category:
        raise SuiteError(f"{source}: missing top-level 'category'")
    defaults = {"owasp": doc.get("owasp", ""), "detectors": doc.get("detectors", ["canary_echo"])}
    tests = []
    for raw in doc.get("tests", []):
        try:
            tc = TestCase(
                id=raw["id"],
                name=raw["name"],
                category=category,
                severity=Severity(raw.get("severity", "medium")),
                detectors=raw.get("detectors", defaults["detectors"]),
                description=raw.get("description", "").strip(),
                owasp=raw.get("owasp", defaults["owasp"]),
                prompt=raw.get("prompt"),
                turns=raw.get("turns", []),
                encode=raw.get("encode"),
                encoding=raw.get("encoding"),
                references=raw.get("references", []),
            )
        except KeyError as e:
            raise SuiteError(f"{source}: test is missing field {e}: {raw}") from None
        except ValueError as e:
            raise SuiteError(f"{source}: {raw.get('id', '?')}: {e}") from None
        if not tc.prompt and not tc.turns:
            raise SuiteError(f"{source}: {tc.id} needs 'prompt' or 'turns'")
        if bool(tc.encode) != bool(tc.encoding):
            raise SuiteError(f"{source}: {tc.id} needs both 'encode' and 'encoding'")
        unknown = [d for d in tc.detectors if d not in REGISTRY]
        if unknown:
            raise SuiteError(f"{source}: {tc.id} uses unknown detector(s) {unknown}")
        tests.append(tc)
    return tests


def load_suites(paths: Iterable[str | Path] | None = None, include_builtin: bool = True) -> list[TestCase]:
    files: list[Path] = builtin_suite_files() if include_builtin else []
    for p in paths or []:
        p = Path(p)
        files.extend(sorted(p.glob("*.yaml")) + sorted(p.glob("*.yml")) if p.is_dir() else [p])

    tests: list[TestCase] = []
    seen: set[str] = set()
    for f in files:
        with open(f, encoding="utf-8") as fh:
            doc = yaml.safe_load(fh) or {}
        for tc in _parse(doc, f.name):
            if tc.id in seen:
                raise SuiteError(f"duplicate test id {tc.id} in {f.name}")
            seen.add(tc.id)
            tests.append(tc)
    return tests


def filter_tests(
    tests: list[TestCase],
    categories: list[str] | None = None,
    ids: list[str] | None = None,
    min_severity: str | None = None,
) -> list[TestCase]:
    out = tests
    if categories:
        cats = {c.lower() for c in categories}
        out = [t for t in out if t.category.lower() in cats]
    if ids:
        wanted = {i.upper() for i in ids}
        out = [t for t in out if t.id.upper() in wanted or any(t.id.upper().startswith(w) for w in wanted)]
    if min_severity:
        floor = Severity(min_severity).rank
        out = [t for t in out if t.severity.rank >= floor]
    return out
