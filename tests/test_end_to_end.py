import json

import pytest

from promptprobe.canary import DEFAULT_SYSTEM_PROMPT
from promptprobe.cli import main
from promptprobe.models import Verdict
from promptprobe.runner import RunConfig, run_tests
from promptprobe.suites import SuiteError, load_suites, _parse
from promptprobe.targets import make_target


def test_builtin_suites_load_and_ids_unique():
    tests = load_suites()
    assert len(tests) >= 35
    assert len({t.id for t in tests}) == len(tests)


async def test_vulnerable_mock_gets_owned():
    tests = load_suites()
    report = await run_tests(make_target({"type": "mock", "model": "vulnerable"}), tests,
                             RunConfig(system_prompt=DEFAULT_SYSTEM_PROMPT))
    s = report.summary()
    assert s["errors"] == 0
    assert s["vulnerable"] >= 25
    # every category should have at least one finding against the gullible bot
    assert all(c["vulnerable"] > 0 for c in s["by_category"].values())


async def test_hardened_mock_resists():
    tests = load_suites()
    report = await run_tests(make_target({"type": "mock", "model": "hardened"}), tests,
                             RunConfig(system_prompt=DEFAULT_SYSTEM_PROMPT, trials=2))
    assert report.summary()["vulnerable"] == 0
    assert all(r.verdict == Verdict.RESISTANT for r in report.results)


def test_bad_suite_rejected():
    with pytest.raises(SuiteError):
        _parse({"category": "x", "tests": [{"id": "A", "name": "a", "prompt": "p", "detectors": ["nope"]}]}, "t")
    with pytest.raises(SuiteError):
        _parse({"category": "x", "tests": [{"id": "A", "name": "a"}]}, "t")


def test_cli_writes_reports_and_fail_on(tmp_path):
    rc = main(["run", "-t", "mock", "-m", "vulnerable", "-o", str(tmp_path), "--fail-on", "high"])
    assert rc == 1
    data = json.loads(next(tmp_path.glob("*.json")).read_text())
    assert data["summary"]["vulnerable"] > 0
    assert next(tmp_path.glob("*.html")).read_text().startswith("<!doctype html>")
    assert "## Findings" in next(tmp_path.glob("*.md")).read_text()

    rc = main(["run", "-t", "mock", "-m", "hardened", "-o", str(tmp_path / "h"), "--fail-on", "low"])
    assert rc == 0


def test_cli_filters(tmp_path, capsys):
    rc = main(["run", "-t", "mock", "--id", "SPL", "-o", str(tmp_path), "-f", "json"])
    assert rc == 0
    data = json.loads(next(tmp_path.glob("*.json")).read_text())
    assert all(r["id"].startswith("SPL") for r in data["results"])
