import json

import pytest

from promptprobe.canary import DEFAULT_SYSTEM_PROMPT
from promptprobe.cli import main
from promptprobe.models import Verdict
from promptprobe.report.sarif import LEVELS, artifact_uri, to_sarif
from promptprobe.runner import RunConfig, run_tests
from promptprobe.suites import load_suites
from promptprobe.targets import make_target


async def _report(model: str, artifact: str | None = None, ids: list[str] | None = None):
    tests = load_suites()
    if ids:
        tests = [t for t in tests if t.id in ids]
    return await run_tests(
        make_target({"type": "mock", "model": model}),
        tests,
        RunConfig(system_prompt=DEFAULT_SYSTEM_PROMPT, artifact=artifact),
    )


async def test_vulnerable_run_produces_one_result_per_finding():
    report = await _report("vulnerable", artifact="prompts/system.txt")
    doc = to_sarif(report)
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    assert len(rules) == len(report.results)
    assert len(run["results"]) == len(report.vulnerable) > 0

    rule_ids = [r["id"] for r in rules]
    for res in run["results"]:
        # ruleIndex must point at the matching rule
        assert rule_ids[res["ruleIndex"]] == res["ruleId"]
        loc = res["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"] == "prompts/system.txt"
        assert loc["region"]["startLine"] == 1
        assert res["level"] in {"error", "warning", "note"}
        assert res["partialFingerprints"]["promptprobeFinding/v1"]


async def test_hardened_run_has_rules_but_no_results():
    doc = to_sarif(await _report("hardened"))
    run = doc["runs"][0]
    assert run["results"] == []
    assert run["tool"]["driver"]["rules"]
    assert run["invocations"][0]["executionSuccessful"] is True


async def test_severity_maps_to_level_and_security_severity():
    report = await _report("vulnerable")
    doc = to_sarif(report)
    by_id = {r.test.id: r.test for r in report.results}
    for rule in doc["runs"][0]["tool"]["driver"]["rules"]:
        level, sec = LEVELS[by_id[rule["id"]].severity]
        assert rule["defaultConfiguration"]["level"] == level
        assert rule["properties"]["security-severity"] == sec
        assert "security" in rule["properties"]["tags"]


async def test_fingerprints_are_stable_across_runs():
    a = to_sarif(await _report("vulnerable", ids=["DI-001"]))
    b = to_sarif(await _report("vulnerable", ids=["DI-001"]))
    fa = a["runs"][0]["results"][0]["partialFingerprints"]
    fb = b["runs"][0]["results"][0]["partialFingerprints"]
    assert fa == fb


async def test_errors_become_notifications_not_results():
    report = await _report("vulnerable", ids=["DI-001"])
    for tr in report.results[0].trials:
        tr.verdict, tr.error = Verdict.ERROR, "connection refused"
    run = to_sarif(report)["runs"][0]
    assert run["results"] == []
    notes = run["invocations"][0]["toolExecutionNotifications"]
    assert notes[0]["associatedRule"]["id"] == "DI-001"
    assert "connection refused" in notes[0]["message"]["text"]
    assert run["invocations"][0]["executionSuccessful"] is False


@pytest.mark.parametrize(
    "raw,expected",
    [(None, "promptprobe.yaml"), ("cfg.yaml", "cfg.yaml"), ("./a/b/prompt.txt", "a/b/prompt.txt")],
)
def test_artifact_uri_is_relative_posix(raw, expected):
    assert artifact_uri(raw) == expected


def test_absolute_path_inside_cwd_becomes_relative(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "p.txt").write_text("x")
    assert artifact_uri(str(tmp_path / "p.txt")) == "p.txt"


def test_cli_writes_sarif(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "prompt.txt").write_text(DEFAULT_SYSTEM_PROMPT)
    rc = main(["run", "-t", "mock", "-m", "vulnerable", "--id", "DI-001",
               "-f", "sarif", "-o", "out", "--system-prompt-file", "prompt.txt"])
    assert rc == 0
    files = list((tmp_path / "out").glob("*.sarif"))
    assert len(files) == 1
    doc = json.loads(files[0].read_text())
    res = doc["runs"][0]["results"]
    assert res and res[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "prompt.txt"
