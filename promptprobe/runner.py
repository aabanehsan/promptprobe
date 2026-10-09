"""Runs test cases against a target and collects results."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable

from .canary import Canaries, build_system_prompt, encode, render
from .detectors import DetectContext, run_detectors
from .models import Message, TestCase, TestResult, TrialResult, Verdict
from .targets import Target


@dataclass
class RunConfig:
    system_prompt: str
    trials: int = 1
    concurrency: int = 4
    plant_secret: bool = True


@dataclass
class RunReport:
    target: str
    started_at: str
    finished_at: str
    config: RunConfig
    results: list[TestResult] = field(default_factory=list)

    @property
    def vulnerable(self) -> list[TestResult]:
        return [r for r in self.results if r.verdict == Verdict.VULNERABLE]

    def summary(self) -> dict:
        total = len(self.results)
        vuln = len(self.vulnerable)
        errors = sum(1 for r in self.results if r.verdict == Verdict.ERROR)
        by_cat: dict[str, dict[str, int]] = {}
        for r in self.results:
            c = by_cat.setdefault(r.test.category, {"total": 0, "vulnerable": 0})
            c["total"] += 1
            c["vulnerable"] += r.verdict == Verdict.VULNERABLE
        by_sev: dict[str, int] = {}
        for r in self.vulnerable:
            by_sev[r.test.severity.value] = by_sev.get(r.test.severity.value, 0) + 1
        tested = total - errors
        return {
            "total_tests": total,
            "vulnerable": vuln,
            "resistant": total - vuln - errors,
            "errors": errors,
            "resistance_score": round(100 * (tested - vuln) / tested, 1) if tested else 0.0,
            "by_category": by_cat,
            "vulnerable_by_severity": by_sev,
        }


ProgressFn = Callable[[TestResult], None]


async def _run_trial(target: Target, test: TestCase, trial: int, cfg: RunConfig) -> TrialResult:
    can = Canaries.fresh()
    extra = {}
    if test.encode and test.encoding:
        extra["encoded"] = encode(render(test.encode, can), test.encoding)

    system = build_system_prompt(cfg.system_prompt, can) if cfg.plant_secret else cfg.system_prompt
    convo = [Message("system", system)]
    replies: list[str] = []
    started = time.perf_counter()
    try:
        for turn in test.user_turns():
            convo.append(Message("user", render(turn, can, extra)))
            reply = await target.chat(convo)
            convo.append(Message("assistant", reply))
            replies.append(reply)
    except Exception as e:  # noqa: BLE001 - any target failure is recorded, not fatal
        return TrialResult(
            trial=trial, verdict=Verdict.ERROR, response="\n\n".join(replies), conversation=convo,
            error=f"{type(e).__name__}: {e}", latency_ms=int((time.perf_counter() - started) * 1000),
        )

    response = "\n\n".join(replies)
    ctx = DetectContext(response=response, canaries=can, base_system_prompt=cfg.system_prompt)
    hits = run_detectors(test.detectors, ctx)
    return TrialResult(
        trial=trial,
        verdict=Verdict.VULNERABLE if hits else Verdict.RESISTANT,
        response=response,
        conversation=convo,
        hits=hits,
        notes=ctx.notes,
        latency_ms=int((time.perf_counter() - started) * 1000),
    )


async def run_tests(
    target: Target,
    tests: list[TestCase],
    cfg: RunConfig,
    on_result: ProgressFn | None = None,
) -> RunReport:
    started = datetime.now(timezone.utc).isoformat(timespec="seconds")
    sem = asyncio.Semaphore(max(1, cfg.concurrency))

    async def one(test: TestCase) -> TestResult:
        async def guarded(i: int) -> TrialResult:
            async with sem:
                return await _run_trial(target, test, i, cfg)

        trials = await asyncio.gather(*(guarded(i + 1) for i in range(cfg.trials)))
        result = TestResult(test=test, trials=list(trials))
        if on_result:
            on_result(result)
        return result

    try:
        results = await asyncio.gather(*(one(t) for t in tests))
    finally:
        await target.aclose()

    return RunReport(
        target=target.label,
        started_at=started,
        finished_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        config=cfg,
        results=list(results),
    )
