"""Command line interface.

    promptprobe run --target mock                      # offline demo
    promptprobe run -c promptprobe.yaml                # real target from config
    promptprobe run -c promptprobe.yaml --category system_prompt_leak --trials 3
    promptprobe list                                   # show available tests
    promptprobe init                                   # write a starter config
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from importlib import resources
from pathlib import Path
from typing import Any

import yaml

from . import __version__
from .canary import DEFAULT_SYSTEM_PROMPT
from .models import Severity, TestResult, Verdict
from .report import WRITERS
from .runner import RunConfig, run_tests
from .suites import SuiteError, filter_tests, load_suites
from .targets import TargetError, make_target

USE_COLOR = sys.stderr.isatty() and not os.environ.get("NO_COLOR")


def c(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m" if USE_COLOR else text


SEV_COLOR = {"critical": "1;31", "high": "31", "medium": "33", "low": "36"}


def load_config(path: str | None) -> dict[str, Any]:
    if not path:
        return {}
    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def cmd_run(args: argparse.Namespace) -> int:
    cfg = load_config(args.config)
    target_cfg: dict[str, Any] = dict(cfg.get("target", {}))
    if args.target:
        target_cfg["type"] = args.target
    if args.model:
        target_cfg["model"] = args.model
    target_cfg.setdefault("type", "mock")

    run_cfg = cfg.get("run", {})
    system_prompt = cfg.get("system_prompt", DEFAULT_SYSTEM_PROMPT)
    if args.system_prompt_file:
        system_prompt = Path(args.system_prompt_file).read_text(encoding="utf-8")

    try:
        tests = load_suites(
            (cfg.get("suites") or []) + (args.suite or []),
            include_builtin=not args.no_builtin and cfg.get("include_builtin", True),
        )
        tests = filter_tests(tests, args.category, args.id, args.min_severity)
        target = make_target(target_cfg)
    except (SuiteError, TargetError, FileNotFoundError) as e:
        print(c(f"error: {e}", "31"), file=sys.stderr)
        return 2
    if not tests:
        print("no tests matched your filters", file=sys.stderr)
        return 2

    rc = RunConfig(
        system_prompt=system_prompt,
        trials=args.trials or run_cfg.get("trials", 1),
        concurrency=args.concurrency or run_cfg.get("concurrency", 4),
        plant_secret=cfg.get("plant_secret", True),
    )

    print(c(f"promptprobe v{__version__}", "1") + f"  target={target.label}  tests={len(tests)}  trials={rc.trials}",
          file=sys.stderr)
    done = 0

    def progress(r: TestResult) -> None:
        nonlocal done
        done += 1
        v = r.verdict
        tag = {Verdict.VULNERABLE: c("VULN", "1;31"), Verdict.RESISTANT: c(" OK ", "32"),
               Verdict.ERROR: c("ERR ", "90")}[v]
        sev = c(f"{r.test.severity.value:<8}", SEV_COLOR[r.test.severity.value])
        rate = f"{r.successes}/{len(r.trials) - r.errors}" if v != Verdict.ERROR else "-"
        print(f"  [{done:>3}/{len(tests)}] {tag}  {sev} {r.test.id:<8} {r.test.name}  ({rate})", file=sys.stderr)
        if v == Verdict.ERROR and args.verbose:
            print(c(f"         {r.trials[0].error}", "90"), file=sys.stderr)

    report = asyncio.run(run_tests(target, tests, rc, on_result=progress))

    out_dir = Path(args.out or cfg.get("output_dir", "reports"))
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = report.started_at.replace(":", "").replace("-", "")[:15]
    formats = [f.strip() for f in (args.format or "json,md,html").split(",") if f.strip()]
    written = []
    for fmt in formats:
        if fmt not in WRITERS:
            print(c(f"unknown format '{fmt}', skipping", "33"), file=sys.stderr)
            continue
        p = out_dir / f"promptprobe-{stamp}.{fmt}"
        WRITERS[fmt](report, p)
        written.append(p)

    s = report.summary()
    print("", file=sys.stderr)
    score_color = "32" if s["resistance_score"] >= 90 else "33" if s["resistance_score"] >= 70 else "31"
    print(f"  Resistance score: {c(str(s['resistance_score']) + '%', '1;' + score_color)}   "
          f"vulnerable={s['vulnerable']}  resistant={s['resistant']}  errors={s['errors']}", file=sys.stderr)
    for p in written:
        print(f"  report → {p}", file=sys.stderr)

    if s["errors"] == s["total_tests"]:
        print(c("  every test errored; check your target config and API key (rerun with -v)", "31"), file=sys.stderr)
        return 2
    if args.fail_on:
        floor = Severity(args.fail_on).rank
        if any(r.test.severity.rank >= floor for r in report.vulnerable):
            return 1
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    try:
        tests = filter_tests(load_suites(args.suite or []), args.category, None, None)
    except SuiteError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    current = None
    for t in tests:
        if t.category != current:
            current = t.category
            print(c(f"\n{current}", "1") + c(f"  ({t.owasp})", "90"))
        print(f"  {t.id:<8} {c(f'{t.severity.value:<8}', SEV_COLOR[t.severity.value])} {t.name}")
    print(f"\n{len(tests)} tests")
    return 0


def cmd_init(args: argparse.Namespace) -> int:
    dest = Path(args.path)
    if dest.exists() and not args.force:
        print(f"{dest} already exists (use --force to overwrite)", file=sys.stderr)
        return 1
    template = resources.files("promptprobe").joinpath("config_template.yaml").read_text(encoding="utf-8")
    dest.write_text(template, encoding="utf-8")
    print(f"wrote {dest}. Edit the target section, then run: promptprobe run -c {dest}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="promptprobe", description="Prompt injection testing for LLM apps.")
    p.add_argument("--version", action="version", version=f"promptprobe {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="run attack suites against a target")
    r.add_argument("-c", "--config", help="YAML config file")
    r.add_argument("-t", "--target", help="target type: openai | ollama | anthropic | http | mock")
    r.add_argument("-m", "--model", help="model name (for mock: vulnerable | hardened)")
    r.add_argument("--system-prompt-file", help="file with the system prompt to defend")
    r.add_argument("--suite", action="append", help="extra suite file or folder (repeatable)")
    r.add_argument("--no-builtin", action="store_true", help="skip the built-in suites")
    r.add_argument("--category", action="append", help="only run this category (repeatable)")
    r.add_argument("--id", action="append", help="only run this test id or prefix, e.g. SPL or DI-001")
    r.add_argument("--min-severity", choices=[s.value for s in Severity])
    r.add_argument("-n", "--trials", type=int, help="attempts per test (LLMs are random; 3+ recommended)")
    r.add_argument("-j", "--concurrency", type=int, help="parallel requests")
    r.add_argument("-o", "--out", help="report folder (default: reports)")
    r.add_argument("-f", "--format", help="comma list of json,md,html (default: all)")
    r.add_argument("--fail-on", choices=[s.value for s in Severity],
                   help="exit 1 if any finding at or above this severity (for CI)")
    r.add_argument("-v", "--verbose", action="store_true")
    r.set_defaults(func=cmd_run)

    ls = sub.add_parser("list", help="list available tests")
    ls.add_argument("--suite", action="append")
    ls.add_argument("--category", action="append")
    ls.set_defaults(func=cmd_list)

    i = sub.add_parser("init", help="write a starter config file")
    i.add_argument("path", nargs="?", default="promptprobe.yaml")
    i.add_argument("--force", action="store_true")
    i.set_defaults(func=cmd_init)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)
