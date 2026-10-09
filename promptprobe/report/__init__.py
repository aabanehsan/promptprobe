"""Report writers: JSON (machine-readable), Markdown (for PRs/issues) and HTML (to share)."""

from __future__ import annotations

import html
import json
from pathlib import Path

from .. import __version__
from ..models import Severity, TestResult, Verdict
from ..runner import RunReport

SEV_ORDER = {s.value: s.rank for s in Severity}


def _sorted(results: list[TestResult]) -> list[TestResult]:
    return sorted(
        results,
        key=lambda r: (r.verdict != Verdict.VULNERABLE, -r.test.severity.rank, -r.attack_success_rate, r.test.id),
    )


def to_dict(report: RunReport) -> dict:
    return {
        "tool": "promptprobe",
        "version": __version__,
        "target": report.target,
        "started_at": report.started_at,
        "finished_at": report.finished_at,
        "settings": {"trials": report.config.trials, "concurrency": report.config.concurrency},
        "system_prompt": report.config.system_prompt,
        "summary": report.summary(),
        "results": [r.to_dict() for r in _sorted(report.results)],
    }


def write_json(report: RunReport, path: Path) -> None:
    path.write_text(json.dumps(to_dict(report), indent=2, ensure_ascii=False), encoding="utf-8")


def _trim(text: str, n: int = 400) -> str:
    text = text.strip()
    return text if len(text) <= n else text[:n] + " …[truncated]"


def write_markdown(report: RunReport, path: Path) -> None:
    s = report.summary()
    lines = [
        "# promptprobe report",
        "",
        f"**Target:** `{report.target}`  ",
        f"**Run:** {report.started_at} → {report.finished_at}  ",
        f"**Trials per test:** {report.config.trials}",
        "",
        "## Summary",
        "",
        f"- **Resistance score:** {s['resistance_score']}%",
        f"- **Tests:** {s['total_tests']} total, {s['vulnerable']} vulnerable, "
        f"{s['resistant']} resistant, {s['errors']} errors",
    ]
    if s["vulnerable_by_severity"]:
        sev = ", ".join(
            f"{k}: {v}" for k, v in sorted(s["vulnerable_by_severity"].items(), key=lambda kv: -SEV_ORDER[kv[0]])
        )
        lines.append(f"- **Vulnerable by severity:** {sev}")
    lines += ["", "| Category | Vulnerable / Total |", "|---|---|"]
    for cat, c in s["by_category"].items():
        lines.append(f"| {cat} | {c['vulnerable']} / {c['total']} |")

    lines += ["", "## Results", "", "| ID | Test | Severity | Verdict | Success rate |", "|---|---|---|---|---|"]
    for r in _sorted(report.results):
        icon = {"vulnerable": "🔴", "resistant": "🟢", "error": "⚪"}[r.verdict.value]
        lines.append(
            f"| {r.test.id} | {r.test.name} | {r.test.severity.value} | {icon} {r.verdict.value} "
            f"| {r.successes}/{len(r.trials) - r.errors} |"
        )

    vulns = [r for r in _sorted(report.results) if r.verdict == Verdict.VULNERABLE]
    if vulns:
        lines += ["", "## Findings", ""]
    for r in vulns:
        tr = next(t for t in r.trials if t.verdict == Verdict.VULNERABLE)
        attack = "\n\n".join(m.content for m in tr.conversation if m.role == "user")
        lines += [
            f"### {r.test.id}: {r.test.name}",
            "",
            f"**Severity:** {r.test.severity.value} · **Category:** {r.test.category} · **OWASP:** {r.test.owasp}",
            "",
            r.test.description,
            "",
            "**Evidence:** " + "; ".join(f"`{h.detector}`: {h.evidence}" for h in tr.hits),
            "",
            "<details><summary>Attack and response</summary>",
            "",
            "**Attack:**",
            "```text",
            _trim(attack, 1200),
            "```",
            "**Response:**",
            "```text",
            _trim(tr.response, 1200),
            "```",
            "</details>",
            "",
        ]
    errs = [r for r in report.results if r.errors]
    if errs:
        lines += ["## Errors", ""]
        for r in errs:
            e = next(t.error for t in r.trials if t.error)
            lines.append(f"- **{r.test.id}**: {e}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


HTML_TEMPLATE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>promptprobe report</title>
<style>
:root{--bg:#0e1116;--panel:#161b22;--line:#2a313c;--text:#e6edf3;--muted:#8b949e;
--red:#f85149;--green:#3fb950;--amber:#d29922;--blue:#58a6ff}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);
font:14px/1.5 ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
main{max-width:1100px;margin:0 auto;padding:32px 16px}
h1{font-size:22px;margin:0 0 4px}h2{font-size:16px;margin:32px 0 12px;color:var(--muted);
text-transform:uppercase;letter-spacing:.06em}
.meta{color:var(--muted);font-size:13px}code,pre{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin-top:20px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px}
.card b{display:block;font-size:26px}.card span{color:var(--muted);font-size:12px}
.bar{height:8px;background:var(--line);border-radius:4px;overflow:hidden;margin-top:6px}
.bar i{display:block;height:100%;background:var(--red)}
table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line);border-radius:10px;overflow:hidden}
th,td{text-align:left;padding:9px 12px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-size:12px;color:var(--muted);font-weight:600}
.pill{display:inline-block;padding:1px 8px;border-radius:99px;font-size:12px;font-weight:600}
.vulnerable{background:#f8514926;color:var(--red)}.resistant{background:#3fb95026;color:var(--green)}
.error{background:#8b949e26;color:var(--muted)}
.critical{color:var(--red)}.high{color:#ff7b72}.medium{color:var(--amber)}.low{color:var(--blue)}
details{background:var(--panel);border:1px solid var(--line);border-radius:10px;margin:10px 0;padding:0 14px}
summary{cursor:pointer;padding:12px 0;font-weight:600}
pre{white-space:pre-wrap;word-break:break-word;background:#0b0e13;border:1px solid var(--line);
border-radius:8px;padding:10px;font-size:12px;max-height:340px;overflow:auto}
.ev{color:var(--amber);font-size:13px}.wrap{overflow-x:auto}
</style></head><body><main>
<h1>promptprobe report</h1>
<div class="meta">Target <code>{target}</code> · {started} → {finished} · {trials} trial(s) per test · v{version}</div>
<div class="cards">
<div class="card"><span>Resistance score</span><b>{score}%</b></div>
<div class="card"><span>Vulnerable</span><b style="color:var(--red)">{vuln}</b></div>
<div class="card"><span>Resistant</span><b style="color:var(--green)">{resist}</b></div>
<div class="card"><span>Errors</span><b>{errors}</b></div>
</div>
<h2>By category</h2>
<div class="cards">{cats}</div>
<h2>All tests</h2>
<div class="wrap"><table><thead><tr><th>ID</th><th>Test</th><th>Category</th><th>Severity</th><th>Verdict</th><th>Success</th></tr></thead>
<tbody>{rows}</tbody></table></div>
<h2>Findings</h2>
{findings}
</main></body></html>
"""


def write_html(report: RunReport, path: Path) -> None:
    s = report.summary()
    e = html.escape
    cats = "".join(
        f'<div class="card"><span>{e(cat)}</span><b>{c["vulnerable"]}/{c["total"]}</b>'
        f'<div class="bar"><i style="width:{100 * c["vulnerable"] / max(c["total"], 1):.0f}%"></i></div></div>'
        for cat, c in s["by_category"].items()
    )
    rows = "".join(
        f"<tr><td><code>{e(r.test.id)}</code></td><td>{e(r.test.name)}</td><td>{e(r.test.category)}</td>"
        f'<td class="{r.test.severity.value}">{r.test.severity.value}</td>'
        f'<td><span class="pill {r.verdict.value}">{r.verdict.value}</span></td>'
        f"<td>{r.successes}/{len(r.trials) - r.errors}</td></tr>"
        for r in _sorted(report.results)
    )
    findings = []
    for r in _sorted(report.results):
        if r.verdict != Verdict.VULNERABLE:
            continue
        tr = next(t for t in r.trials if t.verdict == Verdict.VULNERABLE)
        convo = "\n\n".join(f"[{m.role}]\n{m.content}" for m in tr.conversation if m.role != "system")
        ev = "<br>".join(f"<b>{e(h.detector)}</b>: {e(h.evidence)}" for h in tr.hits)
        findings.append(
            f'<details><summary><span class="{r.test.severity.value}">●</span> {e(r.test.id)}: {e(r.test.name)} '
            f'<span class="meta">({r.test.severity.value}, {e(r.test.owasp)})</span></summary>'
            f"<p>{e(r.test.description)}</p><p class=\"ev\">{ev}</p>"
            f"<pre>{e(_trim(convo, 4000))}</pre></details>"
        )
    out = HTML_TEMPLATE
    for k, v in {
        "target": e(report.target), "started": e(report.started_at), "finished": e(report.finished_at),
        "trials": str(report.config.trials), "version": __version__, "score": str(s["resistance_score"]),
        "vuln": str(s["vulnerable"]), "resist": str(s["resistant"]), "errors": str(s["errors"]),
        "cats": cats, "rows": rows,
        "findings": "".join(findings) or '<p class="meta">No successful attacks. Nice.</p>',
    }.items():
        out = out.replace("{" + k + "}", v)
    path.write_text(out, encoding="utf-8")


WRITERS = {"json": write_json, "md": write_markdown, "html": write_html}
