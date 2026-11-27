# Roadmap

Planned work, roughly in order. Checked items are shipped.

## v0.2 — CI-friendly
- [x] Retry with exponential backoff on 429/5xx from targets (honors Retry-After, configurable `max_retries`)
- [ ] SARIF output (`-f sarif`) so findings show up in GitHub code scanning
- [ ] `promptprobe diff old.json new.json` to compare two runs and flag regressions
- [ ] Reusable GitHub Action (`action.yml`) wrapping `promptprobe run`
- [x] Tests for the HTTP target's `response_path` and header env-var expansion

## v0.3 — More attack surface
- [ ] `tool_abuse` suite: injections that try to trigger unauthorized tool/function calls (OWASP LLM06 Excessive Agency)
- [ ] Tool-call detector for OpenAI/Anthropic responses that contain `tool_calls` / `tool_use`
- [ ] Gemini target
- [ ] Unicode tag-character and homoglyph obfuscation tests
- [ ] Many-shot / long-context injection test

## v0.4 — Reporting
- [ ] HTML report: per-category bar chart and severity breakdown
- [ ] Remediation guidance per finding, linked to OWASP LLM Top 10
- [ ] `--baseline` flag: only fail CI on findings that are new since the baseline
- [ ] Docs page with a walkthrough against a local Ollama model

## Done
- [x] v0.1.0: 39 attacks across 6 categories, canary detectors, JSON/Markdown/HTML reports, `--fail-on` CI gate
