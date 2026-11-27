# Changelog

All notable changes to this project are listed here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]
### Added
- Roadmap and changelog
- README badges
- `Retry-After` support for both the seconds and HTTP-date forms
- `backoff_base` target option and documented `max_retries` / `timeout`
- Offline tests for retries, backoff timing and the generic HTTP target (body placeholders, header env expansion, `response_path`)

### Fixed
- A malformed `Retry-After` value (e.g. `1.2.3`) crashed the run instead of falling back to normal backoff
- A huge `Retry-After` could stall a run; waits are now capped at 30s
- A non-JSON 200 response (e.g. a login page) raised a raw decode error instead of a clear target error
- Error after exhausting retries now says what failed and how many attempts were made

## [0.1.0] - 2026-10-19
### Added
- Initial release: 39 prompt injection attacks across 6 categories
- Canary-based detectors: marker echo, planted secret leak (plain, spaced, reversed, base64, hex, ROT13, partial), markdown exfiltration, unsafe HTML, system prompt overlap
- Targets: OpenAI-compatible, Ollama, Anthropic, generic HTTP, mock
- JSON, Markdown and HTML reports
- `--fail-on` severity gate for CI
