# Changelog

All notable changes to this project are listed here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]
### Added
- Roadmap and changelog
- README badges

## [0.1.0] - 2026-10-19
### Added
- Initial release: 39 prompt injection attacks across 6 categories
- Canary-based detectors: marker echo, planted secret leak (plain, spaced, reversed, base64, hex, ROT13, partial), markdown exfiltration, unsafe HTML, system prompt overlap
- Targets: OpenAI-compatible, Ollama, Anthropic, generic HTTP, mock
- JSON, Markdown and HTML reports
- `--fail-on` severity gate for CI
