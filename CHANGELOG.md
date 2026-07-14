# Changelog

All notable changes are recorded here. The project follows semantic versioning
after the first stable release.

## Unreleased

### Added

- Multilingual project entry points for 23 languages.
- CodeQL, immutable GitHub Action references, issue templates, and CODEOWNERS.
- Global scan/SSE admission limits and strict GitHub repository validation.
- Evidence lease fencing and job-bound progressive finalization.
- Semantic package-identity grounding for model output.

### Changed

- Product, binary, packages, and public documentation are named
  **AI Supply Chain Trust**.
- The benchmark-selected primary model is `openai/gpt-4.1-mini`, with
  `google/gemini-2.5-flash` as the provider-diverse secondary.
- Missing AI/MCP, model-artifact, and scanner evidence is explicitly unavailable
  rather than being interpreted as a safe result.

### Security

- Public queue priority is bounded and rescan requests are rate limited.
- OpenRouter response bodies are bounded to 1 MiB.
- Stale evidence workers cannot overwrite a successor's result.
