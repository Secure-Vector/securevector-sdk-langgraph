# Changelog

All notable changes to `securevector-sdk-langgraph` are documented here.
This project adheres to [Semantic Versioning](https://semver.org/).

## [0.1.0] - Unreleased

### Added
- Initial LangChain adapter (Phase γ of the SecureVector SDK roadmap, story #174).
- `SecureVectorCallbackHandler` — a `BaseCallbackHandler` that runs the three
  controls on every tool call:
  - **(a)** tool-call permission resolution (synced → override → essential → default-allow),
  - **(b)** secret / data-leak detection on tool input and output,
  - **(c)** threat detection on tool input and output.
- `install(mode=...)` for global registration; `import securevector_sdk_langgraph.auto`
  for zero-config setup.
- `observe` (fail-open, default) and `enforce` (fail-closed) modes.
- Audit forwarding to the local app's tamper-evident chain with
  `runtime_kind="langchain"` attribution.
- CI + Test PyPI (develop) / PyPI (main release) publishing via OIDC trusted
  publishing, mirroring `securevector-guardian-model`.
