# Changelog

All notable changes to `securevector-sdk-langgraph` are documented here.
This project adheres to [Semantic Versioning](https://semver.org/).

## [1.0.0]

### Added
- Initial LangGraph adapter (Phase 2 of the SecureVector SDK roadmap, story #174).
- `secure_middleware(mode=...)` — the primary interception path, built on the
  documented `wrap_tool_call` middleware that `create_agent` /
  `create_react_agent` accept. Runs the three controls on every tool call and,
  in enforce mode, short-circuits a denied tool with a `ToolMessage` (no
  exceptions):
  - **(a)** tool-call permission resolution (synced → override → essential → default-allow),
  - **(b)** secret / data-leak detection on tool input and output,
  - **(c)** threat detection on tool input and output.
- `SecureVectorCallbackHandler` — observe-only audit logging for any graph
  (propagated through langchain-core's callback manager). Callbacks cannot
  reliably block, so this never enforces; for raw `StateGraph` tool nodes, gate
  with LangGraph's `interrupt()`.
- `observe` (fail-open, default) and `enforce` (fail-closed) modes.
- Audit forwarding to the local app's tamper-evident chain with
  `runtime_kind="langgraph"` attribution.
- Requires `langgraph>=1.0` and `langchain>=1.0` (the `wrap_tool_call` middleware API).
- CI + Test PyPI (develop) / PyPI (main release) publishing via OIDC trusted
  publishing, mirroring `securevector-guardian-model`.
