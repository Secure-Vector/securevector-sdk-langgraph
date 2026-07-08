# Changelog

All notable changes to `securevector-sdk-langgraph` are documented here.
This project adheres to [Semantic Versioning](https://semver.org/).

## [1.2.1]

### Fixed
- **`SECUREVECTOR_API_KEY` now actually sent**: the env var was documented but
  never read — no `Authorization` header was attached, so remote token-gated
  deployments rejected every request (bricked enforce mode / silently-off
  observe mode). The client now reads it into `Config.api_key` and forwards it
  as `Authorization: Bearer` on every call, matching the hermes SDK.
- **MCP `server:tool` policy matching**: MCP tools surfaced with a sanitized
  flat name (`mcp_<server>_<tool>`) never matched cloud policies keyed in the
  `<server>:<tool>` form, silently falling through to default-allow. Permission
  resolution now expands each name via `candidate_tool_ids()` (also exported)
  and matches every plausible split, tier precedence unchanged — parity with
  the hermes SDK.

## [1.2.0]

### Added
- **LLM cost tracking** (story #185): the SDK now captures LLM token usage and
  posts it to the local app's Cost Tracking (`POST /api/costs/track`), so
  LangGraph agents appear in the dollar-based cost dashboard alongside proxy
  agents and respect per-agent budgets.
  - `cost_tracking_middleware()` — a `wrap_model_call` middleware for the
    langgraph-backed `create_agent`; pass it alongside `secure_middleware()`.
    Reads `AIMessage.usage_metadata` (input/output/cached tokens) after each
    model call.
  - `SecureVectorCallbackHandler` now also captures usage via `on_llm_end` for
    raw graphs (and `.auto` mode).
  - Provider + model-id normalization mirrors the app's pricing table
    (`provider/model_id` exact match), including versioned-model aliases, so
    dollar cost resolves instead of landing as `pricing_known=false`.
  - Attribution: records post as `agent_id` `"langgraph-agent"` by default;
    override per-agent via `cost_tracking_middleware(agent_id=...)` or
    `SECUREVECTOR_SDK_AGENT_ID`.
  - Best-effort like audit forwarding: an unreachable app or unknown model
    never breaks the agent.

## [1.1.0]

### Added
- **Unified engine endpoint** (#190): point the SDK at the local app or a
  self-hosted deployment via `SECUREVECTOR_ENGINE_ENDPOINT`. Legacy
  `SECUREVECTOR_SDK_APP_URL` continues to work as a fallback.

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
