# SecureVector SDK for LangGraph

[![PyPI](https://img.shields.io/pypi/v/securevector-sdk-langgraph)](https://pypi.org/project/securevector-sdk-langgraph/)
[![Downloads](https://img.shields.io/pypi/dm/securevector-sdk-langgraph)](https://pypistats.org/packages/securevector-sdk-langgraph)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://pypi.org/project/securevector-sdk-langgraph/)
[![License](https://img.shields.io/badge/license-Apache--2.0-green)](LICENSE)

> Bring the SecureVector local threat monitor's three controls — **tool-call
> permissions**, **secret / data-leak detection**, and **threat detection** —
> to every LangGraph tool call, with tamper-evident audit logging. One import.

```bash
pip install securevector-sdk-langgraph
```

> 📦 **One install — batteries included.** `pip install securevector-sdk-langgraph`
> **also installs the local SecureVector app** (`securevector-ai-monitor`): the
> adapter **and** the detection engine + tamper-evident audit chain arrive in a
> single `pip install`. The SDK is a thin interception layer — **the app must be
> running locally** (`securevector-app --web`) for it to do anything.

> 🌐 **Pointing at your own cloud? Use the lightweight install.** If you've deployed
> SecureVector to your own cloud, you don't need the bundled
> local app. Install **only the adapter** on the machine where your agents run, and
> point it at your deployment:
>
> ```bash
> # lightweight — adapter only, no local app (your env already has langgraph)
> pip install securevector-sdk-langgraph --no-deps
>
> # point at your SecureVector endpoint — all you need for a private (in-VPC) endpoint
> export SECUREVECTOR_SDK_APP_URL=https://<your-securevector-endpoint>
>
> # OPTIONAL: only if your endpoint is publicly exposed and gated with an inbound token.
> # A private endpoint in your own VPC needs no key. To gate a public one, use a free
> # SecureVector cloud account API key or an SVET token — it gates access only; no agent
> # data is sent to SecureVector.
> export SECUREVECTOR_API_KEY=<SecureVector account key or SVET token>
> ```
> The adapter then forwards every tool call to your remote deployment instead of a
> local app. The default `pip install securevector-sdk-langgraph` (no `--no-deps`)
> still bundles the app for local use.

## Quick start

**Enforcement (recommended)** — the documented `wrap_tool_call` middleware,
accepted by the langgraph-backed `create_agent` (note:
`langgraph.prebuilt.create_react_agent` does **not** take a `middleware`
argument — use `create_agent`):

```python
from securevector_sdk_langgraph import secure_middleware
from langchain.agents import create_agent

agent = create_agent(
    model, tools,
    middleware=[secure_middleware(mode="enforce")],
)
```

A denied tool is short-circuited with a `ToolMessage` before it runs — no
exceptions, no crashed graph.

**Observe-only logging** for any graph (passes through `langchain-core`'s
callback manager):

```python
from securevector_sdk_langgraph import SecureVectorCallbackHandler

graph.invoke(state, config={"callbacks": [SecureVectorCallbackHandler()]})
```

**Raw `StateGraph` with custom tool nodes** (no middleware surface): gate the
tool with LangGraph's documented `interrupt()` for human/programmatic approval:

```python
from langgraph.types import interrupt

@tool
def run_query(sql: str):
    interrupt({"action": "run_query", "args": {"sql": sql}})  # pause for approval
    ...
```

> Why these paths? LangGraph **callbacks are observability-only** — they cannot
> cleanly block a tool. The **`wrap_tool_call` middleware** (for `create_agent`)
> and **`interrupt()`** (for raw graphs) are the documented gates.

## What happens on every tool call

Before a tool node runs, the SDK:

1. **(a) Permissions** — resolves an allow/block verdict for the tool, using the
   app's own precedence: cloud-pushed **synced** policy → local **override** →
   **essential** registry → default-allow.
2. **(b)+(c) Secret & threat scan** — sends the serialized tool input through the
   app's `/analyze` pipeline.

After the tool returns, the result is scanned the same way to catch secrets /
exfiltration in tool output. Every decision is written to the app's audit chain
tagged `runtime_kind="langgraph"`.

## observe vs enforce

| | local app reachable | local app unreachable |
|---|---|---|
| **observe** (default) | log + advisory verdict; tool always runs | tool runs (fail-open) |
| **enforce** (opt-in) | tool runs only if the verdict ≠ block | **tool denied** (fail-closed) |

```python
agent = create_agent(model, tools, middleware=[secure_middleware(mode="enforce")])
```

Enforce mode prints a one-time disclosure to stderr. (Enforcement requires the
middleware or `interrupt()` path; the observe callback handler always logs only.)

## Configuration

All optional, via env or `install(...)` kwargs:

| Env var | Default | Meaning |
|---|---|---|
| `SECUREVECTOR_SDK_APP_URL` | `http://127.0.0.1:8741` | local app base URL |
| `SECUREVECTOR_SDK_MODE` | `observe` | `observe` or `enforce` |
| `SECUREVECTOR_SDK_TIMEOUT_MS` | `3000` | per-call verdict timeout |
| `SECUREVECTOR_SDK_RISK_THRESHOLD` | `70` | risk score that blocks in enforce mode |
| `SECUREVECTOR_SDK_DISABLED` | _(unset)_ | set truthy to no-op |

## Compliance

The tool-call-level, attributed, tamper-evident audit trail this produces is
exactly the **action-layer logging** auditors ask for under **EU AI Act
Art. 12 / 15**. This SDK produces the local evidence; the cloud governance
surface turns it into an auditor-ready pack.

## Trademarks

**SecureVector** is the product name of this SDK. **LangGraph** and
**LangChain** are trademarks of LangChain, Inc. This is an independent,
community SDK that *integrates with* LangGraph via its public callback API. It
is **not affiliated with, sponsored by, or endorsed by LangChain, Inc.** The
name uses "langgraph" only descriptively, to identify the framework this
package works with (nominative fair use).

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
