# SecureVector SDK for LangGraph

> Bring the SecureVector local threat monitor's three controls — **tool-call
> permissions**, **secret / data-leak detection**, and **threat detection** —
> to every LangGraph tool call, with tamper-evident audit logging. One import.

```bash
pip install securevector-sdk-langgraph
```

This also installs the local SecureVector app (`securevector-ai-monitor`). The
SDK is a thin interception layer; the detection engine and the tamper-evident
audit chain live in the app, which must be running locally.

LangGraph executes its tool nodes through `langchain-core`'s callback manager,
so a single callback handler instruments every tool call inside your graph.

## Quick start

```python
from securevector_sdk_langgraph import install

install(mode="observe")   # registers a global handler for every graph
```

or attach it to a single graph run:

```python
from securevector_sdk_langgraph import SecureVectorCallbackHandler

graph.invoke(state, config={"callbacks": [SecureVectorCallbackHandler()]})
```

or fully zero-config:

```python
import securevector_sdk_langgraph.auto   # reads env, installs globally
```

## What happens on every tool call

Before a tool node runs (`on_tool_start`), the SDK:

1. **(a) Permissions** — resolves an allow/block verdict for the tool, using the
   app's own precedence: cloud-pushed **synced** policy → local **override** →
   **essential** registry → default-allow.
2. **(b)+(c) Secret & threat scan** — sends the serialized tool input through the
   app's `/analyze` pipeline.

After the tool returns (`on_tool_end`), the result is scanned the same way to
catch secrets / exfiltration in tool output. Every decision is written to the
app's audit chain tagged `runtime_kind="langgraph"`.

## observe vs enforce

| | local app reachable | local app unreachable |
|---|---|---|
| **observe** (default) | log + advisory verdict; tool always runs | tool runs (fail-open) |
| **enforce** (opt-in) | tool runs only if the verdict ≠ block | **tool denied** (fail-closed) |

```python
install(mode="enforce")   # blocks denied tools and fails closed if the app is down
```

Enforce mode prints a one-time disclosure to stderr.

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
