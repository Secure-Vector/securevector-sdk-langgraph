"""SecureVector SDK for LangGraph.

Enforcement (recommended) — the documented ``wrap_tool_call`` middleware, which
``create_agent`` / ``create_react_agent`` accept::

    from securevector_sdk_langgraph import secure_middleware
    from langchain.agents import create_agent

    agent = create_agent(
        model, tools,
        middleware=[secure_middleware(mode="enforce")],
    )

Observe-only logging (any graph) — pass the callback handler in config::

    from securevector_sdk_langgraph import SecureVectorCallbackHandler
    graph.invoke(state, config={"callbacks": [SecureVectorCallbackHandler()]})

For a raw ``StateGraph`` with custom tool nodes (no middleware surface), gate
execution with LangGraph's ``interrupt()`` inside the tool — see the README.

Either way, every tool call runs the local SecureVector app's three controls —
tool-call permissions, secret/data-leak detection, threat detection — and each
decision is written to the app's tamper-evident audit chain with
``runtime_kind="langgraph"``. Requires the SecureVector app running locally
(installed automatically as the ``securevector-ai-monitor`` dependency).
"""

import logging
from typing import Optional

from ._version import __version__
from .config import Config
from .errors import AppUnreachable, SecureVectorError, ToolBlocked
from .handler import SecureVectorCallbackHandler
from .middleware import secure_middleware

log = logging.getLogger("securevector_sdk_langgraph")

__all__ = [
    "__version__",
    "secure_middleware",
    "install",
    "SecureVectorCallbackHandler",
    "Config",
    "SecureVectorError",
    "ToolBlocked",
    "AppUnreachable",
]


def install(mode: str = "observe", base_url: Optional[str] = None, **kwargs):
    """Convenience alias for :func:`secure_middleware` — returns the middleware
    to pass to ``create_agent(..., middleware=[install(mode="enforce")])``."""
    return secure_middleware(mode=mode, base_url=base_url, **kwargs)
