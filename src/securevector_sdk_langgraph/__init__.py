"""SecureVector SDK for LangChain.

Two-line usage::

    from securevector_sdk_langgraph import install
    install(mode="observe")          # registers a global handler

    # — or attach explicitly to one run —
    from securevector_sdk_langgraph import SecureVectorCallbackHandler
    agent.invoke(payload, config={"callbacks": [SecureVectorCallbackHandler()]})

Or, fully zero-config::

    import securevector_sdk_langgraph.auto   # reads env, installs globally

The handler brings the local SecureVector app's three controls — tool-call
permissions, secret/data-leak detection, threat detection — to every LangChain
tool call, and writes each decision to the app's tamper-evident audit chain.
Requires the SecureVector app running locally (installed automatically as the
``securevector-ai-monitor`` dependency).
"""

import logging
from contextvars import ContextVar
from typing import Optional

from ._version import __version__
from .config import Config
from .errors import AppUnreachable, SecureVectorError, ToolBlocked
from .handler import SecureVectorCallbackHandler

log = logging.getLogger("securevector_sdk_langgraph")

__all__ = [
    "__version__",
    "install",
    "SecureVectorCallbackHandler",
    "Config",
    "SecureVectorError",
    "ToolBlocked",
    "AppUnreachable",
]

# Holds the globally-registered handler so LangChain injects it into every run.
_sv_handler_var: ContextVar = ContextVar("securevector_sdk_langgraph_handler", default=None)
_hook_registered = False


def install(
    mode: str = "observe",
    base_url: Optional[str] = None,
    *,
    register_global: bool = True,
    **kwargs,
) -> SecureVectorCallbackHandler:
    """Create a handler and (by default) register it process-wide.

    ``mode``: ``"observe"`` (fail-open, default) or ``"enforce"`` (fail-closed).
    Returns the handler so you can also pass it explicitly per run.
    """
    global _hook_registered
    handler = SecureVectorCallbackHandler(mode=mode, base_url=base_url, **kwargs)
    if register_global:
        try:
            from langchain_core.callbacks.manager import register_configure_hook

            _sv_handler_var.set(handler)
            if not _hook_registered:
                # inheritable=True → the handler is added to every (sub)run.
                register_configure_hook(_sv_handler_var, True)
                _hook_registered = True
        except Exception as exc:  # pragma: no cover - depends on langchain version
            log.warning(
                "Global handler registration unavailable (%s); pass the handler "
                "via config={'callbacks': [...]} instead.",
                exc,
            )
    return handler
