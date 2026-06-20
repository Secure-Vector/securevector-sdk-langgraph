"""``import securevector_sdk_langgraph.auto`` — observe-mode global logging.

There is no global registration for middleware (it is passed to
``create_agent``), so this module registers an **observe-only** callback handler
as a LangChain global handler where the version supports it. For enforcement,
add ``secure_middleware(mode="enforce")`` to your agent's ``middleware`` list.
"""

import logging
import os

from .handler import SecureVectorCallbackHandler

log = logging.getLogger("securevector_sdk_langgraph")

_handler = SecureVectorCallbackHandler()

try:
    # Best-effort: register as a global handler so existing chains are logged.
    from langchain_core.callbacks.manager import register_configure_hook
    from contextvars import ContextVar

    _var: ContextVar = ContextVar("securevector_sdk_langgraph_handler", default=None)
    _var.set(_handler)
    register_configure_hook(_var, True)
except Exception as exc:  # pragma: no cover - depends on langchain version
    log.warning(
        "Global observe handler unavailable (%s); pass SecureVectorCallbackHandler "
        "via config={'callbacks': [...]}, or use secure_middleware to enforce.",
        exc,
    )

if os.environ.get("SECUREVECTOR_SDK_MODE", "observe").lower() == "enforce":
    log.warning(
        "SECUREVECTOR_SDK_MODE=enforce has no effect via auto-import (callbacks "
        "cannot block). Add secure_middleware(mode='enforce') to create_agent."
    )
