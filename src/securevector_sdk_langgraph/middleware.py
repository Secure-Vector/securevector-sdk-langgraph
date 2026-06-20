"""LangChain v1 ``wrap_tool_call`` middleware — the primary interception path.

This is the documented way to intercept a tool call before it runs and block
it: the middleware receives a ``ToolCallRequest`` (with structured
``tool_call["name"]`` / ``["args"]``), and either calls ``handler(request)`` to
execute the tool or returns a ``ToolMessage`` *without* calling the handler to
short-circuit it. Returning a ``ToolMessage`` is the sanctioned block — it
feeds a clean result back to the model instead of raising.

    from securevector_sdk_langgraph import secure_middleware
    from langchain.agents import create_agent

    agent = create_agent(model, tools, middleware=[secure_middleware(mode="enforce")])

Works for both LangChain ``create_agent`` and LangGraph
``create_react_agent``/``create_agent`` (they share the middleware surface).
"""

import json
import logging
import uuid
from typing import Any, Callable, Optional

from .config import Config
from .core import Interceptor

log = logging.getLogger("securevector_sdk_langgraph")


def _to_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, default=str)
    except Exception:
        return str(value)


def _result_text(result: Any) -> str:
    """Pull text out of whatever the tool handler returned (usually a
    ToolMessage, possibly a Command or raw value)."""
    content = getattr(result, "content", None)
    if content is not None:
        return _to_text(content)
    return _to_text(result)


def _make_tool_call_handler(
    interceptor: Interceptor,
    session: str,
    tool_message_factory: Callable[..., Any],
):
    """Build the ``(request, handler)`` callable used by ``wrap_tool_call``.

    Factored out (and parameterised on the ToolMessage factory) so it is unit
    testable without a full LangChain v1 install.
    """

    def _securevector(request, handler):
        tool_call = getattr(request, "tool_call", None) or {}
        name = tool_call.get("name") or "unknown"
        args = tool_call.get("args")
        call_id = tool_call.get("id")
        req = uuid.uuid4().hex[:16]

        decision = interceptor.evaluate_input(
            name, _to_text(args), session_id=session, request_id=req
        )
        if decision.blocked:
            # Documented short-circuit: return a ToolMessage WITHOUT running the
            # tool. The model sees a clean blocked result, not an exception.
            return tool_message_factory(
                content=f"[SecureVector] Tool '{name}' blocked: {decision.reason}",
                tool_call_id=call_id,
                status="error",
            )

        result = handler(request)
        interceptor.scan_output(
            name, _result_text(result), session_id=session, request_id=req
        )
        return result

    return _securevector


def secure_middleware(mode: str = "observe", base_url: Optional[str] = None, **kwargs):
    """Build a SecureVector ``wrap_tool_call`` middleware.

    ``mode``: ``"observe"`` (fail-open, default) or ``"enforce"`` (fail-closed —
    denied tools are short-circuited with a ToolMessage before they run).
    Raises ``ImportError`` if LangChain v1's middleware API is unavailable.
    """
    try:
        from langchain.agents.middleware import wrap_tool_call
        from langchain.messages import ToolMessage
    except Exception as exc:  # pragma: no cover - depends on langchain version
        raise ImportError(
            "secure_middleware requires LangChain v1 (langchain>=1.0) for "
            "langchain.agents.middleware.wrap_tool_call. For older versions, "
            "use SecureVectorCallbackHandler for observe-only logging."
        ) from exc

    cfg = Config.from_env(mode=mode, base_url=base_url, **kwargs)
    interceptor = Interceptor(cfg)
    session = uuid.uuid4().hex[:16]
    return wrap_tool_call(_make_tool_call_handler(interceptor, session, ToolMessage))
