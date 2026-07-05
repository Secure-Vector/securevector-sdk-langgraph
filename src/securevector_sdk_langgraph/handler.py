"""Observe-mode LangChain callback handler.

Callbacks are an **observability** surface — they cannot cleanly block a tool
call (raising from them is version-dependent and tends to crash the run rather
than return a clean result). So this handler is for **logging/audit** in
contexts where the ``wrap_tool_call`` middleware isn't available (legacy
AgentExecutor, raw LCEL chains). For real enforcement, use
:func:`securevector_sdk_langgraph.secure_middleware` with ``create_agent``.

Attach it via ``config={"callbacks": [SecureVectorCallbackHandler()]}``.
``run_id`` correlates start→end so the output scan is attributed to the same
tool.
"""

import json
import logging
import uuid
from typing import Any, Dict, Optional

from .config import Config
from .core import Interceptor
from .costs import CostTracker

log = logging.getLogger("securevector_sdk_langgraph")

try:  # langchain-core ships with langchain; guard so tests import standalone
    from langchain_core.callbacks import BaseCallbackHandler
except Exception:  # pragma: no cover
    try:
        from langchain.callbacks.base import BaseCallbackHandler  # type: ignore
    except Exception:
        BaseCallbackHandler = object  # type: ignore


def _to_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, default=str)
    except Exception:
        return str(value)


class SecureVectorCallbackHandler(BaseCallbackHandler):
    """Observe-only audit handler. Logs the three controls' findings for every
    tool call; does not block (use ``secure_middleware`` to enforce)."""

    def __init__(self, mode: Optional[str] = None, base_url: Optional[str] = None, **kwargs):
        # Force observe: callbacks cannot reliably block, so we never pretend to.
        kwargs.pop("mode", None)
        self.cfg = Config.from_env(mode="observe", base_url=base_url, **kwargs)
        self.interceptor = Interceptor(self.cfg)
        self.costs = CostTracker(self.cfg)
        self._session = uuid.uuid4().hex[:16]
        self._runs: Dict[Any, str] = {}
        if mode == "enforce":
            log.warning(
                "SecureVectorCallbackHandler runs in observe mode only; for "
                "enforcement use secure_middleware(mode='enforce') with create_agent."
            )

    def on_tool_start(
        self,
        serialized: Optional[dict],
        input_str: str,
        *,
        run_id: Any = None,
        **kwargs: Any,
    ) -> None:
        from .tool_id import normalize_tool_id

        tool_id = normalize_tool_id(serialized, kwargs.get("name"))
        if run_id is not None:
            self._runs[run_id] = tool_id
        self.interceptor.evaluate_input(
            tool_id,
            _to_text(input_str),
            session_id=self._session,
            request_id=str(run_id) if run_id is not None else None,
        )

    def on_tool_end(self, output: Any, *, run_id: Any = None, **kwargs: Any) -> None:
        tool_id = self._runs.pop(run_id, None) or "unknown"
        self.interceptor.scan_output(
            tool_id,
            _to_text(output),
            session_id=self._session,
            request_id=str(run_id) if run_id is not None else None,
        )

    def on_tool_error(self, error: BaseException, *, run_id: Any = None, **kwargs: Any) -> None:
        self._runs.pop(run_id, None)

    def on_llm_end(self, response: Any, *, run_id: Any = None, **kwargs: Any) -> None:
        """Capture LLM token usage for the app's Cost Tracking (issue #185).

        ``response`` is an ``LLMResult``; chat generations carry an
        ``AIMessage`` with ``usage_metadata``. Best-effort — never raises.
        """
        try:
            for gen_list in getattr(response, "generations", None) or []:
                for gen in gen_list or []:
                    message = getattr(gen, "message", None)
                    if message is not None:
                        self.costs.record_message(message)
        except Exception as exc:
            log.debug("cost tracking failed: %s", exc)
