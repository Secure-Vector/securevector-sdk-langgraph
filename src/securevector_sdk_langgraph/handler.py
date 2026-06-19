"""The LangChain ``BaseCallbackHandler`` that wires tool calls into SecureVector.

``on_tool_start`` runs the three controls *before* the tool executes; in
enforce mode a denial raises ``ToolBlocked``, which aborts the step. We set
``raise_error = True`` and ``run_inline = True`` so LangChain propagates the
exception synchronously instead of swallowing it — that is what makes enforce
mode an actual gate rather than advisory logging.

``run_id`` correlates start→end so the output scan is attributed to the same
tool. Output scanning is observe-only.
"""

import logging
import uuid
from typing import Any, Dict, Optional

from .config import Config
from .core import Interceptor

log = logging.getLogger("securevector_sdk_langgraph")

try:  # langchain-core is a declared dependency; guard so tests import standalone
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
        import json
        return json.dumps(value, default=str)
    except Exception:
        return str(value)


class SecureVectorCallbackHandler(BaseCallbackHandler):
    """Attach to any LangChain run via ``config={"callbacks": [handler]}`` or
    register it globally with :func:`securevector_sdk_langgraph.install`."""

    # Make enforce mode a real gate: propagate exceptions synchronously.
    raise_error = True
    run_inline = True

    def __init__(self, mode: Optional[str] = None, base_url: Optional[str] = None, **kwargs):
        self.cfg = Config.from_env(mode=mode, base_url=base_url, **kwargs)
        self.interceptor = Interceptor(self.cfg)
        self._session = uuid.uuid4().hex[:16]
        self._runs: Dict[Any, str] = {}

    # -- LangChain callback surface -------------------------------------- #
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
        self.interceptor.on_tool_start(
            tool_id,
            _to_text(input_str),
            session_id=self._session,
            request_id=str(run_id) if run_id is not None else None,
        )

    def on_tool_end(self, output: Any, *, run_id: Any = None, **kwargs: Any) -> None:
        tool_id = self._runs.pop(run_id, None) or "unknown"
        self.interceptor.on_tool_end(
            tool_id,
            _to_text(output),
            session_id=self._session,
            request_id=str(run_id) if run_id is not None else None,
        )

    def on_tool_error(self, error: BaseException, *, run_id: Any = None, **kwargs: Any) -> None:
        self._runs.pop(run_id, None)
