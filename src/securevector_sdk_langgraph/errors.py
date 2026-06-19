"""Exceptions raised by the SecureVector LangChain adapter.

``ToolBlocked`` is the one that matters operationally: in ``enforce`` mode the
callback handler raises it from ``on_tool_start`` *before* the tool executes,
which aborts the tool step. In ``observe`` mode it is never raised — the call
is logged and allowed through.
"""


class SecureVectorError(Exception):
    """Base class for all adapter errors."""


class ToolBlocked(SecureVectorError):
    """Raised in enforce mode to abort a tool call (policy block, input threat,
    or fail-closed when the local app is unreachable)."""

    def __init__(self, tool_id: str, reason: str):
        self.tool_id = tool_id
        self.reason = reason
        super().__init__(f"SecureVector blocked tool '{tool_id}': {reason}")


class AppUnreachable(SecureVectorError):
    """The local SecureVector app could not be reached. Mode decides the
    consequence: observe → allow (fail-open); enforce → deny (fail-closed)."""
