"""Control routing — the three checks on every tool call.

This is the framework-agnostic engine. Detection already exists in the app; the
job here is **routing + the observe/enforce state machine**. The public surface
is deliberately non-raising so each adapter can choose how to *act* on a block:

* the LangChain/LangGraph ``wrap_tool_call`` middleware returns a ``ToolMessage``
  to short-circuit (the documented block primitive);
* the CrewAI tool wrapper raises ``ToolBlocked`` (CrewAI has no middleware).

Per intercepted call, in order:

    (a) PERMISSIONS  — resolve allow/block for the tool id
    (b) SECRET scan  — \\
    (c) THREAT scan  — // over the serialized tool input (and, on end, output)

``observe`` (default) is fail-open: everything is logged, nothing is blocked,
and an unreachable app degrades to allow. ``enforce`` is fail-closed: a policy
block, a high-risk input finding, or an unreachable app all mark the decision
``blocked``.
"""

import logging
import re
import sys
from dataclasses import dataclass
from typing import Optional

from .client import LocalAppClient
from .config import Config
from .errors import AppUnreachable, ToolBlocked

log = logging.getLogger("securevector_sdk_langgraph")

# Belt-and-braces preview redaction (the app redacts too; this keeps obvious
# secrets out of the args_preview we send).
_REDACTIONS = [
    (re.compile(r"AKIA[A-Z0-9]{16}"), "AKIA[REDACTED]"),
    (re.compile(r"ghp_[A-Za-z0-9]{36}"), "ghp_[REDACTED]"),
    (re.compile(r"sk-[A-Za-z0-9]{20,}"), "sk-[REDACTED]"),
    (re.compile(r"(?i)(password\"?\s*[:=]\s*\")[^\"]+(\")"), r"\1[REDACTED]\2"),
]


def redact(text: object, limit: int = 500) -> str:
    if not text:
        return ""
    s = str(text)
    for pattern, repl in _REDACTIONS:
        s = pattern.sub(repl, s)
    return s[:limit]


@dataclass
class Decision:
    """Result of evaluating a tool call's input. ``blocked`` already accounts
    for mode — it is only True when the call should actually be stopped (i.e.
    enforce mode + a deny). ``action`` is the audited action."""

    blocked: bool
    action: str          # allow | block | log_only
    reason: str
    risk: str


class Interceptor:
    def __init__(self, cfg: Config, client: Optional[LocalAppClient] = None):
        self.cfg = cfg
        self.client = client or LocalAppClient(cfg)
        self._disclosed = False

    @property
    def enforce(self) -> bool:
        return self.cfg.mode == "enforce"

    def _disclose_once(self) -> None:
        if self.enforce and not self._disclosed:
            self._disclosed = True
            sys.stderr.write(
                "[SecureVector] SDK is in ENFORCE mode — tool calls will be "
                "BLOCKED if a policy denies them or the local app is unreachable.\n"
            )

    # ------------------------------------------------------------------ #
    # Primary, non-raising API                                           #
    # ------------------------------------------------------------------ #
    def evaluate_input(
        self,
        tool_id: str,
        args_text: str,
        *,
        session_id: Optional[str] = None,
        request_id: Optional[str] = None,
    ) -> Decision:
        """Run the three controls on a tool's input and return a Decision.
        Records the audit row as a side effect. Never raises."""
        if not self.cfg.enabled:
            return Decision(False, "allow", "sdk disabled", "")
        self._disclose_once()
        preview = redact(args_text)

        # (a) PERMISSIONS
        try:
            verdict = self.client.resolve_permission(tool_id)
        except AppUnreachable:
            if self.enforce:
                return Decision(True, "block", "local app unreachable (fail-closed)", "unreachable")
            log.warning("app unreachable; observe mode allows %s", tool_id)
            return Decision(False, "allow", "app unreachable (observe, fail-open)", "unreachable")

        if verdict.action == "block":
            self.client.record_audit(
                tool_id=tool_id, function_name=tool_id, action="block",
                risk=verdict.risk, reason=verdict.reason,
                is_essential=verdict.is_essential, args_preview=preview,
                session_id=session_id, request_id=request_id,
            )
            return Decision(self.enforce, "block", verdict.reason, verdict.risk)

        # (b)+(c) SECRET + THREAT on the tool input
        a_in = None
        try:
            a_in = self.client.analyze(args_text, "tool_input")
        except AppUnreachable:
            a_in = None  # analysis best-effort; permissions already passed

        if a_in and a_in.is_threat:
            should_block = self.enforce and a_in.risk_score >= self.cfg.threat_risk_threshold
            act = "block" if should_block else "log_only"
            self.client.record_audit(
                tool_id=tool_id, function_name=tool_id, action=act,
                risk=str(a_in.risk_score),
                reason=f"Input secret/threat detected (risk={a_in.risk_score})",
                is_essential=verdict.is_essential, args_preview=preview,
                session_id=session_id, request_id=request_id,
            )
            return Decision(should_block, act, f"input secret/threat risk={a_in.risk_score}", str(a_in.risk_score))

        # Allowed — record the decision.
        self.client.record_audit(
            tool_id=tool_id, function_name=tool_id, action="allow",
            risk=verdict.risk, reason=verdict.reason,
            is_essential=verdict.is_essential, args_preview=preview,
            session_id=session_id, request_id=request_id,
        )
        return Decision(False, "allow", verdict.reason, verdict.risk)

    def scan_output(
        self,
        tool_id: str,
        output_text: str,
        *,
        session_id: Optional[str] = None,
        request_id: Optional[str] = None,
    ) -> None:
        """Scan the tool RESULT for secrets / exfiltration (observe-only — the
        tool already ran). Records a row if anything is found. Never raises."""
        if not self.cfg.enabled:
            return
        try:
            a_out = self.client.analyze(output_text, "tool_output")
        except AppUnreachable:
            return
        if a_out and a_out.is_threat:
            self.client.record_audit(
                tool_id=tool_id, function_name=tool_id, action="log_only",
                risk=str(a_out.risk_score),
                reason=f"Output secret/threat detected (risk={a_out.risk_score})",
                is_essential=False, args_preview=redact(output_text),
                session_id=session_id, request_id=request_id,
            )

    # ------------------------------------------------------------------ #
    # Raising convenience (CrewAI wrapper, where blocking == raising)     #
    # ------------------------------------------------------------------ #
    def guard_input(self, tool_id: str, args_text: str, **kwargs) -> Decision:
        decision = self.evaluate_input(tool_id, args_text, **kwargs)
        if decision.blocked:
            raise ToolBlocked(tool_id, decision.reason)
        return decision
