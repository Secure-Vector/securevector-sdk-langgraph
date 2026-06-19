"""Control routing — the three checks on every tool call.

This is the actual new logic the adapter contributes. Detection already exists
in the app; the job here is **interception + routing + the observe/enforce
state machine**. Per intercepted call, in order:

    (a) PERMISSIONS  — resolve allow/block for the tool id
    (b) SECRET scan  — \\
    (c) THREAT scan  — // over the serialized tool input (and, on end, output)

``observe`` (default) is fail-open: everything is logged, nothing is ever
blocked, and an unreachable app degrades to allow. ``enforce`` is fail-closed:
a policy block, a high-risk input finding, or an unreachable app all DENY by
raising ``ToolBlocked`` before the tool executes.
"""

import logging
import re
import sys
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


class Interceptor:
    """Framework-agnostic engine. The LangChain handler feeds it normalized
    (tool_id, text); this class owns the policy."""

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
                "BLOCKED if the local app is unreachable or a policy denies them.\n"
            )

    def on_tool_start(
        self,
        tool_id: str,
        args_text: str,
        *,
        session_id: Optional[str] = None,
        request_id: Optional[str] = None,
    ) -> None:
        if not self.cfg.enabled:
            return
        self._disclose_once()
        preview = redact(args_text)

        # (a) PERMISSIONS
        try:
            verdict = self.client.resolve_permission(tool_id)
        except AppUnreachable as exc:
            if self.enforce:
                raise ToolBlocked(tool_id, "local app unreachable (fail-closed)") from exc
            log.warning("app unreachable; observe mode allows %s", tool_id)
            return

        if verdict.action == "block":
            self.client.record_audit(
                tool_id=tool_id, function_name=tool_id, action="block",
                risk=verdict.risk, reason=verdict.reason,
                is_essential=verdict.is_essential, args_preview=preview,
                session_id=session_id, request_id=request_id,
            )
            if self.enforce:
                raise ToolBlocked(tool_id, verdict.reason)
            return

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
            if should_block:
                raise ToolBlocked(tool_id, f"input threat risk={a_in.risk_score}")
            return

        # Allowed — record the decision.
        self.client.record_audit(
            tool_id=tool_id, function_name=tool_id, action="allow",
            risk=verdict.risk, reason=verdict.reason,
            is_essential=verdict.is_essential, args_preview=preview,
            session_id=session_id, request_id=request_id,
        )

    def on_tool_end(
        self,
        tool_id: str,
        output_text: str,
        *,
        session_id: Optional[str] = None,
        request_id: Optional[str] = None,
    ) -> None:
        """Scan the tool RESULT for secrets / exfiltration. Output scanning is
        observe-only (the tool already ran) — we log, we never raise here."""
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
