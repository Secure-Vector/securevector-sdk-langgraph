"""Thin client to the local SecureVector app.

Two transports, on purpose:

* **Tool-permission resolution + audit** go over the local REST API
  (``/api/tool-permissions/*``) via the stdlib (``urllib``) — no extra HTTP
  dependency. The permission *decision* is computed client-side by merging the
  three policy tiers exactly as the app's own OpenClaw hook does:
  synced (cloud-pushed) > local override > essential registry > default-allow.

* **Secret + threat detection** reuses the already-shipped ``SecureVectorClient``
  from ``securevector-ai-monitor`` — the detection engine lives there; the
  adapter must not reimplement it.

Everything is best-effort and lazy: importing this module never requires the
app or langchain to be installed, so unit tests run standalone.
"""

import json
import logging
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from .config import Config
from .errors import AppUnreachable
from .tool_id import RUNTIME_KIND

log = logging.getLogger("securevector_sdk_langgraph")

_VALID_AUDIT_ACTIONS = ("block", "allow", "log_only")


@dataclass
class Verdict:
    """Resolved permission decision for one tool id."""

    action: str          # allow | block | log_only
    risk: str
    reason: str
    is_essential: bool
    tool_id: str


@dataclass
class AnalysisVerdict:
    """Outcome of a secret/threat scan over a piece of text."""

    is_threat: bool
    risk_score: int
    reason: str


class LocalAppClient:
    def __init__(self, cfg: Config):
        self.cfg = cfg

    # ------------------------------------------------------------------ #
    # REST transport (stdlib)                                            #
    # ------------------------------------------------------------------ #
    def _request(self, method: str, path: str, body: Optional[dict]) -> Any:
        url = f"{self.cfg.base_url.rstrip('/')}{path}"
        data = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(
            url,
            data=data,
            method=method,
            headers={"Content-Type": "application/json"},
        )
        timeout = max(self.cfg.timeout_ms / 1000.0, 0.1)
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (localhost)
            raw = resp.read()
            return json.loads(raw) if raw else {}

    def _get(self, path: str) -> Any:
        return self._request("GET", path, None)

    def _post(self, path: str, body: dict) -> Any:
        return self._request("POST", path, body)

    def reachable(self) -> bool:
        try:
            self._get("/api/tool-permissions/essential")
            return True
        except Exception:
            return False

    # ------------------------------------------------------------------ #
    # (a) Permissions — synced > override > essential > default-allow    #
    # ------------------------------------------------------------------ #
    def resolve_permission(self, tool_id: str) -> Verdict:
        try:
            essential = self._get("/api/tool-permissions/essential") or {}
            overrides = self._get("/api/tool-permissions/overrides") or {}
            synced = self._get(
                "/api/tool-permissions/synced-overrides?"
                + urllib.parse.urlencode({"runtime": RUNTIME_KIND})
            ) or {}
        except (urllib.error.URLError, OSError, json.JSONDecodeError) as exc:
            raise AppUnreachable(str(exc)) from exc
        return self._resolve(tool_id, essential, overrides, synced)

    @staticmethod
    def _index(arr: Optional[List[dict]], key: str) -> Dict[str, dict]:
        """Index rows by their id, with a case-insensitive fallback (exact
        casing wins, mirroring the app's lookup)."""
        out: Dict[str, dict] = {}
        for item in arr or []:
            k = item.get(key)
            if k is not None:
                out.setdefault(str(k).lower(), item)
        for item in arr or []:
            k = item.get(key)
            if k is not None:
                out[str(k)] = item
        return out

    def _resolve(self, tool_id, essential, overrides, synced) -> Verdict:
        name = tool_id
        low = tool_id.lower()
        emap = self._index(essential.get("tools"), "tool_id")
        omap = self._index(overrides.get("overrides"), "tool_id")
        smap = self._index(synced.get("synced"), "tool_id")

        # 1. Cloud-pushed synced policy wins.
        s = smap.get(name) or smap.get(low)
        if s:
            effect = str(s.get("effect", "")).lower()
            action = "allow" if effect == "allow" else "block"
            policy = s.get("policy_name") or s.get("policy_id") or "synced"
            ver = f" v{s['policy_version']}" if s.get("policy_version") is not None else ""
            return Verdict(
                action, "synced", f"Synced policy '{policy}'{ver}: {effect}",
                (name in emap or low in emap), name,
            )
        # 2. Local user override.
        o = omap.get(name) or omap.get(low)
        if o:
            return Verdict(
                o.get("action", "allow"), "overridden",
                f"User override: {o.get('action')}",
                (name in emap or low in emap), name,
            )
        # 3. Essential registry default.
        e = emap.get(name) or emap.get(low)
        if e:
            return Verdict(
                e.get("effective_action") or e.get("default_action") or "allow",
                e.get("risk", "unknown"), e.get("reason", "Essential tool policy"),
                True, name,
            )
        # 4. Not in registry — allowed by default.
        return Verdict("allow", "unknown", "Not in registry — allowed by default", False, name)

    # ------------------------------------------------------------------ #
    # (b)+(c) Secret + threat detection — the running app's /api/analyze       #
    # ------------------------------------------------------------------ #
    # We deliberately use the app's REST `/analyze` (same engine, same HTTP
    # transport as permissions/audit) rather than constructing an in-process
    # SecureVectorClient: the SDK already requires the app running, and the
    # in-process local analyzer needs its own config/license and can raise on
    # init. Tool input is user→tool ("outgoing"); tool output is fetched
    # context→model, which is exactly the app's IDPI "incoming" scan mode.
    _DIRECTION_MODE = {"tool_input": "outgoing", "tool_output": "incoming"}

    def analyze(self, text: str, direction: str) -> AnalysisVerdict:
        if not text:
            return AnalysisVerdict(False, 0, "empty")
        mode = self._DIRECTION_MODE.get(direction, "outgoing")
        try:
            # The analyze route is mounted at /analyze (no /api prefix).
            res = self._post("/analyze", {"text": str(text)[:102400], "mode": mode})
        except (urllib.error.URLError, OSError, json.JSONDecodeError) as exc:
            raise AppUnreachable(f"analyze failed: {exc}") from exc
        if not isinstance(res, dict):
            return AnalysisVerdict(False, 0, "no-result")
        risk = int(res.get("risk_score") or 0)
        is_threat = bool(res.get("is_threat", False))
        # Secrets/data-leaks also surface via redaction: the app sets
        # redacted_text (and action_taken=redact/block) when it catches a secret.
        # Control (b) keys on that, control (c) on is_threat. A finding is either.
        has_secret = bool(res.get("redacted_text")) or (res.get("action_taken") in ("redact", "block"))
        finding = is_threat or has_secret
        return AnalysisVerdict(
            finding, risk,
            f"{direction} threat={is_threat} secret={has_secret} risk={risk}",
        )

    # ------------------------------------------------------------------ #
    # Audit — append to the tamper-evident chain                         #
    # ------------------------------------------------------------------ #
    def record_audit(
        self,
        *,
        tool_id: str,
        function_name: Optional[str],
        action: str,
        risk: Optional[str],
        reason: Optional[str],
        is_essential: bool,
        args_preview: Optional[str],
        session_id: Optional[str] = None,
        request_id: Optional[str] = None,
    ) -> None:
        act = action if action in _VALID_AUDIT_ACTIONS else "log_only"
        body = {
            "tool_id": tool_id,
            "function_name": function_name or tool_id,
            "action": act,
            "risk": risk,
            "reason": reason,
            "is_essential": bool(is_essential),
            "args_preview": args_preview,
            "runtime_kind": RUNTIME_KIND,
            "session_id": session_id,
            "request_id": (request_id or None) and str(request_id)[:64],
        }
        try:
            self._post("/api/tool-permissions/call-audit", body)
        except Exception as exc:  # never let audit failure break the agent
            log.debug("audit post failed: %s", exc)

    # ------------------------------------------------------------------ #
    # Cost tracking — LLM token usage → the app's Cost Tracking          #
    # ------------------------------------------------------------------ #
    def record_cost(
        self,
        *,
        agent_id: Optional[str],
        provider: str,
        model_id: str,
        input_tokens: int,
        output_tokens: int,
        input_cached_tokens: int = 0,
    ) -> bool:
        """POST one LLM call's token usage to ``/api/costs/track``.

        The app resolves pricing by exact ``"{provider}/{model_id}"`` and
        computes the dollar cost; unknown pairs are still recorded (at $0,
        ``pricing_known=false``). Best-effort like ``record_audit``; returns
        True when the app accepted the record.
        """
        body = {
            "agent_id": agent_id or f"{RUNTIME_KIND}-agent",
            "provider": provider,
            "model_id": model_id,
            "input_tokens": max(int(input_tokens or 0), 0),
            "output_tokens": max(int(output_tokens or 0), 0),
            "input_cached_tokens": max(int(input_cached_tokens or 0), 0),
        }
        try:
            self._post("/api/costs/track", body)
            return True
        except Exception as exc:  # never let cost tracking break the agent
            log.debug("cost post failed: %s", exc)
            return False
