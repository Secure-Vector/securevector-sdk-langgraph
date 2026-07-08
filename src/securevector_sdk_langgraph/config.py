"""Adapter configuration — explicit kwargs override environment overrides
defaults.

Environment variables (all optional):
    SECUREVECTOR_ENGINE_ENDPOINT    engine endpoint — where tool calls are sent for
                                    analysis: the local app (default
                                    http://127.0.0.1:8741) or your own self-host
                                    engine (e.g. a Terraform deployment). The
                                    ENGINE, never the SecureVector cloud. Unified
                                    across the SDKs + the native plugins.
    SECUREVECTOR_SDK_APP_URL        legacy alias for the engine endpoint; honored
                                    only when SECUREVECTOR_ENGINE_ENDPOINT is unset
    SECUREVECTOR_SDK_MODE           observe | enforce          (default observe)
    SECUREVECTOR_SDK_TIMEOUT_MS     per-call verdict timeout   (default 3000)
    SECUREVECTOR_SDK_RISK_THRESHOLD enforce-block risk cutoff  (default 70)
    SECUREVECTOR_SDK_ANALYZE_MODE   SecureVectorClient mode    (default local)
    SECUREVECTOR_SDK_AGENT_ID       agent id for Cost Tracking attribution
                                    (default "<runtime>-agent")
    SECUREVECTOR_SDK_DISABLED       set truthy to no-op entirely
    SECUREVECTOR_API_KEY            credential forwarded to the app as
                                    Authorization: Bearer — required when the
                                    app is a remote, token-gated deployment
                                    (e.g. the Terraform self-host modules);
                                    unused for the default loopback app

Note: SECUREVECTOR_ENGINE_ENDPOINT (and its legacy alias
SECUREVECTOR_SDK_APP_URL) address the *engine* — the local app or a self-host
deployment. They are NOT SECUREVECTOR_URL, which points at the *cloud* API
elsewhere in the ecosystem; the SDK never talks to the cloud directly.
"""

import os
from dataclasses import dataclass

DEFAULT_BASE_URL = "http://127.0.0.1:8741"


def _truthy(val: str) -> bool:
    return str(val).strip().lower() in ("1", "true", "yes", "on")


@dataclass
class Config:
    base_url: str = DEFAULT_BASE_URL
    mode: str = "observe"            # observe (fail-open) | enforce (fail-closed)
    timeout_ms: int = 3000
    threat_risk_threshold: int = 70  # risk_score >= this blocks in enforce mode
    analyze_mode: str = "local"      # SecureVectorClient mode used for /analyze
    agent_id: str = ""               # Cost Tracking attribution ("" → "<runtime>-agent")
    enabled: bool = True
    api_key: str = ""                # forwarded as Authorization: Bearer to the app

    @classmethod
    def from_env(cls, **overrides) -> "Config":
        cfg = cls(
            base_url=os.environ.get("SECUREVECTOR_ENGINE_ENDPOINT")
            or os.environ.get("SECUREVECTOR_SDK_APP_URL", DEFAULT_BASE_URL),
            mode=os.environ.get("SECUREVECTOR_SDK_MODE", "observe").strip().lower(),
            timeout_ms=int(os.environ.get("SECUREVECTOR_SDK_TIMEOUT_MS", "3000")),
            threat_risk_threshold=int(
                os.environ.get("SECUREVECTOR_SDK_RISK_THRESHOLD", "70")
            ),
            analyze_mode=os.environ.get("SECUREVECTOR_SDK_ANALYZE_MODE", "local"),
            agent_id=os.environ.get("SECUREVECTOR_SDK_AGENT_ID", ""),
            enabled=not _truthy(os.environ.get("SECUREVECTOR_SDK_DISABLED", "")),
            api_key=os.environ.get("SECUREVECTOR_API_KEY", ""),
        )
        # Explicit kwargs win over env, but only when actually provided.
        for key, value in overrides.items():
            if value is not None and hasattr(cfg, key):
                setattr(cfg, key, value)
        if cfg.mode not in ("observe", "enforce"):
            cfg.mode = "observe"
        return cfg
