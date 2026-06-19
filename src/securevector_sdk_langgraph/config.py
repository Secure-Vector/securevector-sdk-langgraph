"""Adapter configuration — explicit kwargs override environment overrides
defaults.

Environment variables (all optional):
    SECUREVECTOR_SDK_APP_URL        local app base URL (default http://127.0.0.1:8741)
    SECUREVECTOR_SDK_MODE           observe | enforce          (default observe)
    SECUREVECTOR_SDK_TIMEOUT_MS     per-call verdict timeout   (default 3000)
    SECUREVECTOR_SDK_RISK_THRESHOLD enforce-block risk cutoff  (default 70)
    SECUREVECTOR_SDK_ANALYZE_MODE   SecureVectorClient mode    (default local)
    SECUREVECTOR_SDK_DISABLED       set truthy to no-op entirely

Note: we deliberately use SECUREVECTOR_SDK_APP_URL, not the existing
SECUREVECTOR_URL — the latter points at the *cloud* API in the rest of the
ecosystem, whereas the SDK talks to the *local* app.
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
    enabled: bool = True

    @classmethod
    def from_env(cls, **overrides) -> "Config":
        cfg = cls(
            base_url=os.environ.get("SECUREVECTOR_SDK_APP_URL", DEFAULT_BASE_URL),
            mode=os.environ.get("SECUREVECTOR_SDK_MODE", "observe").strip().lower(),
            timeout_ms=int(os.environ.get("SECUREVECTOR_SDK_TIMEOUT_MS", "3000")),
            threat_risk_threshold=int(
                os.environ.get("SECUREVECTOR_SDK_RISK_THRESHOLD", "70")
            ),
            analyze_mode=os.environ.get("SECUREVECTOR_SDK_ANALYZE_MODE", "local"),
            enabled=not _truthy(os.environ.get("SECUREVECTOR_SDK_DISABLED", "")),
        )
        # Explicit kwargs win over env, but only when actually provided.
        for key, value in overrides.items():
            if value is not None and hasattr(cfg, key):
                setattr(cfg, key, value)
        if cfg.mode not in ("observe", "enforce"):
            cfg.mode = "observe"
        return cfg
