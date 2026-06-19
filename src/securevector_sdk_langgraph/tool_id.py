"""Canonical tool-id normalization — the ONLY framework-specific mapping.

The whole SecureVector fleet keys permissions and audit on a single canonical
``tool_id``. LangChain surfaces a tool's name as ``Tool.name``, delivered in
the callback's ``serialized["name"]`` (or, for newer cores, a flat ``name``
kwarg). Normalizing it here is the one piece of LangChain-specific code; every
downstream step (permission resolution, analysis, audit) is shared engine
behaviour, so a policy authored once — "allow web_search, block shell" —
applies identically across LangChain / LangGraph / CrewAI.

Casing is preserved: the local app matches tool ids case-insensitively, so a
rule authored ``tool_id="Bash"`` still governs a LangChain tool named ``bash``.
"""

from typing import Any, Optional

# The audit/Bill-of-Tools/OCSF pipeline groups by this attribution tag.
RUNTIME_KIND = "langgraph"


def normalize_tool_id(serialized: Any, name: Optional[str] = None) -> str:
    """Resolve a canonical tool id from a LangChain ``on_tool_start`` payload.

    Accepts the legacy ``serialized`` dict (``{"name": ...}`` or a dotted
    ``{"id": [...]}`` path) and/or a flat ``name`` kwarg. Falls back to
    ``"unknown"`` so a missing name never crashes the agent.
    """
    raw: Optional[str] = None
    if isinstance(serialized, dict):
        raw = serialized.get("name")
        if not raw:
            ident = serialized.get("id")
            if isinstance(ident, (list, tuple)) and ident:
                raw = str(ident[-1])
    if not raw:
        raw = name
    if not raw:
        return "unknown"
    return str(raw).strip() or "unknown"
