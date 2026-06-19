"""The permission merge must match the app's own hook precedence:
synced > override > essential > default-allow."""

from securevector_sdk_langgraph.client import LocalAppClient
from securevector_sdk_langgraph.config import Config


def _client():
    return LocalAppClient(Config(base_url="http://127.0.0.1:8741"))


ESSENTIAL = {"tools": [
    {"tool_id": "Bash", "effective_action": "block", "risk": "high", "reason": "shell"},
    {"tool_id": "web_search", "effective_action": "allow", "risk": "low"},
]}


def test_default_allow_when_not_in_registry():
    v = _client()._resolve("random_tool", {}, {}, {})
    assert v.action == "allow"
    assert v.is_essential is False


def test_essential_block_applies():
    v = _client()._resolve("Bash", ESSENTIAL, {}, {})
    assert v.action == "block"
    assert v.is_essential is True
    assert v.risk == "high"


def test_essential_lookup_is_case_insensitive():
    v = _client()._resolve("bash", ESSENTIAL, {}, {})
    assert v.action == "block"
    assert v.is_essential is True


def test_override_beats_essential():
    overrides = {"overrides": [{"tool_id": "Bash", "action": "allow"}]}
    v = _client()._resolve("Bash", ESSENTIAL, overrides, {})
    assert v.action == "allow"
    assert v.risk == "overridden"


def test_synced_beats_override_and_essential():
    overrides = {"overrides": [{"tool_id": "Bash", "action": "allow"}]}
    synced = {"synced": [{"tool_id": "Bash", "effect": "block", "policy_name": "corp", "policy_version": 3}]}
    v = _client()._resolve("Bash", ESSENTIAL, overrides, synced)
    assert v.action == "block"
    assert v.risk == "synced"
    assert "corp" in v.reason and "v3" in v.reason


def test_synced_non_allow_effect_falls_back_to_block():
    synced = {"synced": [{"tool_id": "x", "effect": "warn"}]}
    v = _client()._resolve("x", {}, {}, synced)
    assert v.action == "block"  # engine has no warn action → safer block
