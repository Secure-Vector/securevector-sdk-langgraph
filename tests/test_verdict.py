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


# --- MCP candidate matching ---------------------------------------------- #
# mcp_<server>_<tool> is lossy; a rule authored in the cloud <server>:<tool>
# form must still govern the call.

def test_mcp_call_matches_cloud_server_tool_rule():
    synced = {"synced": [{"tool_id": "github:create_issue", "effect": "block", "policy_name": "corp"}]}
    v = _client()._resolve("mcp_github_create_issue", {}, {}, synced)
    assert v.action == "block"
    assert v.risk == "synced"


def test_mcp_call_matches_raw_function_name_rule():
    overrides = {"overrides": [{"tool_id": "mcp_github_create_issue", "action": "block"}]}
    v = _client()._resolve("mcp_github_create_issue", {}, overrides, {})
    assert v.action == "block"


def test_mcp_ambiguous_split_still_matches_underscored_server():
    # server "my-api" sanitized to my_api: rule my_api:list_items must match
    # mcp_my_api_list_items even though the split point is ambiguous.
    synced = {"synced": [{"tool_id": "my_api:list_items", "effect": "block"}]}
    v = _client()._resolve("mcp_my_api_list_items", {}, {}, synced)
    assert v.action == "block"


def test_tier_precedence_dominates_candidate_specificity():
    # A synced rule matching a LESS specific candidate still beats an
    # override matching the raw name.
    overrides = {"overrides": [{"tool_id": "mcp_github_create_issue", "action": "allow"}]}
    synced = {"synced": [{"tool_id": "github:create_issue", "effect": "block"}]}
    v = _client()._resolve("mcp_github_create_issue", {}, overrides, synced)
    assert v.action == "block"
    assert v.risk == "synced"
