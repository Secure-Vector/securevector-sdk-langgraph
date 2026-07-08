from securevector_sdk_langgraph.tool_id import (
    RUNTIME_KIND,
    candidate_tool_ids,
    normalize_tool_id,
)


def test_runtime_kind_is_langchain():
    assert RUNTIME_KIND == "langgraph"


def test_name_from_serialized_dict():
    assert normalize_tool_id({"name": "web_search"}) == "web_search"


def test_name_from_dotted_id_path():
    assert normalize_tool_id({"id": ["langchain", "tools", "ShellTool"]}) == "ShellTool"


def test_flat_name_kwarg_fallback():
    assert normalize_tool_id(None, name="bash") == "bash"


def test_casing_preserved():
    assert normalize_tool_id({"name": "Bash"}) == "Bash"


def test_missing_everything_is_unknown():
    assert normalize_tool_id(None) == "unknown"
    assert normalize_tool_id({}) == "unknown"
    assert normalize_tool_id({"name": "   "}) == "unknown"


def test_non_mcp_candidates_are_just_the_name():
    assert candidate_tool_ids("terminal") == ["terminal"]


def test_mcp_candidates_emit_every_server_tool_split():
    cands = candidate_tool_ids("mcp_my_api_list_items")
    assert cands[0] == "mcp_my_api_list_items"  # raw name is most specific
    assert "my:api_list_items" in cands
    assert "my_api:list_items" in cands
    assert "my_api_list:items" in cands
    assert len(cands) == 4


def test_mcp_single_segment_has_no_split():
    assert candidate_tool_ids("mcp_solo") == ["mcp_solo"]
