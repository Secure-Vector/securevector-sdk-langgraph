from securevector_sdk_langgraph.tool_id import RUNTIME_KIND, normalize_tool_id


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
