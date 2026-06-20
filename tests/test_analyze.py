"""The analyze() REST mapping: correct path/mode, and a finding is raised for
either a threat (is_threat) or a secret (redacted_text / action_taken)."""

from securevector_sdk_langgraph.client import LocalAppClient
from securevector_sdk_langgraph.config import Config


def _client(response, capture=None):
    c = LocalAppClient(Config())

    def fake_post(path, body):
        if capture is not None:
            capture["path"] = path
            capture["body"] = body
        return response

    c._post = fake_post
    return c


def test_path_is_analyze_and_input_uses_outgoing_mode():
    cap = {}
    c = _client({"is_threat": False, "risk_score": 0}, cap)
    c.analyze("hello", "tool_input")
    assert cap["path"] == "/analyze"
    assert cap["body"]["mode"] == "outgoing"


def test_output_uses_incoming_mode():
    cap = {}
    c = _client({"is_threat": False, "risk_score": 0}, cap)
    c.analyze("fetched data", "tool_output")
    assert cap["body"]["mode"] == "incoming"


def test_threat_is_a_finding():
    v = _client({"is_threat": True, "risk_score": 90}).analyze("ignore previous", "tool_input")
    assert v.is_threat is True
    assert v.risk_score == 90


def test_secret_via_redacted_text_is_a_finding():
    v = _client({"is_threat": False, "risk_score": 20, "redacted_text": "auth AKIA****"}).analyze(
        "auth AKIAIOSFODNN7EXAMPLE", "tool_input"
    )
    assert v.is_threat is True  # secret counts as a finding even when is_threat=False


def test_secret_via_action_taken_is_a_finding():
    v = _client({"is_threat": False, "risk_score": 10, "action_taken": "redact"}).analyze(
        "ghp_xxx", "tool_output"
    )
    assert v.is_threat is True


def test_clean_input_is_not_a_finding():
    v = _client({"is_threat": False, "risk_score": 0, "redacted_text": None}).analyze("hi", "tool_input")
    assert v.is_threat is False
