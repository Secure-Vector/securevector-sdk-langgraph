"""The wrap_tool_call handler must short-circuit with a ToolMessage on an
enforce block, and otherwise call the real handler and scan output."""

from securevector_sdk_langgraph.client import AnalysisVerdict, Verdict
from securevector_sdk_langgraph.config import Config
from securevector_sdk_langgraph.core import Interceptor
from securevector_sdk_langgraph.middleware import _make_tool_call_handler


class FakeClient:
    def __init__(self, verdict=None, analysis=None):
        self._verdict = verdict or Verdict("allow", "unknown", "ok", False, "t")
        self._analysis = analysis or AnalysisVerdict(False, 0, "clean")
        self.audits = []

    def resolve_permission(self, tool_id):
        return self._verdict

    def analyze(self, text, direction):
        return self._analysis

    def record_audit(self, **kw):
        self.audits.append(kw)


class FakeToolMessage:
    def __init__(self, content, tool_call_id=None, status=None):
        self.content = content
        self.tool_call_id = tool_call_id
        self.status = status


class FakeRequest:
    def __init__(self, name, args, call_id="call-1"):
        self.tool_call = {"name": name, "args": args, "id": call_id}


def _handler(mode, client):
    icept = Interceptor(Config(mode=mode), client=client)
    return _make_tool_call_handler(icept, "sess", FakeToolMessage)


def test_enforce_block_short_circuits_with_toolmessage():
    c = FakeClient(verdict=Verdict("block", "high", "shell", True, "Bash"))
    cb = _handler("enforce", c)
    ran = {"called": False}

    def real_handler(req):
        ran["called"] = True
        return FakeToolMessage("should not run", "call-1")

    result = cb(FakeRequest("Bash", {"cmd": "rm -rf /"}), real_handler)
    assert ran["called"] is False                      # tool never executed
    assert isinstance(result, FakeToolMessage)
    assert "blocked" in result.content.lower()
    assert result.status == "error"
    assert c.audits[-1]["action"] == "block"


def test_observe_block_still_runs_tool():
    c = FakeClient(verdict=Verdict("block", "high", "shell", True, "Bash"))
    cb = _handler("observe", c)
    ran = {"called": False}

    def real_handler(req):
        ran["called"] = True
        return FakeToolMessage("ran", "call-1")

    result = cb(FakeRequest("Bash", {"cmd": "ls"}), real_handler)
    assert ran["called"] is True                       # observe never blocks
    assert result.content == "ran"
    assert c.audits[-1]["action"] == "block"           # but it is logged


def test_allow_runs_and_scans_output():
    c = FakeClient(
        verdict=Verdict("allow", "low", "ok", False, "web_search"),
        analysis=AnalysisVerdict(False, 0, "clean"),
    )
    cb = _handler("enforce", c)
    result = cb(FakeRequest("web_search", {"q": "hi"}), lambda req: FakeToolMessage("answer", "call-1"))
    assert result.content == "answer"
    assert any(a["action"] == "allow" for a in c.audits)
