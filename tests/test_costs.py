"""Cost tracking (issue #185): usage extraction, provider/model normalization,
the /api/costs/track POST, and fail-soft behaviour."""

from securevector_sdk_langgraph.client import LocalAppClient
from securevector_sdk_langgraph.config import Config
from securevector_sdk_langgraph.costs import (
    CostTracker,
    extract_usage,
    infer_provider,
    iter_messages,
    make_model_call_handler,
    split_model_id,
)


class FakeMessage:
    def __init__(self, usage=None, meta=None):
        if usage is not None:
            self.usage_metadata = usage
        if meta is not None:
            self.response_metadata = meta


class CaptureClient:
    def __init__(self):
        self.costs = []

    def record_cost(self, **kwargs):
        self.costs.append(kwargs)
        return True


USAGE = {
    "input_tokens": 5300,
    "output_tokens": 870,
    "total_tokens": 6170,
    "input_token_details": {"cache_read": 4000},
}


# --------------------------------------------------------------------- #
# client.record_cost                                                    #
# --------------------------------------------------------------------- #
def test_record_cost_posts_contract_payload():
    c = LocalAppClient(Config())
    seen = {}

    def fake_post(path, body):
        seen["path"], seen["body"] = path, body
        return {"status": "recorded"}

    c._post = fake_post
    c.record_cost(
        agent_id="my-agent",
        provider="anthropic",
        model_id="claude-3-5-sonnet-20241022",
        input_tokens=5300,
        output_tokens=870,
        input_cached_tokens=4000,
    )
    assert seen["path"] == "/api/costs/track"
    assert seen["body"] == {
        "agent_id": "my-agent",
        "provider": "anthropic",
        "model_id": "claude-3-5-sonnet-20241022",
        "input_tokens": 5300,
        "output_tokens": 870,
        "input_cached_tokens": 4000,
    }


def test_record_cost_defaults_agent_id_and_clamps_negatives():
    c = LocalAppClient(Config())
    seen = {}
    c._post = lambda path, body: seen.update(body)
    c.record_cost(
        agent_id=None, provider="openai", model_id="gpt-4o",
        input_tokens=-5, output_tokens=10,
    )
    assert seen["agent_id"] == "langgraph-agent"
    assert seen["input_tokens"] == 0
    assert seen["input_cached_tokens"] == 0


def test_record_cost_fail_soft_when_app_unreachable():
    c = LocalAppClient(Config(base_url="http://127.0.0.1:1"))

    def boom(path, body):
        raise OSError("connection refused")

    c._post = boom
    # Must not raise — cost tracking never breaks the agent.
    c.record_cost(agent_id="a", provider="openai", model_id="gpt-4o",
                  input_tokens=1, output_tokens=1)


# --------------------------------------------------------------------- #
# extraction + normalization                                            #
# --------------------------------------------------------------------- #
def test_extract_usage_reads_tokens_and_cache():
    usage = extract_usage(FakeMessage(usage=USAGE))
    assert usage == {"input": 5300, "output": 870, "cached": 4000}


def test_extract_usage_none_without_usage_or_tokens():
    assert extract_usage(FakeMessage()) is None
    assert extract_usage(FakeMessage(usage={"input_tokens": 0, "output_tokens": 0})) is None
    assert extract_usage("not-a-message") is None


def test_split_model_id_applies_aliases_and_provider_prefix():
    assert split_model_id("gpt-4o-2024-08-06") == (None, "gpt-4o")
    assert split_model_id("openai/gpt-4o-2024-11-20") == ("openai", "gpt-4o")
    assert split_model_id("mistralai/mistral-large-2411") == ("mistral", "mistral-large-latest")
    assert split_model_id("claude-3-5-sonnet-20241022") == (None, "claude-3-5-sonnet-20241022")
    assert split_model_id(None) == (None, "")


def test_infer_provider_precedence():
    # response_metadata model_provider wins
    assert infer_provider(response_metadata={"model_provider": "google_genai"}) == "gemini"
    # model-id heuristics
    assert infer_provider(model_id="claude-3-5-haiku-20241022") == "anthropic"
    assert infer_provider(model_id="gpt-4o") == "openai"
    assert infer_provider(model_id="o3-mini") == "openai"
    assert infer_provider(model_id="gemini-1.5-pro") == "gemini"
    assert infer_provider(model_id="command-r") == "cohere"
    assert infer_provider(model_id="totally-unknown") == ""


# --------------------------------------------------------------------- #
# CostTracker                                                           #
# --------------------------------------------------------------------- #
def test_tracker_records_from_message_metadata():
    client = CaptureClient()
    tracker = CostTracker(Config(), client=client)
    msg = FakeMessage(usage=USAGE, meta={"model_name": "claude-3-5-sonnet-20241022"})
    assert tracker.record_message(msg) is True
    assert client.costs == [{
        "agent_id": "langgraph-agent",
        "provider": "anthropic",
        "model_id": "claude-3-5-sonnet-20241022",
        "input_tokens": 5300,
        "output_tokens": 870,
        "input_cached_tokens": 4000,
    }]


def test_tracker_falls_back_to_model_object_for_model_id():
    client = CaptureClient()
    tracker = CostTracker(Config(), client=client)

    class Model:
        model_name = "gpt-4o-2024-08-06"

    assert tracker.record_message(FakeMessage(usage=USAGE), model=Model()) is True
    assert client.costs[0]["model_id"] == "gpt-4o"
    assert client.costs[0]["provider"] == "openai"


def test_tracker_skips_messages_without_usage_or_model():
    client = CaptureClient()
    tracker = CostTracker(Config(), client=client)
    assert tracker.record_message(FakeMessage(meta={"model_name": "gpt-4o"})) is False
    assert tracker.record_message(FakeMessage(usage=USAGE)) is False  # no model id anywhere
    assert client.costs == []


def test_tracker_disabled_config_posts_nothing():
    client = CaptureClient()
    tracker = CostTracker(Config(enabled=False), client=client)
    msg = FakeMessage(usage=USAGE, meta={"model_name": "gpt-4o"})
    assert tracker.record_message(msg) is False
    assert client.costs == []


def test_tracker_agent_id_overrides():
    client = CaptureClient()
    msg = FakeMessage(usage=USAGE, meta={"model_name": "gpt-4o"})
    CostTracker(Config(agent_id="from-config"), client=client).record_message(msg)
    CostTracker(Config(), client=client, agent_id="explicit").record_message(msg)
    assert [c["agent_id"] for c in client.costs] == ["from-config", "explicit"]


def test_tracker_never_raises_on_client_failure():
    class BoomClient:
        def record_cost(self, **kwargs):
            raise RuntimeError("boom")

    tracker = CostTracker(Config(), client=BoomClient())
    msg = FakeMessage(usage=USAGE, meta={"model_name": "gpt-4o"})
    assert tracker.record_message(msg) is False


# --------------------------------------------------------------------- #
# wrap_model_call handler                                               #
# --------------------------------------------------------------------- #
class FakeModelResponse:
    def __init__(self, messages):
        self.result = messages


class FakeModelRequest:
    def __init__(self, model=None):
        self.model = model


def test_iter_messages_shapes():
    m = FakeMessage(usage=USAGE)
    assert list(iter_messages(m)) == [m]
    assert list(iter_messages([m, m])) == [m, m]
    assert list(iter_messages(FakeModelResponse([m]))) == [m]
    assert list(iter_messages(None)) == []


def test_model_call_handler_records_and_returns_response():
    client = CaptureClient()
    tracker = CostTracker(Config(), client=client)
    handler_fn = make_model_call_handler(tracker)

    msg = FakeMessage(usage=USAGE, meta={"model_name": "claude-3-5-sonnet-20241022"})
    response = FakeModelResponse([msg])
    result = handler_fn(FakeModelRequest(), lambda req: response)

    assert result is response  # response passes through untouched
    assert len(client.costs) == 1
    assert client.costs[0]["provider"] == "anthropic"


def test_model_call_handler_fail_soft_keeps_response():
    class BoomClient:
        def record_cost(self, **kwargs):
            raise RuntimeError("boom")

    tracker = CostTracker(Config(), client=BoomClient())
    handler_fn = make_model_call_handler(tracker)
    msg = FakeMessage(usage=USAGE, meta={"model_name": "gpt-4o"})
    response = FakeModelResponse([msg])
    assert handler_fn(FakeModelRequest(), lambda req: response) is response


# --------------------------------------------------------------------- #
# legacy callback path (on_llm_end)                                     #
# --------------------------------------------------------------------- #
def test_callback_handler_on_llm_end_records_usage():
    from securevector_sdk_langgraph.handler import SecureVectorCallbackHandler

    h = SecureVectorCallbackHandler()
    client = CaptureClient()
    h.costs.client = client

    class Gen:
        def __init__(self, message):
            self.message = message

    class LLMResult:
        def __init__(self, gens):
            self.generations = gens

    msg = FakeMessage(usage=USAGE, meta={"model_name": "gpt-4o"})
    h.on_llm_end(LLMResult([[Gen(msg)]]), run_id="r1")
    assert len(client.costs) == 1
    assert client.costs[0]["model_id"] == "gpt-4o"

    # malformed result → fail-soft
    h.on_llm_end(object(), run_id="r2")
    assert len(client.costs) == 1


def test_env_agent_id(monkeypatch):
    monkeypatch.setenv("SECUREVECTOR_SDK_AGENT_ID", "env-agent")
    cfg = Config.from_env()
    client = CaptureClient()
    tracker = CostTracker(cfg, client=client)
    tracker.record_message(FakeMessage(usage=USAGE, meta={"model_name": "gpt-4o"}))
    assert client.costs[0]["agent_id"] == "env-agent"
