"""LLM cost tracking — post model-call token usage to the local app.

The tool middleware secures tool calls but never sees the model call, so
framework agents were invisible to the app's Cost Tracking. This module
observes LLM usage (``AIMessage.usage_metadata``) and POSTs it to the app's
``POST /api/costs/track``, which looks up pricing by exact
``"{provider}/{model_id}"`` and computes dollars. SDK agents run on the
user's own API keys (like the proxy), so the dollar cost is real.

Wiring (LangChain v1 ``create_agent``)::

    from securevector_sdk_langgraph import secure_middleware, cost_tracking_middleware

    agent = create_agent(
        model, tools,
        middleware=[secure_middleware(mode="enforce"), cost_tracking_middleware()],
    )

Legacy AgentExecutor / raw LCEL chains get the same capture automatically via
``SecureVectorCallbackHandler`` (``on_llm_end``).

Everything here is best-effort: an unreachable app, an unknown provider, or an
exotic message shape never breaks the agent (mirrors the audit fail-soft).
"""

import logging
import re
from typing import Any, Dict, Iterable, Optional, Tuple

from .client import LocalAppClient
from .config import Config
from .tool_id import RUNTIME_KIND

log = logging.getLogger("securevector_sdk_langgraph")

# Map versioned model ids to the canonical pricing keys the app's pricing
# table uses. Mirrors the app-side CostRecorder aliases: /api/costs/track
# itself does an EXACT "provider/model_id" match with no normalization, so
# the SDK must normalize client-side or records land as pricing_known=false.
MODEL_ID_ALIASES: Dict[str, str] = {
    # OpenAI versioned → canonical
    "gpt-4o-2024-11-20": "gpt-4o",
    "gpt-4o-2024-08-06": "gpt-4o",
    "gpt-4o-2024-05-13": "gpt-4o",
    "gpt-4o-mini-2024-07-18": "gpt-4o-mini",
    "gpt-4-turbo-2024-04-09": "gpt-4-turbo",
    "gpt-4-turbo-preview": "gpt-4-turbo",
    "gpt-3.5-turbo-0125": "gpt-3.5-turbo",
    "gpt-3.5-turbo-1106": "gpt-3.5-turbo",
    "o1-2024-12-17": "o1",
    "o1-mini-2024-09-12": "o1-mini",
    "o3-mini-2025-01-31": "o3-mini",
    # Gemini variants → canonical
    "gemini-2.0-flash-001": "gemini-2.0-flash",
    "gemini-2.0-flash-exp": "gemini-2.0-flash",
    "gemini-1.5-pro-001": "gemini-1.5-pro",
    "gemini-1.5-pro-002": "gemini-1.5-pro",
    "gemini-1.5-flash-001": "gemini-1.5-flash",
    "gemini-1.5-flash-002": "gemini-1.5-flash",
    # Mistral versioned
    "mistral-large-2402": "mistral-large-latest",
    "mistral-large-2407": "mistral-large-latest",
    "mistral-large-2411": "mistral-large-latest",
    "mistral-small-2402": "mistral-small-latest",
    "mistral-small-2409": "mistral-small-latest",
    # Cohere versioned
    "command-r-plus": "command-r-plus-08-2024",
    "command-r": "command-r-08-2024",
}

# Provider slugs the pricing table keys on: openai / anthropic / gemini /
# ollama / groq / mistral / cohere. Canonicalize the many spellings the
# LangChain ecosystem uses for the same provider.
_PROVIDER_CANON: Dict[str, str] = {
    "openai": "openai",
    "azure_openai": "openai",
    "azure-openai": "openai",
    "anthropic": "anthropic",
    "google_genai": "gemini",
    "google-genai": "gemini",
    "google_vertexai": "gemini",
    "google": "gemini",
    "gemini": "gemini",
    "vertexai": "gemini",
    "vertex_ai": "gemini",
    "ollama": "ollama",
    "groq": "groq",
    "mistralai": "mistral",
    "mistral": "mistral",
    "cohere": "cohere",
}

# ``type(model).__module__`` prefix → provider (integration packages).
_MODULE_PROVIDERS: Tuple[Tuple[str, str], ...] = (
    ("langchain_openai", "openai"),
    ("langchain_anthropic", "anthropic"),
    ("langchain_google", "gemini"),
    ("langchain_ollama", "ollama"),
    ("langchain_groq", "groq"),
    ("langchain_mistralai", "mistral"),
    ("langchain_cohere", "cohere"),
)

# Last-resort heuristics on the model id itself.
_MODEL_PREFIX_PROVIDERS: Tuple[Tuple[str, str], ...] = (
    ("gpt-", "openai"),
    ("chatgpt", "openai"),
    ("claude", "anthropic"),
    ("gemini", "gemini"),
    ("mistral", "mistral"),
    ("ministral", "mistral"),
    ("codestral", "mistral"),
    ("command", "cohere"),
)
_OPENAI_O_SERIES = re.compile(r"^o\d(-|$)")


def split_model_id(raw: Any) -> Tuple[Optional[str], str]:
    """Split a possibly provider-prefixed model id (``"openai/gpt-4o"``,
    litellm-style) into ``(provider_hint, bare_model_id)`` and apply the
    canonical-pricing aliases."""
    mid = str(raw or "").strip()
    hint: Optional[str] = None
    if "/" in mid:
        prefix, rest = mid.split("/", 1)
        canon = _PROVIDER_CANON.get(prefix.strip().lower())
        if canon:
            hint, mid = canon, rest.strip()
    return hint, MODEL_ID_ALIASES.get(mid, mid)


def infer_provider(
    model: Any = None,
    model_id: str = "",
    response_metadata: Optional[dict] = None,
) -> str:
    """Best-effort provider slug for the pricing lookup ('' when unknown)."""
    meta = response_metadata or {}
    canon = _PROVIDER_CANON.get(str(meta.get("model_provider") or "").strip().lower())
    if canon:
        return canon
    module = getattr(type(model), "__module__", "") if model is not None else ""
    for prefix, provider in _MODULE_PROVIDERS:
        if module.startswith(prefix):
            return provider
    mid = str(model_id or "").strip().lower()
    if _OPENAI_O_SERIES.match(mid):
        return "openai"
    for prefix, provider in _MODEL_PREFIX_PROVIDERS:
        if mid.startswith(prefix):
            return provider
    return ""


def _field(obj: Any, name: str) -> Any:
    if isinstance(obj, dict):
        return obj.get(name)
    return getattr(obj, name, None)


def extract_usage(message: Any) -> Optional[Dict[str, int]]:
    """Pull ``{input, output, cached}`` token counts off an AIMessage-shaped
    object (``usage_metadata`` attr or key). None when there is no usage."""
    usage = _field(message, "usage_metadata")
    if not usage:
        return None
    input_tokens = int(_field(usage, "input_tokens") or 0)
    output_tokens = int(_field(usage, "output_tokens") or 0)
    if input_tokens <= 0 and output_tokens <= 0:
        return None
    details = _field(usage, "input_token_details") or {}
    cached = int(_field(details, "cache_read") or 0)
    return {"input": input_tokens, "output": output_tokens, "cached": cached}


def _model_id_of(model: Any) -> str:
    for attr in ("model_name", "model", "model_id"):
        value = getattr(model, attr, None)
        if isinstance(value, str) and value.strip():
            return value
    return ""


def iter_messages(result: Any) -> Iterable[Any]:
    """Yield candidate messages from whatever a model-call handler returned
    (an AIMessage, a ModelResponse with ``.result``, or a plain list)."""
    if result is None:
        return []
    inner = getattr(result, "result", None)
    if inner is not None and not isinstance(inner, (str, bytes)):
        result = inner
    if isinstance(result, (list, tuple)):
        return result
    return [result]


class CostTracker:
    """Extracts usage from messages and posts it, tagged by runtime.

    ``agent_id`` groups records in the app's Cost Tracking dashboard; the
    default is a stable per-runtime id so all agents of this framework roll
    up together unless the user names theirs.
    """

    def __init__(
        self,
        cfg: Config,
        client: Optional[LocalAppClient] = None,
        agent_id: Optional[str] = None,
    ):
        self.cfg = cfg
        self.client = client or LocalAppClient(cfg)
        self.agent_id = agent_id or cfg.agent_id or f"{RUNTIME_KIND}-agent"

    def record_message(self, message: Any, model: Any = None) -> bool:
        """Record one message's usage. Returns True when a record was posted.
        Never raises."""
        if not self.cfg.enabled:
            return False
        try:
            usage = extract_usage(message)
            if usage is None:
                return False
            meta = _field(message, "response_metadata") or {}
            raw_model = (
                _field(meta, "model_name") or _field(meta, "model") or _model_id_of(model)
            )
            hint, model_id = split_model_id(raw_model)
            if not model_id:
                return False
            provider = (
                infer_provider(model=model, model_id=model_id, response_metadata=meta)
                or hint
                or "unknown"
            )
            return bool(self.client.record_cost(
                agent_id=self.agent_id,
                provider=provider,
                model_id=model_id,
                input_tokens=usage["input"],
                output_tokens=usage["output"],
                input_cached_tokens=usage["cached"],
            ))
        except Exception as exc:  # never let cost tracking break the agent
            log.debug("cost tracking failed: %s", exc)
            return False

    def record_result(self, result: Any, model: Any = None) -> int:
        """Record every usage-bearing message in a model-call result.
        Returns the number of records posted. Never raises."""
        recorded = 0
        try:
            for message in iter_messages(result):
                if self.record_message(message, model=model):
                    recorded += 1
        except Exception as exc:
            log.debug("cost tracking failed: %s", exc)
        return recorded


def make_model_call_handler(tracker: CostTracker):
    """Build the ``(request, handler)`` callable used by ``wrap_model_call``.

    Factored out so it is unit testable without a full LangChain v1 install
    (mirrors ``_make_tool_call_handler``).
    """

    def _securevector_costs(request, handler):
        response = handler(request)
        tracker.record_result(response, model=getattr(request, "model", None))
        return response

    return _securevector_costs


def cost_tracking_middleware(
    base_url: Optional[str] = None,
    agent_id: Optional[str] = None,
    **kwargs,
):
    """Build a SecureVector ``wrap_model_call`` middleware that posts LLM
    token usage to the app's Cost Tracking after every model call.

    Pass it alongside :func:`secure_middleware`::

        middleware=[secure_middleware(mode="enforce"), cost_tracking_middleware()]

    Raises ``ImportError`` if LangChain v1's middleware API is unavailable.
    """
    try:
        from langchain.agents.middleware import wrap_model_call
    except Exception as exc:  # pragma: no cover - depends on langchain version
        raise ImportError(
            "cost_tracking_middleware requires LangChain v1 (langchain>=1.0) for "
            "langchain.agents.middleware.wrap_model_call. For older versions, "
            "SecureVectorCallbackHandler captures usage via on_llm_end."
        ) from exc

    cfg = Config.from_env(base_url=base_url, **kwargs)
    tracker = CostTracker(cfg, agent_id=agent_id)
    return wrap_model_call(make_model_call_handler(tracker))
