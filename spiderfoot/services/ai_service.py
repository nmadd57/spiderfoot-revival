"""Chat-completions client for SpiderFoot AI summarization.

By default this wraps the OpenRouter `/api/v1/chat/completions` endpoint with
the project-specific defaults documented in the AI summarization design
spec: streaming on, low temperature, throughput-sorted provider, automatic
failover via the `models` array, and stable attribution headers.

When a custom ``base_url`` is supplied (e.g. ``http://host:11434/v1`` for
Ollama, llama.cpp, vLLM, LM Studio, llama-swap), the client instead speaks
plain OpenAI-compatible ``POST {base_url}/chat/completions`` without any
OpenRouter-only request fields, and the API key is optional.

The client is intentionally narrow: it does not know about scans,
correlations, prompts, or the database. Higher-level orchestration
lives elsewhere in the AI service package.
"""

import ipaddress
import json
import logging
import re
import threading
from typing import Iterator, List, Mapping, Optional
from urllib.parse import urlparse, urlunparse

import requests

from spiderfoot.services import urlcheck


log = logging.getLogger(f"spiderfoot.{__name__}")

OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
OPENROUTER_MODELS_URL = "https://openrouter.ai/api/v1/models"
ATTRIBUTION_REFERER = "https://github.com/boredchilada/spiderfoot-revival"
ATTRIBUTION_TITLE = "SpiderFoot Revival"


class OpenRouterError(Exception):
    """Raised when OpenRouter returns a non-2xx response.

    The string form is a user-facing message — the blueprint emits it
    verbatim into the SSE error event.
    """


_STATUS_MESSAGES = {
    401: "Invalid OpenRouter API key — check Settings → AI Assistant.",
    402: "Out of OpenRouter credits — top up at openrouter.ai.",
    408: "Model took too long. Try regenerating, a smaller scan, or the other model.",
    413: "Scan too large for the model. Reduce events or try the other model.",
    422: "Request validation failed — please report this.",
    429: "Rate limited by OpenRouter. Wait a moment and try again.",
    500: "OpenRouter server error. Try again shortly.",
    502: "Upstream model is unavailable. Try the other model.",
    503: "OpenRouter service unavailable. Try again later.",
}


def _chat_completions_url(base_url: str) -> str:
    """Normalise a user-supplied base URL to a chat-completions endpoint."""
    url = base_url.strip().rstrip("/")
    if url.endswith("/chat/completions"):
        return url
    return url + "/chat/completions"


_CUSTOM_STATUS_MESSAGES = {
    401: "AI endpoint rejected the API key — check Settings → AI Assistant.",
    404: "AI endpoint or model not found — check the base URL and model name.",
    408: "Model took too long. Try regenerating or a smaller scan.",
    413: "Scan too large for the model. Reduce events or use a larger-context model.",
    422: "Request validation failed — check the model name.",
    429: "AI endpoint is rate limiting or busy. Try again shortly.",
    500: "AI endpoint server error. Try again shortly.",
    502: "AI endpoint upstream is unavailable.",
    503: "AI endpoint unavailable (model may still be loading). Try again shortly.",
}


OPENROUTER_MODELS = [
    {"id": "moonshotai/kimi-k2.6", "label": "Kimi K2.6"},
    {"id": "z-ai/glm-5.1", "label": "GLM 5.1"},
]


def _models_url(base_url: str) -> str:
    """The OpenAI-compatible model list for a base URL (OpenRouter when empty)."""
    url = (base_url or "").strip().rstrip("/")
    if not url:
        return "https://openrouter.ai/api/v1/models"
    for suffix in ("/chat/completions", "/completions"):
        if url.endswith(suffix):
            url = url[: -len(suffix)]
    return url + "/models"


def parse_models(payload) -> List[dict]:
    """Model ids from an OpenAI-style ``{"data": [{"id": ...}]}`` list.

    Also accepts the shapes llama.cpp/Ollama use (``{"models": [{"name"|"model"|"id": ...}]}``)
    and a bare list. Returns ``[{"id", "label"}]`` sorted by id, without duplicates.
    """
    items = []
    if isinstance(payload, dict):
        items = payload.get("data") or payload.get("models") or []
    elif isinstance(payload, list):
        items = payload
    seen, out = set(), []
    for it in items:
        mid = it if isinstance(it, str) else (it.get("id") or it.get("name") or it.get("model") or "") if isinstance(it, dict) else ""
        mid = str(mid).strip()
        if not mid or mid in seen:
            continue
        seen.add(mid)
        label = it.get("name") if isinstance(it, dict) and it.get("name") and it.get("name") != mid else mid
        out.append({"id": mid, "label": str(label)})
    return sorted(out, key=lambda m: m["id"].lower())


def test_connection(base_url: str, api_key: str, model: str = "", timeout: int = 20) -> dict:
    """Check an AI endpoint: list its models, then (if ``model`` is set) send a tiny chat request.

    Never raises. Returns {ok, message, models, modelCount, chat}; the API key is not echoed.
    """
    import time as _time

    custom = bool((base_url or "").strip())
    out = {"ok": False, "message": "", "models": [], "modelCount": 0, "chat": None}
    if custom:
        checked, problem = urlcheck.check_http_url(base_url)
        if problem:
            out["message"] = problem
            return out
        models_endpoint, chat_endpoint = _models_url(checked), _chat_completions_url(checked)
    else:
        models_endpoint, chat_endpoint = OPENROUTER_MODELS_URL, OPENROUTER_URL
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    if not custom:
        headers["HTTP-Referer"] = ATTRIBUTION_REFERER
        headers["X-Title"] = ATTRIBUTION_TITLE
    where = "AI endpoint" if custom else "OpenRouter"

    t0 = _time.time()
    try:
        resp = requests.get(models_endpoint, headers=headers, timeout=timeout)
    except requests.exceptions.RequestException as e:
        out["message"] = f"Could not reach the {where}: {type(e).__name__}. Check the base URL."
        return out
    out["modelsMs"] = int((_time.time() - t0) * 1000)
    if resp.status_code in (401, 403):
        out["message"] = f"The {where} rejected the API key (HTTP {resp.status_code})."
        return out
    if resp.status_code != 200:
        out["message"] = f"The {where} answered the model list with HTTP {resp.status_code}."
        return out
    try:
        models = parse_models(resp.json())
    except ValueError:
        out["message"] = f"The {where} did not return a JSON model list."
        return out
    out["models"], out["modelCount"] = models, len(models)
    out["ok"] = True
    out["message"] = f"Connected to the {where}: {len(models)} model{'s' if len(models) != 1 else ''} available."

    model = (model or "").strip()
    if model:
        known = any(m["id"] == model for m in models)
        t1 = _time.time()
        try:
            r = requests.post(chat_endpoint, headers=headers, timeout=max(timeout, 40), json={
                "model": model, "max_tokens": 8, "temperature": 0,
                "messages": [{"role": "user", "content": "Reply with the word OK."}]})
            ms = int((_time.time() - t1) * 1000)
            if r.status_code == 200:
                out["chat"] = {"ok": True, "model": model, "ms": ms, "known": known,
                               "message": f"Model {model} answered in {ms} ms."}
            else:
                msg = f"Model {model} returned HTTP {r.status_code}."
                if r.status_code in (404, 400, 422) and not known:
                    msg += " It is not in the model list; pick one from the list."
                out["chat"] = {"ok": False, "model": model, "ms": ms, "known": known, "message": msg}
        except requests.exceptions.RequestException as e:
            out["chat"] = {"ok": False, "model": model, "known": known,
                           "message": f"The chat request failed: {type(e).__name__}."}
    return out


def model_choices(config) -> List[dict]:
    """Models offered in the UI pickers.

    OpenRouter mode offers the curated list. With a custom base URL the model
    names are whatever the endpoint serves, so offer the configured default
    and fallback models as-is.
    """
    if not (config.get('_ai_base_url') or '').strip():
        return [dict(m) for m in OPENROUTER_MODELS]
    seen, out = set(), []
    for key in ('_ai_default_model', '_ai_fallback_model'):
        mid = (config.get(key) or '').strip()
        if mid and mid not in seen:
            seen.add(mid)
            out.append({"id": mid, "label": mid})
    return out


class OpenRouterClient:
    """OpenRouter client, or a generic OpenAI-compatible client if ``base_url`` is set."""

    def __init__(self, api_key: str = "", timeout: int = 60, base_url: str = ""):
        self._base_url = (base_url or "").strip()
        if not api_key and not self._base_url:
            raise ValueError("OpenRouter API key is required")
        self._api_key = api_key or ""
        self._timeout = timeout
        self._custom = bool(self._base_url)
        self._url = (_chat_completions_url(self._base_url)
                     if self._custom else OPENROUTER_URL)
        self._provider = "AI endpoint" if self._custom else "OpenRouter"

    def stream_chat(
        self,
        model: str,
        fallback: str,
        messages: List[Mapping],
        max_tokens: int,
        metadata: Mapping,
        session_id: str,
        temperature: float = 0.3,
        top_p: float = 0.9,
    ) -> Iterator[dict]:
        """Stream a chat completion from OpenRouter.

        Yields a sequence of dicts:
          {"type": "token", "content": "..."}    - one per content delta
          {"type": "done",
           "model_used": "...",
           "prompt_tokens": int|None,
           "completion_tokens": int|None,
           "cost_usd": float|None}               - exactly once, on [DONE]

        Raises OpenRouterError with a user-facing message on HTTP error or
        upstream stream error before any token chunk arrives.
        """
        headers = {"Content-Type": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
        if not self._custom:
            headers["HTTP-Referer"] = ATTRIBUTION_REFERER
            headers["X-Title"] = ATTRIBUTION_TITLE
        body = {
            "model": model,
            "models": [model, fallback] if fallback and fallback != model else [model],
            "messages": list(messages),
            "max_tokens": max_tokens,
            "temperature": temperature,
            "top_p": top_p,
            "stream": True,
            # Ask OpenRouter to include token/cost accounting in the final SSE
            # chunk. Without this, `usage` is often absent and cost_usd is
            # persisted as NULL while tokens are actually billed — the monthly
            # cost dashboard would under-report real spend.
            "usage": {"include": True},
            "provider": {
                "sort": "throughput",
                "allow_fallbacks": True,
            },
            "metadata": dict(metadata),
            "session_id": session_id,
        }

        if self._custom:
            # Plain OpenAI-compatible request: no OpenRouter-only fields
            # (models/usage/provider/metadata/session_id), which strict
            # servers may reject. No fallback list either.
            body = {
                "model": model,
                "messages": list(messages),
                "max_tokens": max_tokens,
                "temperature": temperature,
                "top_p": top_p,
                "stream": True,
                "stream_options": {"include_usage": True},
            }

        # Note: we never log `headers` or `body` — they contain the API key
        # and full payload. Log only the model and metadata identifiers.
        log.info("%s request: model=%s session=%s", self._provider, model, session_id)

        try:
            with requests.post(
                self._url,
                headers=headers,
                json=body,
                stream=True,
                timeout=self._timeout,
            ) as resp:
                if resp.status_code != 200:
                    if self._custom:
                        msg = _CUSTOM_STATUS_MESSAGES.get(
                            resp.status_code,
                            f"AI endpoint returned HTTP {resp.status_code}.",
                        )
                    else:
                        msg = _STATUS_MESSAGES.get(
                            resp.status_code,
                            f"OpenRouter returned HTTP {resp.status_code}.",
                        )
                    raise OpenRouterError(msg)

                yield from self._iter_sse(resp)
        except requests.Timeout:
            raise OpenRouterError(
                "Model took too long. Try regenerating, a smaller scan, "
                "or the other model."
            )
        except requests.RequestException as e:
            log.warning("%s network error: %s", self._provider, e)
            raise OpenRouterError(
                f"Network error contacting {self._provider}. "
                + ("Check the base URL and that the server is reachable."
                   if self._custom else "Check your connection.")
            )

    @staticmethod
    def _iter_sse(resp) -> Iterator[dict]:
        model_used: Optional[str] = None
        prompt_tokens: Optional[int] = None
        completion_tokens: Optional[int] = None
        cost_usd: Optional[float] = None

        for raw in resp.iter_lines(decode_unicode=False):
            if not raw:
                continue
            line = raw.decode("utf-8", errors="replace").strip()
            if not line.startswith("data:"):
                continue
            payload = line[len("data:"):].strip()
            if payload == "[DONE]":
                yield {
                    "type": "done",
                    "model_used": model_used,
                    "prompt_tokens": prompt_tokens,
                    "completion_tokens": completion_tokens,
                    "cost_usd": cost_usd,
                }
                return
            try:
                obj = json.loads(payload)
            except json.JSONDecodeError:
                continue

            if model_used is None and obj.get("model"):
                model_used = obj["model"]

            usage = obj.get("usage")
            if usage:
                prompt_tokens = usage.get("prompt_tokens", prompt_tokens)
                completion_tokens = usage.get("completion_tokens", completion_tokens)
                cost_usd = usage.get("cost", cost_usd)

            choices = obj.get("choices") or []
            if choices:
                delta = choices[0].get("delta") or {}
                content = delta.get("content")
                if content:
                    yield {"type": "token", "content": content}


# ----------------------------------------------------------------------------
# Event ranking and prompt budget management
# ----------------------------------------------------------------------------

# Tokens per character heuristic. Empirically OpenRouter's tokenizers run
# 3.3–3.7 chars/token on English+ASCII; we round to 3.5 and over-estimate
# slightly so we stay safely under the model's hard limits.
_CHARS_PER_TOKEN = 3.5

_HIGH_INTEREST_PREFIXES = (
    "VULNERABILITY_",
    "LEAKED_",
    "PASSWORD_",
)
_HIGH_INTEREST_KEYWORDS = (
    "_PASSWORD_",
    "_BREACH_",
    "_HIJACKABLE",
)


def _interest_score(event: dict) -> int:
    etype = event.get("type", "")
    if any(etype.startswith(p) for p in _HIGH_INTEREST_PREFIXES):
        base = 10000
    elif any(k in etype for k in _HIGH_INTEREST_KEYWORDS):
        base = 9000
    elif event.get("in_correlation"):
        base = 5000
    else:
        base = 0
    return base


def rank_events(events: list) -> list:
    """Return events sorted highest-interest-first, newer breaking ties.

    Interest tier is the primary key; recency (`generated`, epoch seconds) is
    only a tie-breaker within a tier. (Previously recency was *added* to the
    tier score, but epoch seconds (~1.7e9) dwarf the max tier (10000), so a
    boring-but-newer event outranked a critical-but-older one on any scan
    lasting more than a few seconds.)
    """
    return sorted(
        events,
        key=lambda e: (_interest_score(e), int(e.get("generated") or 0)),
        reverse=True,
    )


def truncate_event_data(data: str, limit: int = 512) -> str:
    """Truncate per-event data with a trailing ellipsis if over the limit."""
    if data is None:
        return ""
    if len(data) <= limit:
        return data
    return data[:limit] + "…"


def estimate_tokens(text: str) -> int:
    """Cheap token estimator (chars / 3.5). Over-estimates slightly."""
    if not text:
        return 0
    return int(len(text) / _CHARS_PER_TOKEN)


def fit_to_budget(rendered_events: list, ceiling_tokens: int) -> tuple:
    """Drop lowest-ranked events until total estimated tokens ≤ ceiling.

    Each item must have a ``_render`` key holding its rendered string.
    Input is assumed already ranked (highest-interest first).

    Returns (kept_events, dropped_count).
    """
    total = 0
    kept = []
    for ev in rendered_events:
        cost = estimate_tokens(ev["_render"])
        if total + cost > ceiling_tokens:
            break
        kept.append(ev)
        total += cost
    return kept, len(rendered_events) - len(kept)


# ----------------------------------------------------------------------------
# PII redaction (run on assembled prompt string when _ai_redact_pii=True)
# ----------------------------------------------------------------------------

_EMAIL_RE = re.compile(r"\b[\w.+\-]+@[\w.\-]+\.[A-Za-z]{2,}\b")
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# IPv6: rough match — colon-separated hex groups, with optional :: compression.
# We then validate via ipaddress to avoid mangling MAC addresses or version strings.
_IPV6_RE = re.compile(r"(?:[0-9A-Fa-f]{0,4}:){2,}[0-9A-Fa-f]{0,4}")
_URL_RE = re.compile(r"https?://[^\s\"'<>]+")


def _is_public_ipv4(ip_str: str) -> bool:
    try:
        ip = ipaddress.IPv4Address(ip_str)
    except ValueError:
        return False
    return not (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_multicast or ip.is_reserved or ip.is_unspecified)


def _is_public_ipv6(ip_str: str) -> bool:
    try:
        ip = ipaddress.IPv6Address(ip_str)
    except ValueError:
        return False
    # For IPv6, only truly private ranges are preserved: ULA (fc00::/7),
    # link-local, loopback, unspecified, and multicast. Everything else is redacted.
    return not (ip.is_loopback or ip.is_link_local or ip.is_unspecified
                or ip.is_multicast or ip in ipaddress.IPv6Network("fc00::/7"))


def _stable_token(prefix: str, key: str, registry: dict) -> str:
    if key not in registry:
        registry[key] = f"[{prefix}-{len(registry) + 1}]"
    return registry[key]


def _redact_url(match, ipv4_tokens, ipv6_tokens) -> str:
    raw = match.group(0)
    try:
        u = urlparse(raw)
    except ValueError:
        return raw
    netloc = u.hostname or ""
    if u.port:
        netloc = f"{netloc}:{u.port}"
    if u.hostname:
        if _is_public_ipv4(u.hostname):
            netloc = _stable_token("IP", u.hostname, ipv4_tokens)
            if u.port:
                netloc = f"{netloc}:{u.port}"
        elif _is_public_ipv6(u.hostname):
            netloc = _stable_token("IP6", u.hostname, ipv6_tokens)
            if u.port:
                netloc = f"{netloc}:{u.port}"
    rebuilt = urlunparse(u._replace(netloc=netloc))
    rebuilt = _EMAIL_RE.sub(
        lambda m: f"***@{m.group(0).split('@', 1)[1]}", rebuilt
    )
    return rebuilt


def redact_payload(text: str, target: str) -> tuple:
    """Apply PII redaction to ``text`` for OpenRouter submission.

    Returns (redacted_text, mapping_dict). ``mapping_dict`` is request-scoped
    and not persisted — the caller may discard it.
    """
    ipv4_tokens: dict = {}
    ipv6_tokens: dict = {}

    # 1. URLs first (decompose so userinfo + query strings get cleaned).
    text = _URL_RE.sub(
        lambda m: _redact_url(m, ipv4_tokens, ipv6_tokens), text
    )

    # 2. Emails (anywhere remaining).
    text = _EMAIL_RE.sub(
        lambda m: f"***@{m.group(0).split('@', 1)[1]}", text
    )

    # 3. Public IPv4 → stable tokens; private/reserved preserved.
    def _ipv4_sub(m):
        ip = m.group(0)
        if _is_public_ipv4(ip):
            return _stable_token("IP", ip, ipv4_tokens)
        return ip
    text = _IPV4_RE.sub(_ipv4_sub, text)

    # 4. Public IPv6 → stable tokens.
    def _ipv6_sub(m):
        ip = m.group(0)
        if _is_public_ipv6(ip):
            return _stable_token("IP6", ip, ipv6_tokens)
        return ip
    text = _IPV6_RE.sub(_ipv6_sub, text)

    # 5. Scan-target root replacement (subdomains preserved relative).
    if target:
        target = target.strip().lower()
        # Replace `host.target` first to keep relative form, then bare target.
        sub_pattern = re.compile(
            r"\b([\w\-]+(?:\.[\w\-]+)*)\." + re.escape(target) + r"\b",
            re.IGNORECASE,
        )
        text = sub_pattern.sub(r"\1.<TARGET>", text)
        text = re.compile(r"\b" + re.escape(target) + r"\b",
                          re.IGNORECASE).sub("<TARGET>", text)

    return text, {"ipv4": ipv4_tokens, "ipv6": ipv6_tokens}


# ----------------------------------------------------------------------------
# Prompt builders
# ----------------------------------------------------------------------------

SCAN_SYSTEM_PROMPT = (
    "You are a senior threat-intelligence analyst summarizing an OSINT scan "
    "from SpiderFoot. Produce a concise executive summary (≤400 words) in "
    "markdown with these sections:\n\n"
    "1. **Target Overview** — what was scanned and at what depth\n"
    "2. **Notable Findings** — bulleted list, each with severity (HIGH/MEDIUM/LOW)\n"
    "3. **Attack Surface** — exposed services, subdomains, infrastructure\n"
    "4. **Identities & Exposure** — emails, leaked credentials, social presence\n"
    "5. **Recommended Next Steps** — concrete, prioritized actions\n\n"
    "Cite specific hostnames, IPs, CVEs, or correlation rule names from the "
    "data. Do not invent findings not present in the data. Be direct and "
    "skip filler."
)

CORRELATION_SYSTEM_PROMPT = (
    "You are a senior threat-intelligence analyst. A SpiderFoot correlation "
    "rule has fired during a scan. Explain in ≤200 words, in markdown:\n\n"
    "1. **What this means** — what pattern triggered the rule and why it matters\n"
    "2. **Evidence** — the specific events that matched\n"
    "3. **Suggested response** — concrete next steps for the defender\n\n"
    "Be direct. Do not speculate beyond the matched evidence."
)


def _render_event_line(ev: dict) -> str:
    data = truncate_event_data(ev.get("data") or "", limit=512)
    return f"  [{ev.get('type')}] {data} ({ev.get('source_module')})"


def build_scan_prompt(
    scan: dict,
    type_counts: list,
    correlations: list,
    events: list,
    *,
    max_events: int = 200,
    ceiling_tokens: int = 80000,
    redact: bool = False,
):
    """Return (messages, truncation_note).

    ``scan``: dict with keys target, status, event_count, module_count.
    ``type_counts``: list of (TYPE, count) tuples (already top-30, sorted).
    ``correlations``: list of {title, severity, evidence}.
    ``events``: full event list (will be ranked + capped + budget-fitted).
    """
    ranked = rank_events(events)[:max_events]
    rendered = [{"_render": _render_event_line(ev), **ev} for ev in ranked]
    kept, dropped = fit_to_budget(rendered, ceiling_tokens=ceiling_tokens)

    parts = [
        f"TARGET: {scan.get('target')}",
        f"SCAN STATUS: {scan.get('status')}, "
        f"{scan.get('event_count')} events from {scan.get('module_count')} modules",
    ]
    if scan.get("excluded_unrelated"):
        parts.append(
            f"NOTE: {scan['excluded_unrelated']} further findings were judged to be about other people or "
            "organisations with a similar name and are left out; do not mention them as findings."
        )
    parts += [
        "",
        "EVENT TYPE COUNTS (top 30):",
    ]
    for etype, count in type_counts[:30]:
        parts.append(f"  {etype}: {count}")

    parts.append("")
    parts.append(f"CORRELATIONS ({len(correlations)} hits):")
    for c in correlations:
        parts.append(
            f"  - \"{c.get('title')}\" ({c.get('severity')}): {c.get('evidence')}"
        )

    parts.append("")
    parts.append(f"TOP EVENTS ({len(kept)}, ranked by interest score):")
    for ev in kept:
        parts.append(ev["_render"])

    user_content = "\n".join(parts)
    if redact:
        user_content, _ = redact_payload(user_content, target=scan.get("target") or "")

    truncation_note = (
        f"{dropped} events omitted to fit token budget" if dropped > 0 else None
    )
    return [
        {"role": "system", "content": SCAN_SYSTEM_PROMPT},
        {"role": "user", "content": user_content},
    ], truncation_note


def build_correlation_prompt(
    scan: dict, rule: dict, matched_events: list, *, redact: bool = False
):
    parts = [
        f"SCAN TARGET: {scan.get('target')}",
        f"CORRELATION RULE: {rule.get('id')}",
        f"RULE TITLE: {rule.get('title')}",
        f"RULE DESCRIPTION: {rule.get('description')}",
        f"SEVERITY: {rule.get('severity')}",
        f"RISK: {rule.get('risk')}",
        "",
        f"MATCHED EVENTS ({len(matched_events)}):",
    ]
    for ev in matched_events:
        parts.append(_render_event_line(ev))

    user_content = "\n".join(parts)
    if redact:
        user_content, _ = redact_payload(user_content, target=scan.get("target") or "")

    return [
        {"role": "system", "content": CORRELATION_SYSTEM_PROMPT},
        {"role": "user", "content": user_content},
    ], None


# ----------------------------------------------------------------------------
# Concurrency lock (process-local — multi-worker is documented as v2)
# ----------------------------------------------------------------------------

_LOCKS_GUARD = threading.Lock()
_HELD: set = set()


def acquire_lock(key: tuple) -> bool:
    """Try to acquire a per-key in-flight lock. Returns False if already held."""
    with _LOCKS_GUARD:
        if key in _HELD:
            return False
        _HELD.add(key)
        return True


def release_lock(key: tuple) -> None:
    with _LOCKS_GUARD:
        _HELD.discard(key)


# ----------------------------------------------------------------------------
# StreamRunner — drives the OpenRouter client to completion regardless of
# whether the HTTP client is still listening, so we always capture the final
# usage/cost figures and have a complete summary to persist.
# NOTE: draining the stream does NOT save money — OpenRouter bills for the
# tokens it generates whether or not we read them. Cost is bounded by
# `max_tokens`, not by reading to the end. (A client disconnect cannot cancel
# an in-flight completion here.)
# ----------------------------------------------------------------------------


class StreamRunner:
    def __init__(self, *, client, model, fallback, messages, max_tokens,
                 metadata, session_id):
        self._client = client
        self._kw = dict(
            model=model, fallback=fallback, messages=messages,
            max_tokens=max_tokens, metadata=metadata, session_id=session_id,
        )
        self.assembled = ""
        self.model_used: Optional[str] = None
        self.prompt_tokens: Optional[int] = None
        self.completion_tokens: Optional[int] = None
        self.cost_usd: Optional[float] = None
        self.status: str = "failed"
        self.error_message: Optional[str] = None

    def run(self):
        """Generator yielding events for the HTTP layer.

        Event shapes:
          {"type": "token",  "content": "..."}
          {"type": "done"}                          - on successful [DONE]
          {"type": "error",  "message": "..."}      - on upstream failure
        """
        try:
            for ev in self._client.stream_chat(**self._kw):
                if ev["type"] == "token":
                    self.assembled += ev["content"]
                    yield ev
                elif ev["type"] == "done":
                    self.model_used = ev.get("model_used")
                    self.prompt_tokens = ev.get("prompt_tokens")
                    self.completion_tokens = ev.get("completion_tokens")
                    self.cost_usd = ev.get("cost_usd")
                    self.status = "complete"
                    yield {"type": "done"}
                    return
            # Stream ended without [DONE].
            self.status = "partial" if self.assembled else "failed"
            self.error_message = "Stream ended unexpectedly."
            yield {"type": "error", "message": self.error_message}
        except OpenRouterError as e:
            self.error_message = str(e)
            self.status = "partial" if self.assembled else "failed"
            yield {"type": "error", "message": self.error_message}
        except Exception as e:  # noqa: BLE001 — last-resort safety net
            log.warning("StreamRunner unexpected error: %s", e)
            self.error_message = "Unexpected error during summary generation."
            self.status = "partial" if self.assembled else "failed"
            yield {"type": "error", "message": self.error_message}
