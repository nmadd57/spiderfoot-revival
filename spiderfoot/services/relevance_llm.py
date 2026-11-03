"""AI adjudication for the borderline candidates of a relevance assessment.

Sends compact JSON batches (id, type, text) with a short description of the target to the configured chat endpoint
(the AI assistant settings: OpenRouter, or any OpenAI-compatible server) and expects
``{"results": [{"id", "verdict", "confidence", "reason"}]}`` back. The reply is parsed defensively, ids that were
not asked about are ignored, the number of calls and tokens per scan is capped, and every failure leaves the
deterministic score in place. ``_ai_redact_pii`` is honoured.
"""

import json
import logging
import re
import typing

import requests

from spiderfoot.services import ai_service, urlcheck

log = logging.getLogger(__name__)

VERDICTS = ('same', 'different', 'unknown')
BATCH_SIZE = 10

SYSTEM_PROMPT = (
    "You decide whether search results are about one specific person or company. "
    "Reply with JSON only, no other text, in exactly this shape: "
    '{"results":[{"id":"1","verdict":"same","confidence":0.8,"reason":"short reason"}]}. '
    "verdict is one of same, different, unknown. "
    "Use same only when the text gives a concrete reason it is the target: the same middle name, place, employer, "
    "profession or identifier. A matching first and last name alone is unknown. "
    "A short form of the first name (Nick for Nicholas) is the same name. "
    "Use different when the text shows another first name, middle name, place, age or profession than the target's. "
    "confidence is 0 to 1. reason is at most 12 words. Answer every id once."
)


class AdjudicationError(Exception):
    """The chat endpoint could not be used. The message is safe to show."""


def build_messages(profile_text: str, items: typing.List[dict]) -> typing.List[dict]:
    """``items``: [{'id': '1', 'type': 'social media', 'text': '...'}]."""
    cand = json.dumps(items, ensure_ascii=False, separators=(',', ':'))
    user = (
        f"TARGET: {profile_text}\n"
        f"CANDIDATES (JSON): {cand}\n"
        'Example reply for two candidates: {"results":[{"id":"1","verdict":"different","confidence":0.9,'
        '"reason":"middle name Andrew, not Thomas"},{"id":"2","verdict":"unknown","confidence":0.3,"reason":"name only"}]}'
    )
    return [{'role': 'system', 'content': SYSTEM_PROMPT}, {'role': 'user', 'content': user}]


def _strip(text: str) -> str:
    text = re.sub(r"<think>.*?</think>", ' ', text or '', flags=re.S | re.I)
    text = re.sub(r"```(?:json)?", ' ', text)
    return text.strip()


def _objects(text: str) -> typing.Iterator[typing.Any]:
    """Every top-level JSON object or array that can be decoded from ``text``."""
    dec = json.JSONDecoder()
    i = 0
    while i < len(text):
        if text[i] in '{[':
            try:
                obj, end = dec.raw_decode(text, i)
                yield obj
                i = end
                continue
            except ValueError:
                pass
        i += 1


def parse_response(text: str, valid_ids: typing.Iterable[str]) -> typing.Dict[str, typing.Tuple[str, float, str]]:
    """{id: (verdict, confidence, reason)} for the ids that were asked about; garbage yields {}."""
    valid = {str(v) for v in valid_ids}
    out: typing.Dict[str, typing.Tuple[str, float, str]] = {}

    def take(item):
        if not isinstance(item, dict):
            return
        rid = item.get('id')
        if isinstance(rid, (int, float)) and not isinstance(rid, bool):
            rid = str(int(rid))
        rid = str(rid) if rid is not None else ''
        if rid not in valid or rid in out:
            return
        verdict = str(item.get('verdict', '')).strip().lower()
        if verdict not in VERDICTS:
            return
        try:
            conf = float(item.get('confidence', 0.5))
        except (TypeError, ValueError):
            conf = 0.5
        conf = max(0.0, min(1.0, conf if conf == conf else 0.5))
        reason = re.sub(r"[\x00-\x1f]+", ' ', str(item.get('reason', ''))).strip()[:140]
        out[rid] = (verdict, conf, reason)

    for obj in _objects(_strip(text)):
        if isinstance(obj, dict) and isinstance(obj.get('results'), list):
            for item in obj['results']:
                take(item)
        elif isinstance(obj, list):
            for item in obj:
                take(item)
        else:
            take(obj)
    return out


class Adjudicator:
    """Chat-endpoint client with per-scan caps on calls and tokens."""

    def __init__(self, base_url: str = '', api_key: str = '', model: str = '', timeout: int = 120, redact: bool = False,
                 max_calls: int = 8, max_tokens: int = 150000, batch_size: int = BATCH_SIZE):
        self.base_url = str(base_url or '').strip()
        self._key = str(api_key or '').strip()
        self.model = str(model or '').strip()
        self.timeout = timeout
        self.redact = redact
        self.max_calls = max(0, int(max_calls))
        self.max_tokens = max(0, int(max_tokens))
        self.batch_size = max(1, int(batch_size))
        self.calls = 0
        self.tokens = 0
        self.errors: typing.List[str] = []

    @classmethod
    def from_config(cls, cfg: dict) -> typing.Optional['Adjudicator']:
        """None unless the AI assistant is enabled and relevance may use it."""
        if not cfg.get('_ai_enabled') or cfg.get('_rel_use_ai') in (False, 0, '0', 'false', 'False'):
            return None
        base = str(cfg.get('_ai_base_url') or '').strip()
        key = str(cfg.get('_ai_openrouter_key') or '').strip()
        if not base and not key:
            return None
        model = str(cfg.get('_rel_ai_model') or cfg.get('_ai_default_model') or '').strip()
        return cls(base, key, model, redact=bool(cfg.get('_ai_redact_pii')),
                   max_calls=int(cfg.get('_rel_max_llm_calls', 8) or 0), max_tokens=int(cfg.get('_rel_max_llm_tokens', 150000) or 0))

    @property
    def budget_left(self) -> bool:
        return self.calls < self.max_calls and self.tokens < self.max_tokens

    def _url(self) -> str:
        if self.base_url:
            checked, problem = urlcheck.check_http_url(self.base_url)
            if problem:
                raise AdjudicationError(problem)
            return ai_service._chat_completions_url(checked)
        return ai_service.OPENROUTER_URL

    def _chat(self, messages: typing.List[dict]) -> typing.Tuple[str, int]:
        url = self._url()
        headers = {'Content-Type': 'application/json'}
        if self._key:
            headers['Authorization'] = 'Bearer ' + self._key
        body = {'model': self.model, 'messages': messages, 'temperature': 0, 'max_tokens': 900, 'stream': False}
        try:
            r = requests.post(url, headers=headers, json=body, timeout=self.timeout)
        except requests.exceptions.RequestException as e:
            raise AdjudicationError(f"Could not reach the AI endpoint ({type(e).__name__}).") from None
        if r.status_code != 200:
            raise AdjudicationError(f"The AI endpoint answered HTTP {r.status_code}.")
        try:
            data = r.json()
            content = data['choices'][0]['message']['content'] or ''
        except (ValueError, KeyError, IndexError, TypeError):
            raise AdjudicationError("The AI endpoint did not return a chat completion.") from None
        usage = data.get('usage') or {}
        used = int(usage.get('total_tokens') or 0) if isinstance(usage, dict) else 0
        if not used:
            used = ai_service.estimate_tokens(json.dumps(messages)) + ai_service.estimate_tokens(content)
        return content, used

    def judge(self, profile_text: str, items: typing.List[dict]) -> typing.Dict[str, typing.Tuple[str, float, str]]:
        """Verdicts for ``items``, in as many calls as the caps allow. Never raises."""
        verdicts: typing.Dict[str, typing.Tuple[str, float, str]] = {}
        for i in range(0, len(items), self.batch_size):
            if not self.budget_left:
                break
            batch = items[i:i + self.batch_size]
            messages = build_messages(profile_text, batch)
            if self.redact:
                for m in messages:
                    m['content'], _ = ai_service.redact_payload(m['content'], target='')
            try:
                content, used = self._chat(messages)
            except AdjudicationError as e:
                self.errors.append(str(e))
                self.calls += 1
                break          # an endpoint that fails once will fail again; keep the deterministic scores
            self.calls += 1
            self.tokens += used
            verdicts.update(parse_response(content, [b['id'] for b in batch]))
        return verdicts
