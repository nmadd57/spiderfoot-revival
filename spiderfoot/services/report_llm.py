"""Chat client for writing report sections.

One non-streaming chat-completions call per section against the configured endpoint (the ``_ai_*`` settings: OpenRouter
or any OpenAI-compatible server). It is written for small local models: short prompts, no tools, a generous timeout
with one retry on the same model and one attempt on the fallback model, a hard cap on calls and tokens per report, and
the endpoint's own usage figures when it reports them. ``_ai_redact_pii`` is honoured (and reversed in the answer).
The API key is never logged, returned or stored.
"""

import json
import logging
import re
import time
import typing

import requests

from spiderfoot.services import ai_service, urlcheck

log = logging.getLogger(__name__)

SYSTEM_PROMPT = (
    "You write one section of an OSINT investigation report from the DATA the user gives you. "
    "Rules: use only facts that are in DATA. Put the evidence id in square brackets right after each claim that rests on a "
    "finding, for example [E12]. Use only ids that appear in DATA and never invent one. Do not invent names, numbers, dates or "
    "sources. If DATA does not show something, leave it out. Say \"unclear\" or \"unconfirmed\" when DATA says so. "
    "Write plain markdown: short paragraphs or \"- \" bullets, no headings, no tables, no preamble, no closing remarks, "
    "do not repeat these rules."
)


class ReportLLMError(Exception):
    """The chat endpoint could not be used. The message is safe to show (it never contains the key)."""


def strip_reasoning(text: str) -> str:
    text = re.sub(r"<think>.*?</think>", ' ', text or '', flags=re.S | re.I)
    text = re.sub(r"^\s*```(?:markdown|md)?\s*\n|\n```\s*$", '', text.strip())
    return text.strip()


class ReportLLM:
    """The chat endpoint as the report writer uses it. ``calls`` and ``tokens`` are per report."""

    def __init__(self, base_url: str = '', api_key: str = '', model: str = '', fallback: str = '', timeout: int = 150,
                 redact: bool = False, max_calls: int = 24, max_tokens: int = 400000, max_output: int = 1600, retry_wait: float = 2.0):
        self.base_url = str(base_url or '').strip()
        self._key = str(api_key or '').strip()
        self.model = str(model or '').strip()
        self.fallback = str(fallback or '').strip()
        self.timeout = max(5, int(timeout))
        self.redact = bool(redact)
        self.max_calls = max(0, int(max_calls))
        self.max_tokens = max(0, int(max_tokens))
        self.max_output = int(max_output)
        self.retry_wait = retry_wait
        self.calls = 0
        self.tokens = 0
        self.prompt_tokens = 0
        self.completion_tokens = 0
        self.cost = 0.0
        self.models_used: typing.List[str] = []
        self.errors: typing.List[str] = []
        self.failures_in_a_row = 0

    # ------------------------------------------------------------------ setup

    @classmethod
    def from_config(cls, cfg: dict, model: str = '') -> typing.Optional['ReportLLM']:
        """None unless the AI assistant is enabled and an endpoint (or an OpenRouter key) is configured."""
        if not cfg.get('_ai_enabled') or cfg.get('_ai_enabled') in ('0', 'false', 'False'):
            return None
        base = str(cfg.get('_ai_base_url') or '').strip()
        key = str(cfg.get('_ai_openrouter_key') or '').strip()
        if not base and not key:
            return None
        model = (model or str(cfg.get('_report_model') or '') or str(cfg.get('_ai_default_model') or '')).strip()
        if not model:
            return None

        def num(k, d):
            try:
                return int(str(cfg.get(k, d)).strip())
            except ValueError:
                return d
        return cls(base, key, model, str(cfg.get('_ai_fallback_model') or ''), timeout=num('_report_call_timeout', 150),
                   redact=cfg.get('_ai_redact_pii') not in (False, 0, '0', 'false', 'False', None, ''),
                   max_calls=num('_report_max_calls', 24), max_tokens=num('_report_max_tokens', 400000))

    @property
    def budget_left(self) -> bool:
        return self.calls < self.max_calls and self.tokens < self.max_tokens

    @property
    def dead(self) -> bool:
        """The endpoint failed twice in a row: stop asking and finish the report without it."""
        return self.failures_in_a_row >= 2

    def _url(self) -> str:
        if self.base_url:
            checked, problem = urlcheck.check_http_url(self.base_url)
            if problem:
                raise ReportLLMError(problem)
            return ai_service._chat_completions_url(checked)
        return ai_service.OPENROUTER_URL

    # ------------------------------------------------------------------ one request

    def _post(self, model: str, messages: typing.List[dict], max_tokens: int) -> typing.Tuple[str, dict, str]:
        url = self._url()
        headers = {'Content-Type': 'application/json'}
        if self._key:
            headers['Authorization'] = 'Bearer ' + self._key
        if not self.base_url:
            headers['HTTP-Referer'] = ai_service.ATTRIBUTION_REFERER
            headers['X-Title'] = ai_service.ATTRIBUTION_TITLE
        body = {'model': model, 'messages': messages, 'temperature': 0.2, 'top_p': 0.9, 'max_tokens': max_tokens, 'stream': False}
        try:
            r = requests.post(url, headers=headers, json=body, timeout=self.timeout)
        except requests.exceptions.Timeout:
            raise ReportLLMError(f"The AI endpoint did not answer within {self.timeout} s.") from None
        except requests.exceptions.RequestException as e:
            raise ReportLLMError(f"Could not reach the AI endpoint ({type(e).__name__}).") from None
        if r.status_code != 200:
            table = ai_service._CUSTOM_STATUS_MESSAGES if self.base_url else ai_service._STATUS_MESSAGES
            raise ReportLLMError(table.get(r.status_code, f"The AI endpoint answered HTTP {r.status_code}."))
        try:
            data = r.json()
            choice = data['choices'][0]
            content = (choice.get('message') or {}).get('content') or ''
        except (ValueError, KeyError, IndexError, TypeError, AttributeError):
            raise ReportLLMError("The AI endpoint did not return a chat completion.") from None
        usage = data.get('usage') if isinstance(data.get('usage'), dict) else {}
        return content, usage, str(choice.get('finish_reason') or '')

    def _account(self, usage: dict, messages: typing.List[dict], content: str, model_used: str) -> None:
        p, c = int(usage.get('prompt_tokens') or 0), int(usage.get('completion_tokens') or 0)
        total = int(usage.get('total_tokens') or 0) or (p + c)
        if not total:
            p = ai_service.estimate_tokens(json.dumps(messages))
            c = ai_service.estimate_tokens(content)
            total = p + c
        self.prompt_tokens += p
        self.completion_tokens += c
        self.tokens += total
        try:
            self.cost += float(usage.get('cost') or 0)
        except (TypeError, ValueError):
            pass
        if model_used and model_used not in self.models_used:
            self.models_used.append(model_used)

    # ------------------------------------------------------------------ the call a section makes

    def complete(self, user: str, *, system: str = SYSTEM_PROMPT, target: str = '', max_tokens: typing.Optional[int] = None) -> str:
        """The model's answer to one section prompt. Retries once on the same model, then tries the fallback model.

        Raises ReportLLMError when no attempt produced text. Every attempt counts as a call.
        """
        messages = [{'role': 'system', 'content': system}, {'role': 'user', 'content': user}]
        restore: typing.Dict[str, str] = {}
        if self.redact:
            red, mapping = ai_service.redact_payload(user, target=target)
            messages[1]['content'] = red
            restore = {v: k for k, v in {**mapping.get('ipv4', {}), **mapping.get('ipv6', {})}.items()}
            if target:
                restore['<TARGET>'] = target
        attempts = [self.model, self.model]
        if self.fallback and self.fallback != self.model:
            attempts.append(self.fallback)
        out_tokens = max_tokens or self.max_output
        last = 'The AI endpoint produced no text.'
        for i, model in enumerate(attempts):
            if not self.budget_left:
                raise ReportLLMError("The call or token limit for this report was reached.")
            if i:
                time.sleep(self.retry_wait)
            self.calls += 1
            try:
                content, usage, finish = self._post(model, messages, out_tokens)
            except ReportLLMError as e:
                last = str(e)
                self.errors.append(last)
                if 'rejected the API key' in last or 'not found' in last:
                    break        # retrying cannot help
                continue
            self._account(usage, messages, content, model)
            text = strip_reasoning(content)
            if not text:
                last = "The model produced no answer text" + (" (it ran out of tokens while thinking)." if finish == 'length' else ".")
                self.errors.append(last)
                if finish == 'length':
                    out_tokens = min(out_tokens * 2, 6000)
                continue
            self.failures_in_a_row = 0
            for token, real in restore.items():
                text = text.replace(token, real)
            return text
        self.failures_in_a_row += 1
        raise ReportLLMError(last)
