"""Embedding similarity for relevance scoring.

Talks to an OpenAI-compatible ``/embeddings`` endpoint (the one configured under Settings > Web Search, or a
dedicated override under Settings > Relevance). Texts are sent in batches, vectors are cached by
(model, sha256 of the text) in ``tbl_embedding_cache`` so a rerun costs nothing, and the number of new texts per
run is bounded. The API key is only ever put in the ``Authorization`` header: it is not logged, not stored in a
result and not part of any error message.
"""

import hashlib
import logging
import math
import typing

import requests

from spiderfoot.services import embeddings, urlcheck

log = logging.getLogger(__name__)

BATCH = 64
DEFAULT_MAX_TEXTS = 1500
TEXT_LIMIT = 600


class EmbeddingError(Exception):
    """The endpoint could not be used. The message is safe to show (it never contains the key)."""


def cosine(a: typing.Sequence[float], b: typing.Sequence[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    return dot / (na * nb) if na and nb else 0.0


def text_hash(text: str) -> str:
    return hashlib.sha256(text.encode('utf-8', 'replace')).hexdigest()


def resolve_config(cfg: dict) -> dict:
    """The embeddings endpoint to use: the dedicated override under Settings > Relevance, else the Web Search one."""
    own_url = str(cfg.get('_rel_embeddings_url') or '').strip()
    opts = ((cfg.get('__modules__') or {}).get('sfp_searxng') or {}).get('opts') or {}
    if own_url:
        return {'url': own_url, 'model': str(cfg.get('_rel_embeddings_model') or opts.get('embeddings_model') or '').strip(),
                'key': str(cfg.get('_rel_embeddings_apikey') or '').strip(), 'source': 'relevance'}
    return {'url': str(opts.get('embeddings_url') or '').strip(), 'model': str(opts.get('embeddings_model') or '').strip(),
            'key': str(opts.get('embeddings_apikey') or '').strip(), 'source': 'web search'}


class EmbeddingClient:
    def __init__(self, url: str, model: str = '', api_key: str = '', timeout: int = 30, batch: int = BATCH):
        self.url = embeddings.normalise(url)
        self.model = str(model or '').strip()
        self._key = str(api_key or '').strip()
        self.timeout = timeout
        self.batch = max(1, int(batch))
        self.requests_made = 0
        self.failed = False

    @classmethod
    def from_config(cls, cfg: dict, timeout: int = 30) -> typing.Optional['EmbeddingClient']:
        if cfg.get('_rel_use_embeddings') in (False, 0, '0', 'false', 'False'):
            return None
        c = resolve_config(cfg)
        if not c['url']:
            return None
        return cls(c['url'], c['model'], c['key'], timeout)

    @property
    def cache_model(self) -> str:
        """Cache key: the vector depends on the endpoint's model, and a different endpoint may serve a different one."""
        return f"{self.model or 'default'}@{hashlib.sha256(self.url.encode()).hexdigest()[:8]}"

    def _post(self, texts: typing.List[str]) -> typing.List[list]:
        url, problem = urlcheck.check_http_url(self.url)
        if problem:
            raise EmbeddingError(problem)
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}
        if self._key:
            headers['Authorization'] = 'Bearer ' + self._key
        body = {'input': texts}
        if self.model:
            body['model'] = self.model
        try:
            r = requests.post(embeddings.endpoint(url), headers=headers, json=body, timeout=self.timeout)
        except requests.exceptions.RequestException as e:
            raise EmbeddingError(f"Could not reach the embeddings endpoint ({type(e).__name__}).") from None
        self.requests_made += 1
        if r.status_code in (401, 403):
            raise EmbeddingError(f"The embeddings endpoint rejected the API key (HTTP {r.status_code}).")
        if r.status_code != 200:
            raise EmbeddingError(f"The embeddings endpoint answered HTTP {r.status_code}.")
        try:
            rows = sorted(r.json()['data'], key=lambda d: d.get('index', 0))
            vecs = [d['embedding'] for d in rows]
        except (ValueError, KeyError, TypeError):
            raise EmbeddingError("The embeddings endpoint did not return embedding vectors.") from None
        if len(vecs) != len(texts) or not all(isinstance(v, list) and v for v in vecs):
            raise EmbeddingError("The embeddings endpoint returned the wrong number of vectors.")
        return vecs

    def embed(self, texts: typing.List[str]) -> typing.List[list]:
        out: typing.List[list] = []
        for i in range(0, len(texts), self.batch):
            out.extend(self._post(texts[i:i + self.batch]))
        return out


def embed_cached(client: EmbeddingClient, dbh, texts: typing.Iterable[str], max_new: int = DEFAULT_MAX_TEXTS) -> typing.Tuple[dict, dict]:
    """Vectors for ``texts``: ``({text: vector}, stats)``. Only up to ``max_new`` texts that are not cached are sent.

    A failing endpoint stops the run (``stats['error']``) and keeps what was already embedded; texts that
    could not be embedded are simply absent from the result.
    """
    uniq = list(dict.fromkeys(t[:TEXT_LIMIT] for t in texts if t))
    hashes = {t: text_hash(t) for t in uniq}
    cached = dbh.embeddingCacheGet(client.cache_model, hashes.values()) if dbh is not None else {}
    result = {t: cached[h] for t, h in hashes.items() if h in cached}
    missing = [t for t in uniq if t not in result]
    stats = {'texts': len(uniq), 'cached': len(result), 'sent': 0, 'skipped': 0, 'error': ''}
    if len(missing) > max_new:
        stats['skipped'] = len(missing) - max_new
        missing = missing[:max_new]
    for i in range(0, len(missing), client.batch):
        part = missing[i:i + client.batch]
        try:
            vecs = client._post(part)
        except EmbeddingError as e:
            stats['error'] = str(e)
            client.failed = True
            break
        stats['sent'] += len(part)
        fresh = {t: v for t, v in zip(part, vecs)}
        result.update(fresh)
        if dbh is not None:
            dbh.embeddingCachePut(client.cache_model, {hashes[t]: v for t, v in fresh.items()})
    return result, stats


def similarity_delta(sim: float, mid: float = 0.50, neg: float = 0.10, pos: float = 0.20) -> float:
    """Own-score adjustment for a cosine similarity: positive above ``mid`` (up to ``pos``), negative below (down to ``-neg``).

    Context that matches counts for more than context that does not: a page that says nothing about the target's
    place or job may simply not mention it.
    """
    return max(-neg, min(pos, sim - mid))
