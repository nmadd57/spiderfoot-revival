"""Test an OpenAI-compatible embeddings endpoint, and list its models.

Used by Settings -> Web Search. The endpoint is what ``sfp_searxng`` uses to rank phrase-search
results by similarity to the scan target.
"""

import time

import requests

from spiderfoot.services import ai_service, urlcheck


def normalise(url: str) -> str:
    url = str(url or '').strip().rstrip('/')
    if url and '://' not in url:
        url = 'http://' + url
    return url


def endpoint(url: str) -> str:
    url = normalise(url)
    return url if (not url or url.endswith('/embeddings')) else url + '/embeddings'


def models_url(url: str) -> str:
    url = normalise(url)
    if url.endswith('/embeddings'):
        url = url[:-len('/embeddings')]
    return url + '/models'


def test_connection(url: str, api_key: str = '', model: str = '', timeout: int = 30) -> dict:
    """Embed a short text and list the endpoint's models. Never raises; the key is not echoed."""
    out = {'ok': False, 'message': '', 'models': [], 'modelCount': 0, 'dimensions': None, 'ms': None}
    if not normalise(url):
        out['message'] = 'Enter the embeddings endpoint URL first.'
        return out
    url, problem = urlcheck.check_http_url(normalise(url))
    if problem:
        out['message'] = problem
        return out
    headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}
    if str(api_key or '').strip():
        headers['Authorization'] = 'Bearer ' + str(api_key).strip()

    # the model list is optional (many servers do not offer it), so a failure here is not an error
    try:
        r = requests.get(models_url(url), headers=headers, timeout=min(timeout, 15))
        if r.status_code == 200:
            out['models'] = ai_service.parse_models(r.json())
            out['modelCount'] = len(out['models'])
    except (requests.exceptions.RequestException, ValueError):
        pass

    body = {'input': ['SpiderFoot embeddings test']}
    if str(model or '').strip():
        body['model'] = str(model).strip()
    t0 = time.time()
    try:
        r = requests.post(endpoint(url), headers=headers, json=body, timeout=timeout)
    except requests.exceptions.RequestException as e:
        out['message'] = f"Could not reach {endpoint(url)}: {type(e).__name__}. Check the URL."
        return out
    out['ms'] = int((time.time() - t0) * 1000)
    if r.status_code in (401, 403):
        out['message'] = f"The embeddings endpoint rejected the API key (HTTP {r.status_code})."
        return out
    if r.status_code != 200:
        detail = ''
        if r.status_code in (400, 404, 422) and str(model or '').strip():
            known = any(m['id'] == str(model).strip() for m in out['models'])
            detail = ' The model is not in its model list; pick one from the list.' if out['models'] and not known else ' Check the model name.'
        out['message'] = f"The embeddings endpoint answered HTTP {r.status_code}.{detail}"
        return out
    try:
        vec = sorted(r.json()['data'], key=lambda d: d.get('index', 0))[0]['embedding']
        if not isinstance(vec, list) or not vec:
            raise ValueError('empty')
    except (ValueError, KeyError, IndexError, TypeError):
        out['message'] = 'The endpoint answered but did not return an embedding vector (is this an OpenAI-compatible /embeddings API?).'
        return out
    out['ok'] = True
    out['dimensions'] = len(vec)
    out['message'] = f"Embeddings work: {len(vec)} dimensions in {out['ms']} ms." + (
        f" {out['modelCount']} models available." if out['modelCount'] else '')
    return out
