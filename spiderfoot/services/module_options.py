"""Describe a module's user-editable options for the Settings -> Modules page.

Secrets (API keys, tokens, passwords) are never returned: a configured secret is
reported as the placeholder ``********`` so the UI can show "set" without the value.
``api/savesettings`` already ignores that placeholder, so an untouched field keeps
its stored value.
"""

SECRET_TERMS = ('api_key', 'apikey', 'api_id', 'accesstoken', 'access_token', 'secret', 'password', 'token',
                'auth_header', 'authorization', 'bearer')
MASK = '********'


def is_secret(opt: str) -> bool:
    low = opt.lower()
    return any(t in low for t in SECRET_TERMS)


def is_tool_path(mod_name: str, opt: str) -> bool:
    low = opt.lower()
    return mod_name.startswith('sfp_tool_') and (low.endswith('path') or low.endswith('exe'))


def _kind(default, secret: bool) -> str:
    if secret:
        return 'secret'
    if isinstance(default, bool):
        return 'bool'
    if isinstance(default, (int, float)):
        return 'number'
    if isinstance(default, list):
        return 'list'
    return 'text'


def _as_text(value) -> str:
    if isinstance(value, bool):
        return '1' if value else '0'
    if isinstance(value, (list, tuple)):
        return ','.join(str(v) for v in value)
    return '' if value is None else str(value)


def build_fields(mod_name: str, mod_cfg: dict, saved: dict) -> list:
    """Return the editable options of one module, credentials first.

    Each field: {opt, label, kind, value, group, required}. ``group`` is
    ``credentials``, ``tool`` (binary/path settings) or ``options``.
    """
    opts = mod_cfg.get('opts') or {}
    descs = mod_cfg.get('optdescs') or {}
    meta = mod_cfg.get('meta') or {}
    connection = list(meta.get('connectionOpts') or [])
    fields = []
    for opt, default in opts.items():
        if opt.startswith('_'):
            continue
        # connection options such as an auth header carry credentials too
        secret = is_secret(opt) or (opt in connection and 'auth' in opt.lower())
        raw = saved.get(f'{mod_name}:{opt}', default)
        if is_tool_path(mod_name, opt) and default and not str(raw or '').strip():
            raw = default  # an empty saved path means "use the default install location"
        if secret:
            value = MASK if str(raw or '').strip() else ''
            group = 'credentials'
        else:
            value = _as_text(raw)
            group = 'credentials' if opt in connection else ('tool' if is_tool_path(mod_name, opt) else 'options')
        fields.append({
            'opt': opt,
            'label': descs.get(opt, opt),
            'kind': _kind(default, secret),
            'value': value,
            'group': group,
            'required': secret or opt in connection,
        })
    order = {'credentials': 0, 'tool': 1, 'options': 2}
    fields.sort(key=lambda f: order[f['group']])
    return fields
