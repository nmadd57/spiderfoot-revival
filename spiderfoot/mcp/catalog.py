"""The module catalogue as the MCP tools present it (needs a Flask application context).

Built from the same data the New Scan page uses, so "available" means exactly what the scan start
applies: modules the operator disabled and modules switched off automatically (no key, over quota,
tool missing, no instance URL, no web search backend) are listed as unavailable with the reason.
"""

from flask import current_app

from spiderfoot.mcp import guardrails

PRICING = ('free', 'free_key', 'paid', 'local')
_PRICING_ORDER = {p: i for i, p in enumerate(('local', 'free', 'free_key', 'paid'))}


def pricing_rank(pricing: str) -> int:
    return _PRICING_ORDER.get(pricing, 9)


def module_index() -> dict:
    """{module id: info} for every module that can be put in a scan."""
    from spiderfoot.blueprints.ui import _build_modules_data
    mods, _cats = _build_modules_data(include_disabled=True)
    raw = current_app.config['SF_CONFIG'].get('__modules__', {})
    index = {}
    for name, m in mods.items():
        r = raw.get(name) or {}
        meta = r.get('meta') or {}
        flags = list(meta.get('flags') or [])
        reason = ''
        if m['disabled']:
            reason = 'disabled by the operator'
        elif m['autoReason']:
            reason = f"auto-disabled: {m['autoReason']}"
        index[name] = {
            'id': name,
            'name': m['name'],
            'summary': m['summary'],
            'descr': r.get('descr', ''),
            'category': m['category'],
            'categories': list(meta.get('categories') or []),
            'pricing': m['pricing'],
            'flags': flags,
            'useCases': list(m['useCases']),
            'active': guardrails.is_active_module(name, flags),
            'tool': 'tool' in flags or name.startswith('sfp_tool_'),
            'requiresKey': m['requiresKey'],
            'keyConfigured': m['keyConfigured'],
            'broken': m['broken'],
            'available': not reason,
            'unavailableReason': reason,
            'produces': list(r.get('provides') or []),
            'consumes': list(r.get('consumes') or []),
            'privateIpOk': m['privateIpOk'],
        }
    return index


def brief(m: dict) -> dict:
    """The compact listing form of a module."""
    out = {
        'id': m['id'], 'name': m['name'], 'summary': m['summary'][:200], 'category': m['category'],
        'pricing': m['pricing'], 'flags': m['flags'], 'active': m['active'], 'tool': m['tool'],
        'requiresKey': m['requiresKey'], 'available': m['available'],
    }
    if m['requiresKey']:
        out['keyConfigured'] = m['keyConfigured']
    if m['broken']:
        out['broken'] = True
    if not m['available']:
        out['unavailableReason'] = m['unavailableReason']
    return out
