"""Who may call which route.

Every route of the application is listed in :data:`POLICIES` and checked centrally, before the view
runs (see ``spiderfoot.app``). A route that is not listed is refused (administrators only), so a new
route cannot be exposed by forgetting it. ``test_route_policy`` fails when a route has no entry or when
a view that reads a scan id is not classified as a scan route.

Policy kinds:

``PUBLIC``    no sign-in needed (health check, sign-in pages)
``USER``      any signed-in user
``ADMIN``     administrators only
``scan(...)`` the user must hold a level on every scan id given in the request (``view``, ``edit`` or ``owner``)
``FILTERED``  any signed-in user; the view limits what it returns to the scans the user can see
"""

import typing
from dataclasses import dataclass

from flask import jsonify, make_response, render_template, request

from spiderfoot.services import access


@dataclass(frozen=True)
class Policy:
    kind: str  # public | user | admin | scan | filtered | dynamic
    level: str = ''
    arg: str = 'id'
    multi: bool = False   # the value is a comma separated list of scan ids
    where: str = 'values'  # 'values' (query string / form) or 'path' (a URL variable)
    via: str = ''          # 'correlation': the value is a correlation id, resolved to its scan
    decide: typing.Optional[typing.Callable] = None  # dynamic: returns the Policy to apply for this request
    note: str = ''

    def describe(self) -> str:
        if self.kind == 'scan':
            src = f'{self.arg}' + (' (list)' if self.multi else '') + (' via correlation' if self.via else '')
            return f'scan {self.level} [{src}]'
        return self.kind


PUBLIC = Policy('public')
USER = Policy('user')
ADMIN = Policy('admin')
FILTERED = Policy('filtered')


def scan(level: str, arg: str = 'id', multi: bool = False, where: str = 'values', via: str = '') -> Policy:
    return Policy('scan', level=level, arg=arg, multi=multi, where=where, via=via)


def _settings_section_policy() -> Policy:
    """Appearance and the agent (MCP) tokens are for every user; the rest of Settings is for administrators."""
    return USER if request.args.get('section', 'general') in ('appearance', 'mcp') else ADMIN


V, E, OWN = 'view', 'edit', 'owner'

POLICIES: typing.Dict[str, Policy] = {
    # -- pages
    'ui.dashboard': FILTERED,
    'ui.newscan': USER,
    'ui.scaninfo': scan(V),
    'ui.settings': USER,
    # -- scan data (JSON API; also served at the root for the command line client)
    'api.ping': PUBLIC,
    'api.query': ADMIN,
    'api.scanlist': FILTERED,
    'api.scanstatus': scan(V),
    'api.scansummary': scan(V),
    'api.scancorrelations': scan(V),
    'api.scaneventresults': scan(V),
    'api.scaneventresultsunique': scan(V),
    'api.scanopts': scan(V),
    'api.scanlog': scan(V),
    'api.scanerrors': scan(V),
    'api.scandelete': scan(OWN, multi=True),
    'api.stopscan': scan(E, multi=True),
    'api.startscan': USER,
    'api.rerunscan': scan(E),
    'api.rerunscanmulti': scan(E, arg='ids', multi=True),
    'api.search': FILTERED,
    'api.scanhistory': scan(V),
    'api.scanelementtypediscovery': scan(V),
    'api.resultsetfp': scan(E),
    'api.scanexportlogs': scan(V),
    'api.scancorrelationsexport': scan(V),
    'api.scaneventresultexport': scan(V),
    'api.scaneventresultexportmulti': scan(V, arg='ids', multi=True),
    'api.scansearchresultexport': FILTERED,
    'api.scanexportjsonmulti': scan(V, arg='ids', multi=True),
    'api.scanviz': scan(V),
    'api.scanvizmulti': scan(V, arg='ids', multi=True),
    # -- module catalogue (read for users, write for administrators) and presets
    'api.eventtypes': USER,
    'api.modules': USER,
    'api.correlationrules': USER,
    'api.presets_list': USER,
    'api.presets_get': USER,
    'api.presets_create': ADMIN,
    'api.presets_update': ADMIN,
    'api.presets_delete': ADMIN,
    'api.presets_clear_default': ADMIN,
    'api.presets_set_default': ADMIN,
    'api.modulestate': ADMIN,
    'api.module_settings_data': ADMIN,
    'api.module_test': ADMIN,
    # -- settings, keys, usage, maintenance
    'api.optsraw': ADMIN,
    'api.optsexport': ADMIN,
    'api.savesettingsraw': ADMIN,
    'api.savesettings': ADMIN,
    'api.vacuum': ADMIN,
    'api.usage_list': ADMIN,
    'api.usage_set_limits': ADMIN,
    'api.usage_clear_issue': ADMIN,
    'api.usage_reset_period': ADMIN,
    'api.usage_check': ADMIN,
    'api.ai_test': ADMIN,
    'api.searxng_test': ADMIN,
    'api.embeddings_test': ADMIN,
    # -- fragments (htmx)
    'frag.scan_table': FILTERED,
    'frag.results_tab': scan(V),
    'frag.log_lines': scan(V),
    'frag.events_fragment': scan(V),
    'frag.settings_section': Policy('dynamic', decide=_settings_section_policy),
    'ai.scan_summary': scan(V, arg='scan_id', where='path'),
    'ai.correlation_explain': scan(V, arg='correlation_id', where='path', via='correlation'),
    # -- sharing, users
    'access.scan_access_list': scan(V, arg='scan_id', where='path'),
    'access.scan_access_add': scan(OWN, arg='scan_id', where='path'),
    'access.scan_access_remove': scan(OWN, arg='scan_id', where='path'),
    'access.scan_owner_set': ADMIN,
    'access.user_picker': USER,
    'access.group_picker': USER,
    'access.access_settings_get': ADMIN,
    'access.access_settings_set': ADMIN,
    'access.access_test': ADMIN,
    'access.access_users': ADMIN,
    # -- relevance (reads need view, corrections and re-assessment need edit)
    'relevance.status': scan(V),
    'relevance.assess': scan(E),
    'relevance.mark': scan(E),
    'relevance.test': ADMIN,
    'frag.relevance_card': scan(V),
    # -- agent (MCP)
    'mcp_admin.get_settings': USER,
    'mcp_admin.set_settings': ADMIN,
    'mcp_admin.list_tokens': USER,
    'mcp_admin.create_token': USER,
    'mcp_admin.revoke_token': USER,
    # -- sign-in
    'auth.login': PUBLIC,
    'auth.callback': PUBLIC,
    'auth.logout': PUBLIC,
    'auth.me': USER,
}


def table_policy(endpoint: typing.Optional[str]) -> typing.Optional[Policy]:
    """The table entry of an endpoint (a 'dynamic' entry is returned as it is, undecided).

    The root-level copy of the API ('api_compat') follows the API's entry.
    """
    if not endpoint:
        return None
    if endpoint == 'static':
        return PUBLIC
    name = endpoint.replace('api_compat.', 'api.', 1) if endpoint.startswith('api_compat.') else endpoint
    return POLICIES.get(name)


def policy_for(endpoint: typing.Optional[str]) -> typing.Optional[Policy]:
    """The policy to apply to the current request for an endpoint (needs a request when the entry is dynamic)."""
    policy = table_policy(endpoint)
    if policy is not None and policy.kind == 'dynamic':
        policy = policy.decide()
    return policy


def requested_scan_ids(policy: Policy) -> typing.List[str]:
    """Every scan id the request names for this policy (non-empty ones; an absent id names no scan)."""
    if policy.where == 'path':
        raw = [str((request.view_args or {}).get(policy.arg, ''))]
    else:
        raw = request.values.getlist(policy.arg)
    ids = []
    for value in raw:
        parts = value.split(',') if policy.multi else [value]
        ids.extend(p for p in parts if p != '')
    return ids


def _resolve_correlations(ids: typing.List[str], dbh) -> typing.List[str]:
    scans = []
    for cid in ids:
        sid = dbh.scanOwnerOfCorrelation(cid)
        scans.append(sid if sid is not None else '\0missing')
    return scans


# --------------------------------------------------------------------------------------------
# refusals in the shape each kind of route expects

def refuse(status: int, message: str):
    endpoint = request.endpoint or ''
    if endpoint.startswith('ui.') or endpoint.startswith('auth.'):
        try:
            return make_response(render_template('pages/error.html', page_id='', status=status, message=message,
                                                 version=''), status)
        except Exception:  # nosec B110 - fall back to plain text
            return make_response(message + '\n', status)
    if endpoint.startswith('frag.') or endpoint.startswith('ai.'):
        resp = make_response(f'<p class="text-sm text-slate-400 p-8 text-center">{message}</p>', status)
        resp.headers['Cache-Control'] = 'no-store'
        return resp
    resp = jsonify({'error': {'http_status': str(status), 'message': message}})
    resp.status_code = status
    return resp


def authorize(user: access.User, settings, get_dbh) -> typing.Optional[object]:
    """None when the request may go ahead, otherwise the response that refuses it.

    ``get_dbh`` returns a database handle; it is only called when the decision needs the database.
    """
    policy = policy_for(request.endpoint)
    if policy is None:
        # No route matched (404) or an unclassified route: only administrators get through to the view
        return None if (request.endpoint is None or user.is_admin) else refuse(403, 'Not permitted.')
    if policy.kind in ('public', 'user', 'filtered'):
        return None
    if user.is_admin:
        return None
    if policy.kind == 'admin':
        return refuse(403, 'Administrator access is required.')
    if policy.kind == 'scan':
        dbh = get_dbh()
        ids = requested_scan_ids(policy)
        if policy.via == 'correlation':
            ids = _resolve_correlations(ids, dbh)
        for sid in ids:
            have = access.scan_level(user, sid, dbh, settings.unowned_visible)
            if not access.allows(have, policy.level):
                if access.denial(have) == 404:
                    return refuse(404, 'Scan not found.')
                return refuse(403, f'You need {policy.level} access to this scan.')
        return None
    return refuse(403, 'Not permitted.')
