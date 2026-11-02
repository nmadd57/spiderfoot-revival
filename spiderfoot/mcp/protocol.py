"""JSON-RPC 2.0 message handling for the Model Context Protocol (tools only).

Transport independent: ``handle_payload`` takes a parsed JSON value (one message or a batch) and
returns what to send back, or None when nothing is to be sent (notifications).
"""

import logging

from spiderfoot.__version__ import __version__
from spiderfoot.mcp import tools

log = logging.getLogger('spiderfoot.mcp')

SUPPORTED_VERSIONS = ('2025-06-18', '2025-03-26', '2024-11-05')

PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603

INSTRUCTIONS = (
    "SpiderFoot is an OSINT scanner: modules query public sources about a target and store what they find as events. "
    "Work like this. 1) validate_target on what you were asked to investigate; it names the target type and warns about "
    "private addresses. 2) Choose modules: list_presets for ready-made selections (Passive is designed to avoid direct contact with the target), "
    "or suggest_modules / list_modules to pick your own; get_module explains one module. 3) create_scan with exactly one "
    "of modules, preset or use_case; the result lists any modules that were left out and why. 4) Poll get_scan every "
    "10-30 seconds until done is true (scans can take minutes to an hour), looking at get_scan_log if results look thin. "
    "5) Read results: get_scan_summary for what was found by event type, then get_scan_events with event_type, module or "
    "query filters and paging, and get_scan_correlations for higher-level findings. "
    "Limits: active modules (port scans, vulnerability and fingerprinting tools) and private, loopback or link-local "
    "targets need the operator's permission, active modules also need confirm_active=true; deleting scans needs "
    "permission and confirm=true. Do not scan targets you have no authority to investigate. Tool failures are returned "
    "as results with isError true and a message you can act on. API keys and settings are not available through this server."
)


def rpc_error(rid, code, message):
    return {'jsonrpc': '2.0', 'id': rid, 'error': {'code': code, 'message': message}}


def _ok(rid, result):
    return {'jsonrpc': '2.0', 'id': rid, 'result': result}


def _initialize(params):
    if not isinstance(params, dict) or not isinstance(params.get('protocolVersion'), str):
        raise ValueError('initialize needs params.protocolVersion')
    asked = params['protocolVersion']
    return {
        'protocolVersion': asked if asked in SUPPORTED_VERSIONS else SUPPORTED_VERSIONS[0],
        'capabilities': {'tools': {'listChanged': False}},
        'serverInfo': {'name': 'spiderfoot', 'version': __version__},
        'instructions': INSTRUCTIONS,
    }


def handle_message(msg, cc):
    """Handle one JSON-RPC message; returns the response dict or None (notification / client response)."""
    if not isinstance(msg, dict) or msg.get('jsonrpc') != '2.0':
        return rpc_error(None, INVALID_REQUEST, 'Invalid request')
    if 'method' not in msg:
        # a response from the client to something we never sent: nothing to do
        return None if ('result' in msg or 'error' in msg) else rpc_error(None, INVALID_REQUEST, 'Invalid request')
    method = msg['method']
    is_notification = 'id' not in msg
    rid = msg.get('id')
    params = msg.get('params')
    if not isinstance(method, str) or (not is_notification and (isinstance(rid, bool) or not isinstance(rid, (str, int)))) \
            or (params is not None and not isinstance(params, (dict, list))):
        return rpc_error(rid if isinstance(rid, (str, int)) and not isinstance(rid, bool) else None, INVALID_REQUEST, 'Invalid request')
    if is_notification:
        return None
    try:
        if method == 'initialize':
            return _ok(rid, _initialize(params))
        if method == 'ping':
            return _ok(rid, {})
        if method == 'tools/list':
            return _ok(rid, {'tools': tools.definitions()})
        if method == 'tools/call':
            if not isinstance(params, dict) or not isinstance(params.get('name'), str):
                return rpc_error(rid, INVALID_PARAMS, 'tools/call needs params.name')
            if params['name'] not in tools.TOOLS:
                return rpc_error(rid, INVALID_PARAMS, f"Unknown tool: {params['name'][:80]}")
            return _ok(rid, tools.call_tool(cc, params['name'], params.get('arguments')))
        return rpc_error(rid, METHOD_NOT_FOUND, 'Method not found')
    except ValueError as e:
        return rpc_error(rid, INVALID_PARAMS, str(e))
    except Exception:
        log.exception('mcp internal error handling %s', method[:60])
        return rpc_error(rid, INTERNAL_ERROR, 'Internal error')


def handle_payload(payload, cc):
    """Handle a parsed request body. Returns (status, body); body None means no content (HTTP 202)."""
    if isinstance(payload, list):
        if not payload:
            return 400, rpc_error(None, INVALID_REQUEST, 'Invalid request')
        responses = [r for r in (handle_message(m, cc) for m in payload) if r is not None]
        return (200, responses) if responses else (202, None)
    response = handle_message(payload, cc)
    if response is None:
        return 202, None
    if 'error' in response and response['id'] is None:
        return 400, response
    return 200, response
