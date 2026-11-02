"""Starts the MCP endpoint on its own port, inside the web process."""

import logging
import threading

from werkzeug.serving import make_server

from spiderfoot.mcp.wsgi import McpWsgiApp
from spiderfoot.services import mcp_auth

log = logging.getLogger('spiderfoot.mcp')


def start_listener(app, host=None, port=None):
    """Serve the MCP endpoint in a daemon thread. Returns the server, or None when no port is configured.

    The port comes from SF_MCP_PORT and the address from SF_MCP_HOST (see spiderfoot.services.mcp_auth);
    with the port unset or 0 nothing is started. Whether clients are let in is decided per request by
    the settings saved on the Settings page.
    """
    host = host or mcp_auth.listen_host()
    port = mcp_auth.listen_port() if port is None else port
    if not port:
        return None
    try:
        server = make_server(host, port, McpWsgiApp(app), threaded=True)
    except OSError as e:
        log.error('MCP server could not listen on %s:%s: %s', host, port, e)
        return None
    thread = threading.Thread(target=server.serve_forever, name='mcp-server', daemon=True)
    thread.start()
    log.info('MCP server listening on %s:%s (enabled and authorised from the Settings page)', host, port)
    return server
