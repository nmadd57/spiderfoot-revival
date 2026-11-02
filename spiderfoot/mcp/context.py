"""Shared plumbing for the MCP tools: database access, per-call permissions and secret scrubbing."""

from contextlib import contextmanager

from spiderfoot import SpiderFootDb
from spiderfoot.services import mcp_auth, module_options


class ToolError(Exception):
    """A problem the agent should see and can act on (shown as a tool result with isError true)."""


class McpContext:
    """The running web application as seen by the MCP server.

    Settings are read from the database on every call (never cached) so changes made on the
    Settings page apply immediately.
    """

    def __init__(self, app):
        self.app = app

    @property
    def config(self) -> dict:
        return self.app.config['SF_CONFIG']

    @property
    def logging_queue(self):
        return self.app.config.get('SF_LOGGING_QUEUE')

    @contextmanager
    def db(self):
        dbh = SpiderFootDb(self.config)
        try:
            yield dbh
        finally:
            try:
                dbh.conn.close()
            except Exception:  # nosec B110 - closing is best effort
                pass

    def saved(self) -> dict:
        """The settings saved in the database (raises on database failure)."""
        with self.db() as dbh:
            return dbh.configGet()


class CallContext:
    """What a tool handler gets: the application, the settings saved for this request, and the caller.

    ``perms`` are the operator's permissions at the start of the request ({'scan', 'delete', 'active',
    'private'} booleans, see spiderfoot.services.mcp_auth).
    """

    def __init__(self, ctx: McpContext, saved: dict, client: str = ''):
        self.ctx = ctx
        self.saved = saved or {}
        self.perms = mcp_auth.permissions(self.saved)
        self.client = client

    def require(self, permission: str, what: str):
        if not self.perms.get(permission):
            raise ToolError(f"Not permitted: the operator has not allowed MCP clients to {what}. "
                            f"This is a setting on the SpiderFoot Settings page (MCP).")


_SECRET_SUFFIXES = ('key', 'pwd', 'passwd', 'pass')


def _secret_option(opt: str) -> bool:
    low = opt.lower()
    return module_options.is_secret(low) or low.endswith(_SECRET_SUFFIXES)


def collect_secrets(config: dict, saved: dict) -> list:
    """Every configured secret value (API keys, passwords, tokens), longest first.

    Used as a last line of defence: the values are removed from any tool output even if a module
    wrote one into an event or a log line.
    """
    found = set()

    def take(name, value):
        opt = str(name).rsplit(':', 1)[-1]
        if isinstance(value, str) and len(value.strip()) >= 6 and value != module_options.MASK and _secret_option(opt):
            found.add(value.strip())

    for name, value in (saved or {}).items():
        take(name, value)
    for name, value in (config or {}).items():
        if not str(name).startswith('__'):
            take(name, value)
    for mod in ((config or {}).get('__modules__') or {}).values():
        for opt, value in ((mod or {}).get('opts') or {}).items():
            take(opt, value)
    return sorted(found, key=len, reverse=True)


def scrub(obj, secrets):
    """Return ``obj`` with every secret value replaced by ``[redacted]`` (recursing into lists and dicts)."""
    if not secrets:
        return obj
    if isinstance(obj, str):
        for secret in secrets:
            if secret in obj:
                obj = obj.replace(secret, '[redacted]')
        return obj
    if isinstance(obj, list):
        return [scrub(v, secrets) for v in obj]
    if isinstance(obj, dict):
        return {k: scrub(v, secrets) for k, v in obj.items()}
    return obj
