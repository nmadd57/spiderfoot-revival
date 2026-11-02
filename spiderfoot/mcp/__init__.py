"""Model Context Protocol server: lets an MCP client (an agent) inspect modules, build and run scans
and read results, within the limits the operator sets on the Settings page.

* ``protocol``    JSON-RPC 2.0 / MCP message handling
* ``tools``       the tool catalogue (inputs, outputs, guardrails)
* ``guardrails``  active-module and private-target rules
* ``wsgi``        the HTTP endpoint (``POST /mcp``, ``GET /health``), authentication, throttling
* ``server``      starts the endpoint on its own port in a background thread

Option names, the token format and the permission model live in ``spiderfoot.services.mcp_auth``.
"""
