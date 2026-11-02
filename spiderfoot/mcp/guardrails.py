"""Rules the MCP server enforces on top of the operator's permissions.

* active modules: anything flagged ``invasive`` plus the tool modules that probe the target
* private targets: loopback, private-range, link-local and unspecified addresses (and names that
  resolve to them) stay off limits unless the operator allows them
"""

import ipaddress
import socket
import threading

from spiderfoot import SpiderFootHelpers

# Tool and scanner modules that send traffic to the target itself. Modules flagged ``invasive`` in
# their metadata are active as well; this set covers the ones that are not flagged.
ACTIVE_MODULES = frozenset({
    'sfp_tool_nmap', 'sfp_tool_nuclei', 'sfp_tool_bbot_scan', 'sfp_tool_bbot_vuln', 'sfp_tool_bbot_enum',
    'sfp_tool_nbtscan', 'sfp_tool_onesixtyone', 'sfp_tool_whatweb', 'sfp_tool_wafw00f', 'sfp_tool_testsslsh',
    'sfp_tool_cmseek', 'sfp_tool_snallygaster',
    'sfp_portscan_tcp', 'sfp_dnsbrute',
})

IP_TYPES = ('IP_ADDRESS', 'IPV6_ADDRESS')
NET_TYPES = ('NETBLOCK_OWNER', 'NETBLOCKV6_OWNER')
INTERNAL_SUFFIXES = ('.localhost', '.local', '.localdomain', '.internal', '.lan', '.intranet', '.corp', '.home.arpa', '.private')

RESOLVE_TIMEOUT = 3.0


def is_active_module(name: str, flags) -> bool:
    return name in ACTIVE_MODULES or 'invasive' in (flags or [])


def _address_kinds(ip) -> list:
    kinds = []
    if ip.is_loopback:
        kinds.append('loopback')
    if ip.is_link_local:
        kinds.append('link-local')
    if ip.is_unspecified:
        kinds.append('unspecified')
    if ip.is_private and not kinds:
        kinds.append('private')
    if not kinds and (ip.is_multicast or ip.is_reserved or not ip.is_global):
        kinds.append('reserved or non-public')
    return kinds


def address_kinds(text: str) -> list:
    """Why an IP address or netblock is not a public target (empty list when it is public)."""
    base = str(text).split('/')[0].strip().strip('[]')
    try:
        ip = ipaddress.ip_address(base)
    except ValueError:
        return []
    kinds = _address_kinds(ip)
    if not kinds and SpiderFootHelpers.isPrivateIP(base):
        kinds.append('private')
    if '/' in str(text):
        try:
            net = ipaddress.ip_network(str(text).strip(), strict=False)
            for edge in (net.network_address, net.broadcast_address):
                for kind in _address_kinds(edge):
                    if kind not in kinds:
                        kinds.append(kind)
        except ValueError:
            pass
    return kinds


def resolve_addresses(host: str) -> list:
    """Addresses a hostname resolves to (empty on failure or after RESOLVE_TIMEOUT seconds)."""
    found = []

    def work():
        try:
            for info in socket.getaddrinfo(host, None):
                found.append(info[4][0])
        except Exception:  # nosec B110 - an unresolvable name is simply not private
            pass

    thread = threading.Thread(target=work, daemon=True)
    thread.start()
    thread.join(RESOLVE_TIMEOUT)
    return list(found)


# Replaceable in tests so they never touch the network
resolver = resolve_addresses


def assess_target(target: str, target_type: str, resolve: bool = False) -> dict:
    """Is this a public target? Returns {'private': bool, 'kinds': [...], 'reason': str}.

    ``resolve`` also looks hostnames up and treats a name that points at a non-public address as private.
    """
    kinds = []
    reason = ''
    if target_type in IP_TYPES or target_type in NET_TYPES:
        kinds = address_kinds(target)
        if kinds:
            reason = f"{target} is a {'/'.join(kinds)} address"
    elif target_type == 'INTERNET_NAME':
        host = str(target).lower().rstrip('.')
        if host == 'localhost' or host.endswith(INTERNAL_SUFFIXES):
            kinds = ['internal hostname']
            reason = f'{target} is an internal hostname'
        elif resolve:
            for address in resolver(host):
                found = address_kinds(address)
                if found:
                    kinds = found
                    reason = f'{target} resolves to {address}, a {"/".join(found)} address'
                    break
    return {'private': bool(kinds), 'kinds': kinds, 'reason': reason}
