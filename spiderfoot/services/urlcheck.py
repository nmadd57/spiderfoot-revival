"""Validation of URLs that an administrator enters in Settings (AI endpoint, embeddings endpoint...).

These endpoints are deliberately arbitrary: a local LLM on the LAN or on localhost is the normal
case, so private and loopback addresses are allowed. What is refused is anything that is not a
plain http(s) URL, URLs with embedded credentials, and addresses that are never a legitimate
service: the cloud metadata range and other link-local addresses, unspecified and multicast addresses.
"""

import ipaddress
import socket
from urllib.parse import urlsplit, urlunsplit


def _blocked(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr.split('%', 1)[0])
    except ValueError:
        return True
    mapped = getattr(ip, 'ipv4_mapped', None)  # ::ffff:169.254.169.254 is the metadata address too
    if mapped is not None:
        ip = mapped
    return ip.is_link_local or ip.is_unspecified or ip.is_multicast


def check_http_url(url: str, resolve: bool = True):
    """Validate an endpoint URL. Returns ``(normalised_url, None)`` or ``(None, reason)``.

    The reason is a fixed, user-facing sentence. ``resolve`` also checks every address the host
    name resolves to (a name that cannot be resolved is left to fail when the request is made).
    """
    text = str(url or '').strip()
    if not text:
        return None, 'The URL is empty.'
    if '://' not in text:
        text = 'http://' + text
    parts = urlsplit(text)
    if parts.scheme not in ('http', 'https'):
        return None, 'Only http:// and https:// URLs are allowed.'
    if not parts.hostname:
        return None, 'The URL has no host name.'
    if parts.username or parts.password:
        return None, 'Put credentials in the key or header field, not in the URL.'
    try:
        port = parts.port
    except ValueError:
        return None, 'The URL has an invalid port.'

    host = parts.hostname
    candidates = [host]
    try:
        ipaddress.ip_address(host)
    except ValueError:
        candidates = []  # a name: only its resolved addresses can be judged
        if resolve:
            try:
                candidates = list({ai[4][0] for ai in socket.getaddrinfo(host, port or 80, proto=socket.IPPROTO_TCP)})
            except OSError:
                candidates = []
    if any(_blocked(addr) for addr in candidates):
        return None, 'That address is not allowed (link-local, metadata, unspecified or multicast).'
    return urlunsplit((parts.scheme, parts.netloc, parts.path, parts.query, '')), None
