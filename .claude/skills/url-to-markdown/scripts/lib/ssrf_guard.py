"""SSRF validation for outbound URL fetches.

Enforces a three-tier policy on target URLs:

  1. CLOUD METADATA endpoints (IPs and hostnames) — hard-blocked, no override.
     Cloud metadata services expose credentials and internal config. No legitimate
     "fetch an article" workflow targets them.

  2. PRIVATE / LOOPBACK / LINK-LOCAL / RESERVED — soft-blocked by default,
     overridable via allow_private=True. Protects against accidental fetches of
     localhost services, internal LAN, cloud instance-local addresses.

  3. GLOBAL (public) addresses — allowed.

Only http and https schemes are permitted. Non-http(s) schemes are refused before
DNS resolution.

Design references:
  Include Security "Mitigating SSRF in 2023"
  https://blog.includesecurity.com/2023/03/mitigating-ssrf-in-2023/

Known limitation: this validator does not defeat DNS rebinding attacks. The DNS
lookup performed here is advisory for policy; the subsequent HTTP fetch performs
its own resolution and could receive different addresses. For threat models that
include adversarial DNS, apply network-layer controls (egress proxy, container
isolation) in addition to this module. See ../references/security-model.md.
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

ALLOWED_SCHEMES = frozenset({"http", "https"})

# Cloud metadata IPs — well-known addresses hosting credential/config endpoints.
# Hard-blocked regardless of allow_private setting.
CLOUD_METADATA_IPS = frozenset({
    "169.254.169.254",   # AWS IMDSv1, GCP, Azure, DigitalOcean, Oracle Cloud
    "fd00:ec2::254",     # AWS IPv6 metadata
    "100.100.100.200",   # Alibaba Cloud
})

# Cloud metadata hostnames — some platforms expose metadata via DNS name
# rather than (or in addition to) a hardcoded IP. Blocked by name before
# DNS resolution to short-circuit any DNS trickery.
CLOUD_METADATA_HOSTS = frozenset({
    "metadata.google.internal",
    "metadata.goog",
    "metadata.azure.com",
})


class SSRFError(Exception):
    """Raised when a URL fails the SSRF policy check."""


def validate_url(url: str, allow_private: bool = False) -> None:
    """Validate a URL against the SSRF policy.

    Raises SSRFError on any policy violation. Returns None on success.

    Callers must invoke this on the initial URL *and* on every redirect
    target before following the redirect. A single validation at the start
    of a request chain is not sufficient — a public URL can 302 to a
    private one.
    """
    parsed = urlparse(url)

    if parsed.scheme not in ALLOWED_SCHEMES:
        raise SSRFError(
            f"Scheme {parsed.scheme!r} is not allowed "
            f"(only http and https are permitted)"
        )

    hostname = parsed.hostname
    if not hostname:
        raise SSRFError(f"URL has no hostname: {url!r}")

    # Normalize trailing dot (DNS-absolute form) before membership check —
    # a URL like http://metadata.google.internal./ has parsed.hostname
    # ending in a dot, which is functionally equivalent for DNS resolution
    # but would not match the literal strings in CLOUD_METADATA_HOSTS.
    if hostname.lower().rstrip(".") in CLOUD_METADATA_HOSTS:
        raise SSRFError(
            f"Cloud metadata hostname {hostname!r} is blocked unconditionally"
        )

    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    try:
        addrinfo = socket.getaddrinfo(
            hostname, port, proto=socket.IPPROTO_TCP
        )
    except socket.gaierror as exc:
        raise SSRFError(f"DNS resolution failed for {hostname!r}: {exc}") from exc

    if not addrinfo:
        raise SSRFError(f"DNS returned no addresses for {hostname!r}")

    # Validate every returned address. Some bypass techniques exploit
    # multi-homed hostnames where only the first address is checked; a
    # stricter "all must be safe" policy closes that hole.
    for family, _socktype, _proto, _canonname, sockaddr in addrinfo:
        ip_str = sockaddr[0]
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError as exc:
            raise SSRFError(
                f"Could not parse resolved address {ip_str!r} for {hostname!r}: {exc}"
            ) from exc

        # Tier 1: cloud metadata — always refused.
        if ip_str in CLOUD_METADATA_IPS:
            raise SSRFError(
                f"Cloud metadata IP {ip_str} (resolved from {hostname!r}) "
                f"is blocked unconditionally"
            )

        # Tier 2: private / loopback / link-local / reserved — refused unless
        # the caller explicitly opts in with allow_private.
        if not ip_obj.is_global:
            if not allow_private:
                raise SSRFError(
                    f"{hostname!r} resolves to non-public address {ip_str} "
                    f"({_describe(ip_obj)}). Use --allow-private to override "
                    f"if this is an intentional fetch of a local resource."
                )

    # Tier 3: all returned addresses are global. Fetch is permitted.


def _describe(ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
    """Human-readable category for an IP that failed the global check."""
    if ip_obj.is_loopback:
        return "loopback"
    if ip_obj.is_link_local:
        return "link-local"
    if ip_obj.is_private:
        return "RFC1918 private"
    if ip_obj.is_multicast:
        return "multicast"
    if ip_obj.is_reserved:
        return "reserved"
    if ip_obj.is_unspecified:
        return "unspecified (0.0.0.0)"
    return "non-global"
