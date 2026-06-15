"""Cloudflare DNS integration for accel-ppp DATA connections (2c).

Public surface:
  * :data:`CLOUDFLARE_API_TOKEN_KEY` — the platform-settings key holding the
    (encrypted) API token. Add/rotate it from the panel Settings page.
  * :func:`is_configured` — True when a token is present (gate real API calls).
  * :func:`get_client` — a :class:`CloudflareDNSClient` built from the stored
    token, or ``None`` when unconfigured.

Real network calls are GATED behind a configured token: with no token,
:func:`get_client` returns ``None`` and the orchestration layer reports
``not_configured`` without touching the network — so a fresh panel install
never blocks on Cloudflare.
"""
from __future__ import annotations

from typing import Optional

from .client import CloudflareDNSClient, CfResult, DnsRecord, DEFAULT_API_BASE

#: Platform-settings key (see app/services/platform_settings.py KEYS).
CLOUDFLARE_API_TOKEN_KEY = "CLOUDFLARE_API_TOKEN"


def get_token() -> str:
    """Decrypted Cloudflare API token from platform settings ("" when unset)."""
    from .. import platform_settings as ps
    return ps.get_secret(CLOUDFLARE_API_TOKEN_KEY, default="")


def is_configured() -> bool:
    return bool(get_token().strip())


def get_client() -> Optional[CloudflareDNSClient]:
    """Build a client from the stored token, or ``None`` when unconfigured."""
    token = get_token().strip()
    if not token:
        return None
    return CloudflareDNSClient(token)


__all__ = [
    "CLOUDFLARE_API_TOKEN_KEY",
    "CloudflareDNSClient",
    "CfResult",
    "DnsRecord",
    "DEFAULT_API_BASE",
    "get_token",
    "is_configured",
    "get_client",
]
