"""Cloudflare DNS client — minimal A-record management for DATA connections.

Scope (deliberately tiny — see docs/design/ACCEL_PPP_DATA_CONNECTIONS.md §0):
the panel points ``clientN.<zone>`` at the customer's RADIUS VPS as a
**DNS-only A record** so the VPS's own certbot (HTTP-01) can issue the SSTP
cert. We never touch certs here and never proxy (orange-cloud off): SSTP/443
must reach the VPS directly, and HTTP-01 needs port 80 to resolve to the VPS.

All network I/O goes through ``cloudflare._http`` (the single seam tests stub).
The client parses Cloudflare's v4 success-envelope and returns a uniform
:class:`CfResult` — it never raises on an API error, so callers (request
handlers, the orchestration service) keep serving.

Usage::

    client = CloudflareDNSClient(token)
    res = client.upsert_a_record("hoberadius.com", "client5.hoberadius.com", "1.2.3.4")
    if res.ok:
        save(res.record.id)
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Optional
from urllib.parse import quote

from . import _http

log = logging.getLogger("cloudflare.client")

#: Cloudflare API v4 root. Overridable per-client for tests / alternate envs.
DEFAULT_API_BASE = "https://api.cloudflare.com/client/v4"

#: DNS-only A records for DATA VPS endpoints. ``proxied`` MUST stay False:
#: SSTP rides TLS on 443 straight to the VPS and certbot HTTP-01 needs the
#: name to resolve to the VPS, not to Cloudflare's edge.
_PROXIED = False
#: Short TTL so an IP change (VPS migration) propagates fast. 120s = 2 min.
_TTL = 120


@dataclass(frozen=True)
class DnsRecord:
    id: str
    name: str
    type: str
    content: str
    proxied: bool = False
    ttl: int = _TTL

    @classmethod
    def from_api(cls, d: dict[str, Any]) -> "DnsRecord":
        return cls(
            id=str(d.get("id", "")),
            name=str(d.get("name", "")),
            type=str(d.get("type", "")),
            content=str(d.get("content", "")),
            proxied=bool(d.get("proxied", False)),
            ttl=int(d.get("ttl", _TTL) or _TTL),
        )


@dataclass(frozen=True)
class CfResult:
    """Uniform return for every client call. ``ok`` reflects the Cloudflare
    success envelope, not just the HTTP status."""
    ok: bool
    status: int = 0
    error: str = ""
    zone_id: str = ""
    record: Optional[DnsRecord] = None
    raw: Any = None


class CloudflareDNSClient:
    def __init__(self, token: str, *, api_base: str = DEFAULT_API_BASE,
                 timeout: float = 15.0) -> None:
        self._token = (token or "").strip()
        self._base = api_base.rstrip("/")
        self._timeout = timeout

    # ── internals ──────────────────────────────────────────────────────
    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._token}"}

    @staticmethod
    def _envelope(res: _http.HttpResult) -> tuple[bool, Any, str]:
        """Unwrap Cloudflare's ``{success, errors, result}`` envelope.

        Returns ``(ok, result_payload, error_message)``. A transport failure
        (``res.error``) or a ``success: false`` body both come back ``ok=False``
        with a human-ish error string built from the envelope's errors[].
        """
        if res.error and not isinstance(res.body, dict):
            return False, None, res.error
        body = res.body if isinstance(res.body, dict) else {}
        if body.get("success") is True:
            return True, body.get("result"), ""
        errs = body.get("errors") or []
        if isinstance(errs, list) and errs:
            parts = []
            for e in errs:
                if isinstance(e, dict):
                    parts.append(f"{e.get('code', '')}: {e.get('message', '')}".strip(": "))
                else:
                    parts.append(str(e))
            msg = "; ".join(p for p in parts if p)
        else:
            msg = res.error or f"HTTP {res.status}"
        return False, body.get("result"), msg or f"HTTP {res.status}"

    # ── zone + record primitives ───────────────────────────────────────
    def find_zone_id(self, zone_name: str) -> CfResult:
        """Resolve a zone name (``hoberadius.com``) to its Cloudflare zone id."""
        url = f"{self._base}/zones?name={quote(zone_name)}"
        res = _http.get_json(url, headers=self._headers(), timeout=self._timeout)
        ok, result, err = self._envelope(res)
        if not ok:
            return CfResult(ok=False, status=res.status, error=err, raw=res.body)
        zones = result or []
        if not zones:
            return CfResult(ok=False, status=res.status,
                            error=f"zone not found: {zone_name}", raw=res.body)
        return CfResult(ok=True, status=res.status, zone_id=str(zones[0].get("id", "")),
                        raw=res.body)

    def find_a_record(self, zone_id: str, fqdn: str) -> CfResult:
        """Find the A record for ``fqdn`` in ``zone_id``.

        ``ok=True`` with ``record=None`` means "looked up fine, none exists" —
        distinct from ``ok=False`` (the lookup itself failed)."""
        url = (f"{self._base}/zones/{quote(zone_id)}/dns_records"
               f"?type=A&name={quote(fqdn)}")
        res = _http.get_json(url, headers=self._headers(), timeout=self._timeout)
        ok, result, err = self._envelope(res)
        if not ok:
            return CfResult(ok=False, status=res.status, error=err, zone_id=zone_id, raw=res.body)
        records = result or []
        record = DnsRecord.from_api(records[0]) if records else None
        return CfResult(ok=True, status=res.status, zone_id=zone_id, record=record, raw=res.body)

    def create_a_record(self, zone_id: str, fqdn: str, ip: str, *,
                         proxied: bool = _PROXIED, ttl: int = _TTL) -> CfResult:
        url = f"{self._base}/zones/{quote(zone_id)}/dns_records"
        payload = {"type": "A", "name": fqdn, "content": ip, "ttl": ttl, "proxied": proxied}
        res = _http.post_json(url, payload=payload, headers=self._headers(), timeout=self._timeout)
        ok, result, err = self._envelope(res)
        if not ok:
            return CfResult(ok=False, status=res.status, error=err, zone_id=zone_id, raw=res.body)
        return CfResult(ok=True, status=res.status, zone_id=zone_id,
                        record=DnsRecord.from_api(result or {}), raw=res.body)

    def update_a_record(self, zone_id: str, record_id: str, fqdn: str, ip: str, *,
                        proxied: bool = _PROXIED, ttl: int = _TTL) -> CfResult:
        url = f"{self._base}/zones/{quote(zone_id)}/dns_records/{quote(record_id)}"
        payload = {"type": "A", "name": fqdn, "content": ip, "ttl": ttl, "proxied": proxied}
        res = _http.put_json(url, payload=payload, headers=self._headers(), timeout=self._timeout)
        ok, result, err = self._envelope(res)
        if not ok:
            return CfResult(ok=False, status=res.status, error=err, zone_id=zone_id, raw=res.body)
        return CfResult(ok=True, status=res.status, zone_id=zone_id,
                        record=DnsRecord.from_api(result or {}), raw=res.body)

    def delete_record(self, zone_id: str, record_id: str) -> CfResult:
        url = f"{self._base}/zones/{quote(zone_id)}/dns_records/{quote(record_id)}"
        res = _http.delete_json(url, headers=self._headers(), timeout=self._timeout)
        ok, _result, err = self._envelope(res)
        if not ok:
            return CfResult(ok=False, status=res.status, error=err, zone_id=zone_id, raw=res.body)
        return CfResult(ok=True, status=res.status, zone_id=zone_id, raw=res.body)

    # ── high-level idempotent operations ───────────────────────────────
    def upsert_a_record(self, zone_name: str, fqdn: str, ip: str, *,
                        proxied: bool = _PROXIED, ttl: int = _TTL) -> CfResult:
        """Create-or-update the DNS-only A record ``fqdn`` → ``ip``. Idempotent.

        Resolves the zone, looks for an existing A record, then PUTs (when one
        exists, even if the IP already matches — cheap and keeps proxied/ttl
        in sync) or POSTs a new one."""
        zone = self.find_zone_id(zone_name)
        if not zone.ok:
            return zone
        existing = self.find_a_record(zone.zone_id, fqdn)
        if not existing.ok:
            return existing
        if existing.record is not None:
            return self.update_a_record(zone.zone_id, existing.record.id, fqdn, ip,
                                        proxied=proxied, ttl=ttl)
        return self.create_a_record(zone.zone_id, fqdn, ip, proxied=proxied, ttl=ttl)

    def delete_a_record(self, zone_name: str, fqdn: str, *, record_id: str = "") -> CfResult:
        """Delete the A record for ``fqdn``. If ``record_id`` is known (stored
        on the customer row) we skip the lookup; otherwise we resolve it.
        Deleting an already-absent record is treated as success (idempotent)."""
        zone = self.find_zone_id(zone_name)
        if not zone.ok:
            return zone
        rid = (record_id or "").strip()
        if not rid:
            existing = self.find_a_record(zone.zone_id, fqdn)
            if not existing.ok:
                return existing
            if existing.record is None:
                return CfResult(ok=True, status=200, zone_id=zone.zone_id)  # nothing to delete
            rid = existing.record.id
        return self.delete_record(zone.zone_id, rid)


__all__ = ["CloudflareDNSClient", "DnsRecord", "CfResult", "DEFAULT_API_BASE"]
