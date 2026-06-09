"""fleet.dns.models_dns — last-published front-door DNS record set.

ORM mirror of the ``dns_records_state`` table (see ``migrations/005_onboarding_dns.sql``
and ``docs/chr_fleet/02_DATA_MODEL.md §2.11``). One row per ``(fqdn,
record_type)``: the panel's memory of *what it last told DNS* so the controller
only calls the provider API when the healthy set actually changes (avoids rate
limits — see ``docs/chr_fleet/03_FRONT_DOOR_DNS.md §3.5``).

Phase-2 deliverable: the model + helpers only. The DNS controller, provider
drivers, and scheduler land in Phase 6 (P6-T1..T4).

Database portability
--------------------
The migration is PostgreSQL-flavoured (``INET[]``, ``TIMESTAMPTZ``); this model
uses portable types so the same SQLAlchemy classes work against the SQLite test
DB. ``published_ips`` is stored as a JSON-encoded list of strings and exposed
via a list property. The unique key ``(fqdn, record_type)`` is enforced at both
layers.
"""

from __future__ import annotations

import ipaddress
from typing import Iterable

from app.extensions import db
from app.models import TimestampMixin, json_dumps, json_loads


#: Allowed values for ``DnsRecordState.record_type``. The fleet only publishes
#: A and AAAA at the front door; CNAME / TXT / etc. live elsewhere.
DNS_RECORD_TYPES: tuple[str, ...] = ("A", "AAAA")


def _normalize_ip(value: str, *, record_type: str) -> str:
    """Return a normalised IP string; raise ``ValueError`` on type mismatch.

    Used by the setter so ``DnsRecordState.published_ips = [...]`` rejects
    "vpn.example.com" or an IPv6 in an A record at the model layer (DB CHECK
    constraints catch the same thing in Postgres, but we want a friendly error
    in tests + the Phase-6 controller).
    """
    try:
        addr = ipaddress.ip_address(value.strip())
    except (TypeError, ValueError, AttributeError) as exc:
        raise ValueError(f"not a valid IP literal: {value!r}") from exc
    if record_type == "A" and addr.version != 4:
        raise ValueError(f"A record requires IPv4, got {addr!r}")
    if record_type == "AAAA" and addr.version != 6:
        raise ValueError(f"AAAA record requires IPv6, got {addr!r}")
    return str(addr)


class DnsRecordState(TimestampMixin, db.Model):
    """One row = the last record-set the panel published for ``(fqdn, type)``.

    The Phase-6 DNS controller does::

        prev = DnsRecordState.get(fqdn, "A")
        new  = sorted(healthy_ipv4_set)
        if prev is None or prev.published_ips != new:
            provider.publish(fqdn, "A", new, ttl=cfg.ttl)
            DnsRecordState.upsert(fqdn, "A", new, ttl, reason="health_change")

    so this table is the diff source — never publish empty (per §3.6 empty-set
    guard, enforced by the controller, not the schema).
    """

    __tablename__ = "fleet_dns_records_state"
    __table_args__ = (
        db.UniqueConstraint("fqdn", "record_type", name="uq_dns_fqdn_type"),
    )

    # Integer rather than BigInteger so SQLite (used in tests) treats this as
    # ROWID and autoincrements; Postgres production uses BIGSERIAL as declared
    # in the migration — both map cleanly to Python ``int`` either way.
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    fqdn = db.Column(db.String(255), nullable=False)
    record_type = db.Column(db.String(8), nullable=False)

    # JSON-encoded list of IP literals. Postgres stores them as ``INET[]``;
    # we marshal through ``json_loads``/``json_dumps`` for portability. The
    # property layer below enforces type + sort order so ``==`` diffs against
    # the live healthy set are deterministic.
    published_ips_json = db.Column(db.Text, nullable=False, default="[]", server_default="[]")

    ttl = db.Column(db.Integer, nullable=False)
    provider_zone_id = db.Column(db.String(120), nullable=True)
    last_change_reason = db.Column(db.String(255), nullable=True)

    # ────────────────────────────────────────────────────────────────────
    # published_ips property — list[str], canonicalised and sorted
    # ────────────────────────────────────────────────────────────────────
    @property
    def published_ips(self) -> list[str]:
        return json_loads(self.published_ips_json, [])

    @published_ips.setter
    def published_ips(self, value: Iterable[str]) -> None:
        if value is None:
            raise ValueError("published_ips must be non-null (use empty-set guard at controller)")
        rt = self.record_type
        if rt not in DNS_RECORD_TYPES:
            raise ValueError(f"record_type must be set to one of {DNS_RECORD_TYPES} before published_ips")
        normalised = sorted({_normalize_ip(v, record_type=rt) for v in value})
        self.published_ips_json = json_dumps(normalised)

    # ────────────────────────────────────────────────────────────────────
    # Convenience: idempotent upsert used by Phase-6 controller
    # ────────────────────────────────────────────────────────────────────
    @classmethod
    def get(cls, fqdn: str, record_type: str) -> "DnsRecordState | None":
        return cls.query.filter_by(fqdn=fqdn, record_type=record_type).one_or_none()

    @classmethod
    def upsert(
        cls,
        fqdn: str,
        record_type: str,
        ips: Iterable[str],
        ttl: int,
        *,
        provider_zone_id: str | None = None,
        reason: str | None = None,
    ) -> "DnsRecordState":
        """Insert-or-update by ``(fqdn, record_type)``. Caller commits."""
        if record_type not in DNS_RECORD_TYPES:
            raise ValueError(f"record_type must be one of {DNS_RECORD_TYPES}, got {record_type!r}")
        if ttl is None or ttl <= 0:
            raise ValueError("ttl must be a positive integer")
        row = cls.get(fqdn, record_type)
        if row is None:
            row = cls(fqdn=fqdn, record_type=record_type, ttl=ttl)
            db.session.add(row)
        row.record_type = record_type
        row.ttl = ttl
        row.published_ips = ips
        if provider_zone_id is not None:
            row.provider_zone_id = provider_zone_id
        if reason is not None:
            row.last_change_reason = reason
        return row

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return (
            f"<DnsRecordState fqdn={self.fqdn!r} type={self.record_type!r} "
            f"ips={self.published_ips!r}>"
        )
