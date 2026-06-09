"""CHR Fleet Phase 6 — Cloudflare driver verification.

Every test uses a MOCK transport (:class:`_FakeTransport`) — the real
Cloudflare API is NEVER reached. The transport records every call and
returns scripted responses so each idempotency / error / mode path can
be exercised deterministically.

Coverage:

* **Mode FREE**
    - empty live → POST one A-record per included origin.
    - live matches desired → ``changed=False`` and ZERO mutation calls.
    - re-apply same set → idempotent no-op.
    - excluded origin → its IP is DELETED from the live record set.
    - included re-added → DELETE + POST in one apply (diff path).
    - applied state is recorded into ``fleet_dns_records_state``.

* **Mode PAID**
    - empty live → POST pool, POST LB.
    - live pool already matches → no pool update; no LB update.
    - exclude origin → pool origin persists with ``enabled=False`` and
      ``weight=0.0`` is preserved across re-apply.
    - graduated weights (0.2 / 0.5 / 1.0) round-trip into pool origins.
    - re-apply same desired state → no PUT.

* **DRY-RUN gates**
    - No token configured (no ``Setting`` row) → ``dry_run=True``, no
      execute calls.
    - Explicit ``dry_run=True`` overrides token presence.

* **Security**
    - The token never appears in any field of the returned
      :class:`ApplyResult` — not in ``calls_planned[].body``,
      ``calls_planned[].path``, ``errors``, or ``snapshot``.
    - Errors from the transport surface as short codes, NEVER with the
      Cloudflare body raw.

* **Error handling**
    - HTTP 401 short-circuits the apply (no partial publish).
    - HTTP 5xx is reported but does not raise.
    - Idempotency is preserved across an error (state isn't persisted on
      mutation failure).
"""
from __future__ import annotations

import dataclasses
import re
from typing import Iterable

import pytest

from app.extensions import db
from app.models import Setting

from fleet.config import FLEET
from fleet.dns.cloudflare import (
    ApplyResult,
    CloudflareDriver,
    DesiredOrigin,
    IntendedCall,
    MODE_FREE,
    MODE_PAID,
    _RedactedToken,
    apply_desired_state,
    current_state,
)
from fleet.dns.models_dns import DnsRecordState


# ════════════════════════════════════════════════════════════════════════
# Fake transport — captures every call and returns scripted responses
# ════════════════════════════════════════════════════════════════════════


class _FakeTransport:
    """In-memory fake of the Cloudflare API.

    Mode-FREE: holds a list of A-records. POSTs add, DELETEs remove. GET
    returns the current set in Cloudflare's ``{"success": True, "result": [...]}``
    shape.

    Mode-PAID: holds a single pool + a single LB by name. POSTs create,
    PUTs replace.
    """

    def __init__(self) -> None:
        self.records: list[dict] = []
        self.pool: dict | None = None
        self.lb: dict | None = None
        # Optional failure injection: per-method-status-code overrides.
        self.fail_with: tuple[int, str] | None = None
        self.calls: list[tuple[str, str, dict | None]] = []
        self.auth_headers_seen: list[str] = []
        self._next_id = 0
        # The token captured at first call — used by the token-leak test.
        self.token_strings_seen: list[str] = []

    def _new_id(self) -> str:
        self._next_id += 1
        return f"rec-{self._next_id:04d}"

    def __call__(self, call: IntendedCall, token, cfg) -> tuple[int, dict]:
        # Record the token plaintext seen (so the leak test can scan for it).
        self.token_strings_seen.append(token.reveal())
        self.calls.append((call.method, call.path, call.body))

        if self.fail_with is not None:
            status, code = self.fail_with
            return status, {"success": False, "errors": [{"code": int(code or 0), "message": "x"}]}

        # ── FREE-mode endpoints ───────────────────────────────────────
        m = re.fullmatch(r"zones/[^/]+/dns_records.*", call.path)
        if m and call.method == "GET":
            return 200, {"success": True, "result": list(self.records)}
        if m and call.method == "POST":
            body = call.body or {}
            row = {
                "id": self._new_id(),
                "content": body.get("content"),
                "type": body.get("type", "A"),
                "name": body.get("name"),
                "ttl": body.get("ttl"),
            }
            self.records.append(row)
            return 200, {"success": True, "result": row}
        m = re.fullmatch(r"zones/[^/]+/dns_records/([^/]+)", call.path)
        if m and call.method == "DELETE":
            rid = m.group(1)
            self.records = [r for r in self.records if r["id"] != rid]
            return 200, {"success": True, "result": {"id": rid}}

        # ── PAID-mode endpoints ───────────────────────────────────────
        if re.fullmatch(r"accounts/[^/]+/load_balancers/pools", call.path):
            if call.method == "GET":
                return 200, {"success": True, "result": [self.pool] if self.pool else []}
            if call.method == "POST":
                self.pool = {"id": "pool-x", **(call.body or {})}
                return 200, {"success": True, "result": self.pool}
        m = re.fullmatch(r"accounts/[^/]+/load_balancers/pools/([^/]+)", call.path)
        if m and call.method == "PUT":
            assert self.pool is not None
            self.pool = {**self.pool, **(call.body or {})}
            return 200, {"success": True, "result": self.pool}

        if re.fullmatch(r"zones/[^/]+/load_balancers", call.path):
            if call.method == "GET":
                return 200, {"success": True, "result": [self.lb] if self.lb else []}
            if call.method == "POST":
                self.lb = {"id": "lb-x", **(call.body or {})}
                return 200, {"success": True, "result": self.lb}
        m = re.fullmatch(r"zones/[^/]+/load_balancers/([^/]+)", call.path)
        if m and call.method == "PUT":
            assert self.lb is not None
            self.lb = {**self.lb, **(call.body or {})}
            return 200, {"success": True, "result": self.lb}

        return 404, {"success": False, "errors": [{"code": 7003, "message": "unhandled"}]}


# ════════════════════════════════════════════════════════════════════════
# Helpers
# ════════════════════════════════════════════════════════════════════════


_TOKEN_PLAIN = "cfp_test_TOKEN_xyz_DO_NOT_LEAK_098"


def _install_token(app, *, plaintext: str = _TOKEN_PLAIN, ref: str = "vr_test_cf") -> None:
    """Park the Cloudflare token in the vault + write the Setting row that
    points at it. After this, :func:`_load_token` returns the plaintext
    and the driver runs in send mode (not dry-run)."""
    from fleet.registry.secrets_vault import store_secret

    # Reuse a ref if it already exists (idempotent setup).
    real_ref = store_secret(
        owner="cloudflare:dns", purpose="api_token", plaintext=plaintext,
        kind="api_token",
    )
    db.session.merge(Setting(key="cloudflare.dns.token_ref", value=real_ref.ref))
    db.session.commit()


def _desired(*items: tuple[str, str, float, bool]) -> list[DesiredOrigin]:
    return [
        DesiredOrigin(node=n, ip=ip, weight=w, included=inc)
        for (n, ip, w, inc) in items
    ]


# ════════════════════════════════════════════════════════════════════════
# 1. FREE mode
# ════════════════════════════════════════════════════════════════════════


def test_free_publishes_a_record_per_included_origin(app):
    _install_token(app)
    fake = _FakeTransport()

    desired = _desired(
        ("chr-A", "203.0.113.10", 1.0, True),
        ("chr-B", "203.0.113.11", 1.0, True),
    )
    result = apply_desired_state(desired, mode=MODE_FREE, transport=fake)

    assert result.dry_run is False
    assert result.changed is True
    # Two POSTs (no DELETEs); plus one GET happened first (read side).
    posts = [c for c in fake.calls if c[0] == "POST"]
    assert len(posts) == 2
    assert {p[2]["content"] for p in posts} == {"203.0.113.10", "203.0.113.11"}
    # All POSTs carried the right name + ttl.
    assert {p[2]["name"] for p in posts} == {"vpn.hoberadius.com"}
    assert {p[2]["ttl"] for p in posts} == {FLEET.dns.ttl}


def test_free_idempotent_when_live_matches_desired(app):
    _install_token(app)
    fake = _FakeTransport()
    desired = _desired(("chr-A", "203.0.113.10", 1.0, True))

    # First apply seeds the live set.
    apply_desired_state(desired, mode=MODE_FREE, transport=fake)
    fake.calls.clear()

    # Re-applying the EXACT same desired state must not mutate anything.
    result = apply_desired_state(desired, mode=MODE_FREE, transport=fake)
    assert result.changed is False
    assert result.calls_planned == ()
    # Only a GET should have hit the transport (read-side diff).
    assert all(c[0] == "GET" for c in fake.calls)


def test_free_excludes_drained_origin(app):
    _install_token(app)
    fake = _FakeTransport()

    # Seed two origins live.
    apply_desired_state(_desired(
        ("chr-A", "203.0.113.10", 1.0, True),
        ("chr-B", "203.0.113.11", 1.0, True),
    ), mode=MODE_FREE, transport=fake)
    fake.calls.clear()

    # Drain chr-B (included=False) — driver must DELETE 203.0.113.11.
    result = apply_desired_state(_desired(
        ("chr-A", "203.0.113.10", 1.0, True),
        ("chr-B", "203.0.113.11", 1.0, False),  # drained
    ), mode=MODE_FREE, transport=fake)

    assert result.changed is True
    deletes = [c for c in fake.calls if c[0] == "DELETE"]
    assert len(deletes) == 1
    assert "203.0.113.11" not in [r["content"] for r in fake.records]
    assert "203.0.113.10" in [r["content"] for r in fake.records]


def test_free_replace_set_does_delete_and_post(app):
    _install_token(app)
    fake = _FakeTransport()
    apply_desired_state(_desired(("chr-A", "203.0.113.10", 1.0, True)),
                        mode=MODE_FREE, transport=fake)
    fake.calls.clear()

    # Swap chr-A for chr-C with a different IP.
    apply_desired_state(_desired(
        ("chr-A", "203.0.113.10", 1.0, False),    # drained
        ("chr-C", "203.0.113.12", 1.0, True),
    ), mode=MODE_FREE, transport=fake)

    methods = [c[0] for c in fake.calls if c[0] in ("POST", "DELETE")]
    assert "POST" in methods and "DELETE" in methods
    assert {r["content"] for r in fake.records} == {"203.0.113.12"}


def test_free_records_state_into_dns_records_state(app):
    _install_token(app)
    fake = _FakeTransport()
    apply_desired_state(_desired(("chr-A", "203.0.113.10", 1.0, True)),
                        mode=MODE_FREE, transport=fake)
    row = DnsRecordState.get("vpn.hoberadius.com", "A")
    assert row is not None
    assert row.published_ips == ["203.0.113.10"]
    assert row.provider_zone_id == FLEET.dns.cloudflare.zone_id


# ════════════════════════════════════════════════════════════════════════
# 2. PAID mode
# ════════════════════════════════════════════════════════════════════════


def test_paid_creates_pool_then_lb_on_empty(app):
    _install_token(app)
    fake = _FakeTransport()
    desired = _desired(
        ("chr-A", "203.0.113.10", 1.0, True),
        ("chr-B", "203.0.113.11", 0.5, True),
    )
    result = apply_desired_state(desired, mode=MODE_PAID, transport=fake)

    posts = [c for c in fake.calls if c[0] == "POST"]
    paths = [p[1] for p in posts]
    assert any("load_balancers/pools" in p for p in paths)
    assert any("zones/" in p and p.endswith("/load_balancers") for p in paths)
    assert result.changed is True
    # Pool origins reflect the graduated weights.
    assert fake.pool is not None
    by_name = {o["name"]: o for o in fake.pool["origins"]}
    assert by_name["chr-A"]["weight"] == 1.0
    assert by_name["chr-B"]["weight"] == 0.5
    assert all(o["enabled"] for o in fake.pool["origins"])


def test_paid_excludes_origin_with_enabled_false(app):
    _install_token(app)
    fake = _FakeTransport()
    apply_desired_state(_desired(
        ("chr-A", "203.0.113.10", 1.0, True),
        ("chr-B", "203.0.113.11", 1.0, True),
    ), mode=MODE_PAID, transport=fake)
    fake.calls.clear()

    # Drain chr-B; the pool keeps it as enabled=False (preserves health
    # history) rather than removing the origin entirely.
    apply_desired_state(_desired(
        ("chr-A", "203.0.113.10", 1.0, True),
        ("chr-B", "203.0.113.11", 1.0, False),
    ), mode=MODE_PAID, transport=fake)

    assert fake.pool is not None
    by_name = {o["name"]: o for o in fake.pool["origins"]}
    assert by_name["chr-B"]["enabled"] is False
    assert by_name["chr-A"]["enabled"] is True


def test_paid_idempotent_no_put_when_pool_matches(app):
    _install_token(app)
    fake = _FakeTransport()
    desired = _desired(("chr-A", "203.0.113.10", 1.0, True))
    apply_desired_state(desired, mode=MODE_PAID, transport=fake)
    fake.calls.clear()

    result = apply_desired_state(desired, mode=MODE_PAID, transport=fake)
    assert result.changed is False
    # Only GETs (pool list + LB list) — no mutation.
    assert all(c[0] == "GET" for c in fake.calls)


def test_paid_graduated_weights_round_trip(app):
    _install_token(app)
    fake = _FakeTransport()
    desired = _desired(
        ("chr-A", "203.0.113.10", 1.0, True),
        ("chr-B", "203.0.113.11", 0.5, True),
        ("chr-C", "203.0.113.12", 0.2, True),
    )
    apply_desired_state(desired, mode=MODE_PAID, transport=fake)
    weights = {o["name"]: o["weight"] for o in fake.pool["origins"]}
    assert weights == {"chr-A": 1.0, "chr-B": 0.5, "chr-C": 0.2}


# ════════════════════════════════════════════════════════════════════════
# 3. Dry-run gates
# ════════════════════════════════════════════════════════════════════════


def test_dry_run_when_no_token_configured(app):
    # No Setting row at all → driver must NOT send.
    fake = _FakeTransport()
    desired = _desired(("chr-A", "203.0.113.10", 1.0, True))
    result = apply_desired_state(desired, mode=MODE_FREE, transport=fake)

    assert result.dry_run is True
    assert result.calls_executed == ()
    # Read-side GET runs even in dry-run? In our implementation, when the
    # token is empty we skip the GET entirely (no auth-required read).
    assert all(c[0] != "POST" and c[0] != "DELETE" for c in fake.calls)


def test_explicit_dry_run_overrides_token_presence(app):
    _install_token(app)
    fake = _FakeTransport()
    desired = _desired(("chr-A", "203.0.113.10", 1.0, True))
    result = apply_desired_state(desired, mode=MODE_FREE, dry_run=True, transport=fake)

    assert result.dry_run is True
    assert result.calls_executed == ()
    # Still produces a plan (operator can see what WOULD happen).
    assert result.changed is True
    assert any(c.method == "POST" for c in result.calls_planned)


def test_dry_run_still_records_intended_state(app):
    _install_token(app)
    fake = _FakeTransport()
    desired = _desired(("chr-A", "203.0.113.10", 1.0, True))
    apply_desired_state(desired, mode=MODE_FREE, dry_run=True, transport=fake)
    # We persist what we INTENDED — the operator UI shouldn't show stale
    # state just because the live apply is gated.
    row = DnsRecordState.get("vpn.hoberadius.com", "A")
    assert row is not None
    assert row.published_ips == ["203.0.113.10"]


# ════════════════════════════════════════════════════════════════════════
# 4. Security — token never leaks
# ════════════════════════════════════════════════════════════════════════


def test_token_never_appears_in_apply_result(app):
    _install_token(app)
    fake = _FakeTransport()
    desired = _desired(("chr-A", "203.0.113.10", 1.0, True))
    result = apply_desired_state(desired, mode=MODE_FREE, transport=fake)

    # Render every field of the result as a string and scan for the token.
    rendered = " ".join([
        repr(result.calls_planned),
        repr(result.calls_executed),
        repr(result.errors),
        repr(result.snapshot),
    ])
    assert _TOKEN_PLAIN not in rendered, "token leaked into ApplyResult"


def test_token_redaction_wrapper_str_and_repr_are_safe():
    t = _RedactedToken(_TOKEN_PLAIN)
    assert _TOKEN_PLAIN not in repr(t)
    assert _TOKEN_PLAIN not in str(t)
    # Truthy iff the underlying string is non-empty.
    assert bool(t) is True
    assert bool(_RedactedToken("")) is False
    # The plaintext is only reachable via the explicit reveal() method.
    assert t.reveal() == _TOKEN_PLAIN


def test_transport_error_does_not_smuggle_token_back(app):
    _install_token(app)
    fake = _FakeTransport()
    fake.fail_with = (401, "10000")  # Cloudflare auth failure code
    result = apply_desired_state(
        _desired(("chr-A", "203.0.113.10", 1.0, True)),
        mode=MODE_FREE, transport=fake,
    )
    # An error was reported — but the token does not appear.
    assert result.errors, "expected an error on 401"
    assert all(_TOKEN_PLAIN not in e for e in result.errors)


# ════════════════════════════════════════════════════════════════════════
# 5. Error handling
# ════════════════════════════════════════════════════════════════════════


def test_first_failure_short_circuits_apply(app):
    """A failed POST must not allow subsequent mutations — partial
    publishes are dangerous for DNS (clients could resolve to a
    half-populated set)."""
    _install_token(app)
    fake = _FakeTransport()
    fake.fail_with = (500, "0")
    result = apply_desired_state(_desired(
        ("chr-A", "203.0.113.10", 1.0, True),
        ("chr-B", "203.0.113.11", 1.0, True),
    ), mode=MODE_FREE, transport=fake)

    assert result.errors
    assert len(result.calls_executed) == 0
    # State was NOT recorded on error (no DnsRecordState row exists).
    assert DnsRecordState.get("vpn.hoberadius.com", "A") is None


def test_unknown_mode_raises(app):
    with pytest.raises(ValueError):
        apply_desired_state([], mode="bogus")


def test_invalid_ipv4_skipped(app):
    _install_token(app)
    fake = _FakeTransport()
    apply_desired_state(_desired(
        ("chr-A", "203.0.113.10", 1.0, True),
        ("chr-bad", "not-an-ip", 1.0, True),
        ("chr-v6", "2001:db8::1", 1.0, True),   # we don't publish AAAA yet
    ), mode=MODE_FREE, transport=fake)
    contents = {r["content"] for r in fake.records}
    assert contents == {"203.0.113.10"}


# ════════════════════════════════════════════════════════════════════════
# 6. current_state reader
# ════════════════════════════════════════════════════════════════════════


def test_current_state_returns_dry_run_when_no_token(app):
    state = current_state(mode=MODE_FREE)
    assert state == {"dry_run": True, "mode": MODE_FREE}


def test_current_state_free_lists_records(app):
    _install_token(app)
    fake = _FakeTransport()
    apply_desired_state(_desired(("chr-A", "203.0.113.10", 1.0, True)),
                        mode=MODE_FREE, transport=fake)
    state = current_state(mode=MODE_FREE, transport=fake)
    assert {r["content"] for r in state["records"]} == {"203.0.113.10"}


def test_current_state_paid_returns_pool_and_lb(app):
    _install_token(app)
    fake = _FakeTransport()
    apply_desired_state(_desired(("chr-A", "203.0.113.10", 1.0, True)),
                        mode=MODE_PAID, transport=fake)
    state = current_state(mode=MODE_PAID, transport=fake)
    assert state["pool"]["origins"][0]["name"] == "chr-A"
    assert state["lb"]["name"] == FLEET.dns.cloudflare.lb_name


# ════════════════════════════════════════════════════════════════════════
# 7. create_app smoke
# ════════════════════════════════════════════════════════════════════════


def test_create_app_boots(app):
    """If we got the ``app`` fixture, create_app already returned cleanly."""
    from sqlalchemy import inspect
    assert "fleet_dns_records_state" in set(inspect(db.engine).get_table_names())
