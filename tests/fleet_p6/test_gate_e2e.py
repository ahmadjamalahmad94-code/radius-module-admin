"""Phase-6 gate E2E — the DNS parts bind end to end.

Proves the four reconciled seams work together:
  * D: token saved through C's settings_store (Fernet) is the SAME plaintext A's
    driver decrypts (``_load_token``).
  * A+B+C: with a token + a MOCKED transport, the real reconciler + real driver
    (DRIVER_BACKEND=="real", reconciler_available()==True) publish free-mode A
    records and the token reaches the transport.
  * no token ⇒ the reconciler forces dry-run ⇒ the driver makes ZERO transport
    calls. Modes are "free"/"paid" throughout.
"""
from __future__ import annotations

import re

from app.extensions import db
from fleet.config import FLEET
from fleet.dns import cloudflare as cf
from fleet.dns import driver_adapter, reconciler, settings_store
from fleet.dns.models_dns import DnsRecordState  # noqa: F401 (model registration)
from fleet.health.models_health import FleetChrHealth
from fleet.registry.models_chr import FleetChrNode, FleetProvider
from fleet.ui.dns_reconciler_view import reconciler_available

E2E_TOKEN = "cf-e2e-secret-token-987"


class _FakeTransport:
    """Records every call + the token it saw; serves free-mode A records."""

    def __init__(self) -> None:
        self.records: list[dict] = []
        self.calls: list[tuple[str, str, dict | None]] = []
        self.tokens_seen: list[str] = []
        self._n = 0

    def _id(self) -> str:
        self._n += 1
        return f"rec-{self._n}"

    def __call__(self, call, token, cfg):  # HttpTransport signature
        self.tokens_seen.append(token.reveal())
        self.calls.append((call.method, call.path, call.body))
        if re.fullmatch(r"zones/[^/]+/dns_records.*", call.path):
            if call.method == "GET":
                return 200, {"success": True, "result": list(self.records)}
            if call.method == "POST":
                b = call.body or {}
                row = {"id": self._id(), "content": b.get("content"),
                       "type": b.get("type", "A"), "name": b.get("name"), "ttl": b.get("ttl")}
                self.records.append(row)
                return 200, {"success": True, "result": row}
        m = re.fullmatch(r"zones/[^/]+/dns_records/([^/]+)", call.path)
        if m and call.method == "DELETE":
            rid = m.group(1)
            self.records = [r for r in self.records if r["id"] != rid]
            return 200, {"success": True, "result": {"id": rid}}
        return 404, {"success": False, "errors": [{"message": "unhandled"}]}


def _seed_nodes() -> None:
    prov = FleetProvider(name="Contabo", cost_model="open", price_per_tb=0)
    db.session.add(prov)
    db.session.flush()
    for name, ip, mgmt in (("chr-eu-1", "203.0.113.11", "10.99.0.11"),
                           ("chr-eu-2", "203.0.113.12", "10.99.0.12")):
        node = FleetChrNode(
            provider_id=prov.id, name=name, public_ip=ip, wg_mgmt_ip=mgmt,
            wg_mgmt_pubkey=f"PUB_{name}", max_sessions=1000, link_speed_mbps=500,
            status="up", enabled=True, drain=False,
        )
        db.session.add(node)
        db.session.flush()
        # The reconciler re-checks the monitor's authoritative health — mark up.
        db.session.add(FleetChrHealth(chr_id=node.id, state="up"))
    db.session.commit()


# ─────────────────────────────────────────────────────────────────────────────
# D: token flows UI → driver
# ─────────────────────────────────────────────────────────────────────────────
def test_token_saved_in_ui_store_is_what_driver_decrypts(app):
    settings_store.save_token(E2E_TOKEN)
    # C's store decrypts it…
    assert settings_store.get_token_for_driver() == E2E_TOKEN
    # …and A's driver loads the SAME plaintext (via the store, not a vault ref).
    assert cf._load_token(FLEET.dns.cloudflare).reveal() == E2E_TOKEN


# ─────────────────────────────────────────────────────────────────────────────
# A+B+C: real reconciler + real driver, free mode, token reaches the transport
# ─────────────────────────────────────────────────────────────────────────────
def test_reconcile_now_real_chain_publishes_free_a_records(app, monkeypatch):
    _seed_nodes()
    settings_store.save_mode("free")
    settings_store.save_token(E2E_TOKEN)
    fake = _FakeTransport()
    monkeypatch.setattr(cf, "_urllib_transport", fake)

    result = reconciler.reconcile_now()  # real reconciler → real driver → mock transport

    assert driver_adapter.DRIVER_BACKEND == "real"
    assert reconciler_available() is True
    assert result.applied is True
    assert result.apply is not None
    assert result.apply.mode == "free"                       # free mode throughout
    # The real driver actually hit the (mocked) transport with A-record POSTs.
    posts = [c for c in fake.calls if c[0] == "POST"]
    assert len(posts) == 2
    assert all((c[2] or {}).get("type", "A") == "A" for c in posts)
    assert sorted((c[2] or {}).get("content") for c in posts) == ["203.0.113.11", "203.0.113.12"]
    # Token flowed UI → store → driver → transport.
    assert E2E_TOKEN in fake.tokens_seen


# ─────────────────────────────────────────────────────────────────────────────
# no token ⇒ dry-run ⇒ zero transport calls
# ─────────────────────────────────────────────────────────────────────────────
def test_reconcile_now_without_token_is_dry_run_no_transport(app, monkeypatch):
    _seed_nodes()
    settings_store.save_mode("free")
    settings_store.clear_token()  # no token configured
    fake = _FakeTransport()
    monkeypatch.setattr(cf, "_urllib_transport", fake)

    result = reconciler.reconcile_now()

    assert driver_adapter.DRIVER_BACKEND == "real"
    assert result.applied is False          # dry-run: nothing applied
    assert fake.calls == []                 # the driver never called Cloudflare
