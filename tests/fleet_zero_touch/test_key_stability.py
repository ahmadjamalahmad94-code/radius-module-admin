"""Key-stability guard: the panel wg-mgmt key is the single stable source of
truth — no onboarding / render / resync path may regenerate it, and a
deliberate change MUST cascade to flag every node for re-import."""
from __future__ import annotations

from app.extensions import db

from tests.fleet_zero_touch.conftest import (
    _pk, make_node, make_provider, set_full_infra,
)


def test_resync_and_onboarding_never_regenerate_panel_key(zt):
    set_full_infra()
    from fleet.registry import infra_settings as ifs
    before_pub = ifs.panel_pubkey_for_display()
    assert before_pub  # sanity: we set it

    prov = make_provider()
    make_node(prov, "chr-a", octet=11)
    make_node(prov, "chr-b", octet=12)
    db.session.commit()

    # Drive the whole zero-touch machinery: reconcile + a full fleet sync job.
    from fleet.sync import service
    job = service.create_job(scope="fleet")
    service.run_to_completion(job)

    after_pub = ifs.panel_pubkey_for_display()
    assert after_pub == before_pub, "panel pubkey changed during resync — drift!"


def test_panel_key_change_cascades_needs_reimport(zt):
    set_full_infra()
    prov = make_provider()
    n1 = make_node(prov, "chr-a", octet=11)
    n2 = make_node(prov, "chr-b", octet=12)
    db.session.commit()
    assert not n1.needs_reimport and not n2.needs_reimport

    from fleet.sync.keys import flag_fleet_needs_reimport
    flagged = flag_fleet_needs_reimport()
    assert set(flagged) == {"chr-a", "chr-b"}
    db.session.refresh(n1)
    db.session.refresh(n2)
    assert n1.needs_reimport and n2.needs_reimport


def test_wg_mgmt_handshake_clears_needs_reimport(zt, monkeypatch):
    """Stage 5 (wg-mgmt handshake OK) is real proof the re-import landed → flag
    clears automatically."""
    set_full_infra()
    prov = make_provider()
    node = make_node(prov, "chr-a", octet=11)
    node.needs_reimport = True
    db.session.commit()

    # Fake a passing wg-mgmt identity check.
    import fleet.health.wg_verify as wgv

    def _ok(_node, **_kw):
        return wgv.WgVerifyResult(ok=True, code="ok", message_ar="ok", last_handshake="1s")

    monkeypatch.setattr(wgv, "verify_node_wg_identity", _ok)

    from fleet.sync.stages import run_stage
    outcome = run_stage("wg_mgmt", node, {"panel_pubkey": _pk("panel")})
    assert outcome.state == "done"
    db.session.refresh(node)
    assert node.needs_reimport is False
