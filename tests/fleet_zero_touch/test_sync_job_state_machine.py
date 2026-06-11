"""Sync-job stage state machine: real per-stage states, a forced failure that
blocks downstream stages, and a clean live progression to completion."""
from __future__ import annotations

from app.extensions import db

from tests.fleet_zero_touch.conftest import make_node, make_provider, set_full_infra


def _bykey(node_view):
    return {s["key"]: s["state"] for s in node_view["stages"]}


def test_forced_failure_blocks_downstream(zt):
    """A node missing its wg-data pubkey hard-fails stage 1 (keys), which blocks
    every later stage — so the UI shows exactly where it stopped."""
    set_full_infra()
    prov = make_provider()
    make_node(prov, "broken", octet=11, data_pub="")  # no wg-data pubkey
    db.session.commit()

    from fleet.sync import service
    job = service.create_job(scope="fleet")
    service.run_to_completion(job)
    d = service.to_dict(job)
    assert d["status"] == "done"

    nv = d["nodes"][0]
    states = _bykey(nv)
    assert states["keys"] == "failed"
    assert nv["node_state"] == "failed"
    # everything after the hard failure is blocked, not silently skipped
    later = [s for s in nv["stages"][1:]]
    assert all(s["state"] == "blocked" for s in later), states
    # the failure carries a human reason (where + why it stopped)
    assert nv["stages"][0]["reason"]


def test_green_path_reaches_radius(zt):
    set_full_infra()
    prov = make_provider()
    make_node(prov, "good", octet=11)
    db.session.commit()

    from fleet.sync import service
    job = service.create_job(scope="fleet")
    service.run_to_completion(job)
    nv = service.to_dict(job)["nodes"][0]
    states = _bykey(nv)
    assert states["keys"] == "done"
    assert states["proxy_peer"] == "done"
    assert states["script"] == "done"
    assert states["routing"] == "done"
    assert states["radius"] == "done"
    # No REST creds in test → handshakes can't be confirmed → non-blocking warn.
    assert states["wg_mgmt"] == "warn"
    assert states["wg_data"] == "warn"
    # panel apply helper not installed → panel_peer is a non-blocking warn.
    assert states["panel_peer"] == "warn"


def test_tick_is_incremental_and_live(zt):
    """Each tick advances exactly ONE stage (real progress, pollable)."""
    set_full_infra()
    prov = make_provider()
    make_node(prov, "good", octet=11)
    db.session.commit()

    from fleet.sync import service
    job = service.create_job(scope="fleet")

    last_terminal = 0
    seen = 0
    while job.status != "done" and seen < 50:
        service.tick(job)
        d = service.to_dict(job)
        terminal = d["progress"]["terminal"]
        assert terminal >= last_terminal  # never goes backwards
        # each productive tick advances terminal by exactly 1
        assert terminal - last_terminal in (0, 1)
        last_terminal = terminal
        seen += 1
    assert job.status == "done"
    d = service.to_dict(job)
    assert d["progress"]["percent"] == 100
    assert d["progress"]["total"] == 8


def test_progress_counts_and_percent(zt):
    set_full_infra()
    prov = make_provider()
    make_node(prov, "good", octet=11)
    make_node(prov, "broken", octet=12, data_pub="")
    db.session.commit()

    from fleet.sync import service
    job = service.create_job(scope="fleet")
    service.run_to_completion(job)
    d = service.to_dict(job)
    assert d["progress"]["total"] == 16  # 2 nodes × 8 stages
    counts = d["progress"]["counts"]
    assert counts["failed"] >= 1
    assert counts["blocked"] >= 1
    assert d["progress"]["percent"] == 100  # all terminal
