"""fleet.health.wg_verify — verify WireGuard key identity panel ↔ CHR.

Field incident: the CHR's ``wg-mgmt`` peer carried a WRONG panel public
key. Symptom set — no ping to the CHR's wg-mgmt IP, no REST, stale
handshake — burned hours because nothing on either side said "the keys
don't match". This module closes that gap with a one-call diagnosis the
UI can run before declaring a node ready (and any time the operator
suspects the tunnel).

What it checks (over the SAME REST channel the metrics poller uses —
so a passing check also proves REST itself):

1. **CHR trusts the panel**: the ``wg-mgmt`` peer's ``public-key`` on
   the CHR equals the panel's own wg-mgmt public key
   (``infra_settings.panel_pubkey_for_display()``).
2. **Panel trusts the CHR**: the CHR's ``wg-mgmt`` interface
   ``public-key`` equals what the panel has on file for the node
   (``fleet_chr_nodes.wg_mgmt_pubkey``) — i.e. the key the panel-side
   WireGuard peer config was built from.
3. Bonus telemetry: the peer's ``last-handshake`` / ``rx`` / ``tx`` so
   the UI can show liveness next to the verdict.

The function NEVER raises for transport/config problems — it returns a
structured verdict with machine codes so the route can render a precise
Arabic message. A REST failure here usually means the same wire bugs
the metrics poller would hit; surfacing the RouterOSError code keeps
the two paths diagnosable together.
"""
from __future__ import annotations

import dataclasses
import logging
from typing import Any

from app.services.routeros_client import RouterOSClient, RouterOSError

from fleet.health.routeros_creds import credentials_for
from fleet.registry.models_chr import FleetChrNode

logger = logging.getLogger(__name__)


@dataclasses.dataclass(frozen=True)
class WgVerifyResult:
    """Outcome of one panel↔CHR key verification."""

    ok: bool
    code: str                      # ok | no_credentials | rest_failed | peer_missing |
                                   # panel_key_mismatch | chr_key_mismatch | panel_key_unset
    message_ar: str                # operator-facing Arabic verdict
    panel_pubkey_expected: str = ""    # what the panel says its own key is
    panel_pubkey_on_chr: str = ""      # what the CHR's wg-mgmt peer actually trusts
    chr_pubkey_expected: str = ""      # what the panel has on file for the CHR
    chr_pubkey_actual: str = ""        # the CHR's real wg-mgmt interface key
    last_handshake: str = ""
    rx_bytes: str = ""
    tx_bytes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


#: The wg-mgmt peer is tagged with this comment by the unified script.
_MGMT_PEER_COMMENT = "hobe-fleet-mgmt"


def verify_node_wg_identity(node: FleetChrNode, *, client_factory=None) -> WgVerifyResult:
    """Run the both-directions key check for ``node``.

    ``client_factory`` is the unit-test seam — same convention as
    :func:`fleet.health.routeros_collector.collect`.
    """
    # Panel's own pubkey (what the CHR peer must trust).
    from fleet.registry.infra_settings import panel_pubkey_for_display
    panel_key = (panel_pubkey_for_display() or "").strip()
    if not panel_key:
        return WgVerifyResult(
            ok=False, code="panel_key_unset",
            message_ar=(
                "لم يُولَّد مفتاح اللوحة العام بعد — ولّده من "
                "«إعدادات بنية الأسطول» قبل التحقق."
            ),
        )

    creds = credentials_for(node)
    if creds is None:
        return WgVerifyResult(
            ok=False, code="no_credentials",
            message_ar=(
                "لا توجد بيانات اعتماد REST لهذه العقدة — التحقق من المفاتيح "
                "يمر عبر نفس قناة المقاييس."
            ),
            panel_pubkey_expected=panel_key,
        )

    client = (client_factory or _default_factory)(
        host=creds["host"], port=creds["port"],
        user=creds["user"], password=creds["password"],
    )

    # ── read the CHR state over REST ────────────────────────────────────
    try:
        peers = client.list_wireguard_peers(interface="wg-mgmt") or []
        iface = client.find_wireguard_interface("wg-mgmt") or {}
    except RouterOSError as exc:
        return WgVerifyResult(
            ok=False, code="rest_failed",
            message_ar=f"تعذّر القراءة عبر REST: {exc.message}",
            panel_pubkey_expected=panel_key,
        )
    except Exception:  # noqa: BLE001 — never crash the caller
        logger.exception("wg_verify: unexpected error for node %s", node.name)
        return WgVerifyResult(
            ok=False, code="rest_failed",
            message_ar="خطأ غير متوقع أثناء قراءة حالة WireGuard من العقدة.",
            panel_pubkey_expected=panel_key,
        )

    peer = _pick_mgmt_peer(peers)
    if peer is None:
        return WgVerifyResult(
            ok=False, code="peer_missing",
            message_ar=(
                "لا يوجد peer على واجهة wg-mgmt في العقدة — أعد استيراد "
                "سكربت التزويد."
            ),
            panel_pubkey_expected=panel_key,
        )

    peer_key = str(peer.get("public-key") or "").strip()
    chr_iface_key = str(iface.get("public-key") or "").strip()
    chr_expected = (node.wg_mgmt_pubkey or "").strip()
    handshake = str(peer.get("last-handshake") or "")
    rx = str(peer.get("rx") or "")
    tx = str(peer.get("tx") or "")

    base = dict(
        panel_pubkey_expected=panel_key,
        panel_pubkey_on_chr=peer_key,
        chr_pubkey_expected=chr_expected,
        chr_pubkey_actual=chr_iface_key,
        last_handshake=handshake, rx_bytes=rx, tx_bytes=tx,
    )

    # Direction 1: does the CHR trust the right panel key?
    if peer_key != panel_key:
        return WgVerifyResult(
            ok=False, code="panel_key_mismatch",
            message_ar=(
                "مفتاح اللوحة على العقدة لا يطابق مفتاح اللوحة الحالي — "
                "هذا بالضبط عطل الحادثة السابقة. أعد استيراد السكربت "
                "المولَّد حديثاً (يحمل المفتاح الصحيح)."
            ),
            **base,
        )

    # Direction 2: does the panel have the CHR's real key on file?
    # (Empty on-file value → the panel-side peer was never built; flag it.)
    if chr_expected and chr_iface_key and chr_expected != chr_iface_key:
        return WgVerifyResult(
            ok=False, code="chr_key_mismatch",
            message_ar=(
                "مفتاح العقدة المسجَّل في اللوحة لا يطابق مفتاحها الفعلي — "
                "حدّث سجل العقدة (أو أعد التزويد) ثم حدّث peer اللوحة."
            ),
            **base,
        )

    return WgVerifyResult(
        ok=True, code="ok",
        message_ar="مفاتيح WireGuard متطابقة في الاتجاهين — قناة الإدارة سليمة.",
        **base,
    )


def _pick_mgmt_peer(peers: list[dict]) -> dict | None:
    """Prefer the script-tagged peer; fall back to the single peer if the
    operator built it by hand without the comment."""
    for p in peers:
        if str(p.get("comment") or "") == _MGMT_PEER_COMMENT:
            return p
    return peers[0] if len(peers) == 1 else None


def _default_factory(*, host: str, port: int, user: str, password: str) -> RouterOSClient:
    return RouterOSClient(
        host=host, port=port, username=user, password=password,
        use_tls=True, verify_tls=False, timeout=8,
    )


__all__ = ["WgVerifyResult", "verify_node_wg_identity"]
