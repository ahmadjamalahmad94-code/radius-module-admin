"""fleet.sync.wg_data_check — verify the CHR↔proxy wg-data tunnel from the CHR.

The proxy host is external (not in this repo), so the panel can't read the
proxy's WireGuard state directly. But it CAN read the CHR's view over the same
REST channel the metrics poller uses: the CHR's ``wg-data`` peer toward the
proxy (tagged ``hobe-fleet-data``) carries a ``last-handshake``. A fresh
handshake there is real proof the data tunnel is up; a peer that exists but
never handshook is a real failure the operator must see.

Mirrors :mod:`fleet.health.wg_verify` in spirit and return shape so the sync
job can treat both handshake stages uniformly. Never raises.
"""
from __future__ import annotations

import dataclasses

from app.services.routeros_client import RouterOSClient, RouterOSError

from fleet.health.routeros_creds import credentials_for

#: The wg-data peer (toward the proxy) is tagged with this comment by the
#: unified provisioning script (chr_unified.rsc.j2).
_DATA_PEER_COMMENT = "hobe-fleet-data"


@dataclasses.dataclass(frozen=True)
class WgDataResult:
    ok: bool | None        # True=handshake seen, False=peer present but dead, None=could not check
    code: str              # ok | no_handshake | peer_missing | no_credentials | rest_failed
    message_ar: str
    last_handshake: str = ""
    rx_bytes: str = ""
    tx_bytes: str = ""

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)


def _pick_data_peer(peers: list[dict]) -> dict | None:
    for p in peers:
        if str(p.get("comment") or "") == _DATA_PEER_COMMENT:
            return p
    return peers[0] if len(peers) == 1 else None


def verify_node_wg_data(node, *, client_factory=None) -> WgDataResult:
    """Check the CHR's wg-data peer handshake toward the proxy."""
    creds = credentials_for(node)
    if creds is None:
        return WgDataResult(
            ok=None, code="no_credentials",
            message_ar=(
                "لا توجد بيانات اعتماد REST لهذه العقدة — تعذّر التحقق من مصافحة "
                "wg-data مع الوكيل (نفس قناة المقاييس)."
            ),
        )

    client = (client_factory or _default_factory)(
        host=creds["host"], port=creds["port"],
        user=creds["user"], password=creds["password"],
    )
    try:
        peers = client.list_wireguard_peers(interface="wg-data") or []
    except RouterOSError as exc:
        return WgDataResult(
            ok=None, code="rest_failed",
            message_ar=f"تعذّر قراءة نظراء wg-data عبر REST: {exc.message}",
        )
    except Exception:  # noqa: BLE001 — never crash the sync runner
        return WgDataResult(
            ok=None, code="rest_failed",
            message_ar="خطأ غير متوقّع أثناء قراءة حالة wg-data من العقدة.",
        )

    peer = _pick_data_peer(peers)
    if peer is None:
        return WgDataResult(
            ok=False, code="peer_missing",
            message_ar=(
                "لا يوجد peer على واجهة wg-data في العقدة — أعد استيراد سكربت "
                "التزويد (يضيف نظير الوكيل على المسار 10.98.0.1)."
            ),
        )

    handshake = str(peer.get("last-handshake") or "").strip()
    rx = str(peer.get("rx") or "")
    tx = str(peer.get("tx") or "")
    if not handshake:
        return WgDataResult(
            ok=False, code="no_handshake",
            message_ar=(
                "نظير wg-data موجود لكن دون مصافحة بعد — تحقّق من أن الوكيل يثق "
                "بمفتاح wg-data لهذه العقدة (يُنشَر عبر /api/proxy/wg-peers)."
            ),
            rx_bytes=rx, tx_bytes=tx,
        )
    return WgDataResult(
        ok=True, code="ok",
        message_ar="مصافحة wg-data مع الوكيل حيّة — مسار RADIUS قائم.",
        last_handshake=handshake, rx_bytes=rx, tx_bytes=tx,
    )


def _default_factory(*, host: str, port: int, user: str, password: str) -> RouterOSClient:
    return RouterOSClient(
        host=host, port=port, username=user, password=password,
        use_tls=True, verify_tls=False, timeout=8,
    )


__all__ = ["WgDataResult", "verify_node_wg_data"]
