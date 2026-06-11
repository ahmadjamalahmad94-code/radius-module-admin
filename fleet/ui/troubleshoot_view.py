"""fleet.ui.troubleshoot_view — per-CHR onboarding troubleshooter.

One read-only adapter that gathers the four checks the operator needs to
confirm an onboarded CHR is end-to-end healthy:

1. **wg-mgmt key match** — panel's expected pubkey vs what's on the CHR's
   wg-mgmt peer (over the same REST channel the metrics poller uses).
2. **wg-data IP derived correctly** — the canonical RADIUS source IP the
   proxy sees, derived from ``wg_mgmt_ip`` per the parallel /24 rule.
3. **Proxy recognition** — does the live ``/api/proxy/routing-table``
   include this node's ``wg_data_ip`` in ``chr_nodes[]``? Answers "would
   the proxy accept a packet from this CHR?" without touching the proxy.
4. **RADIUS reachability hint** — heuristic based on (1)+(3): if the
   wg-mgmt key matches AND chr_nodes[] publishes the derived wg_data_ip,
   the proxy should accept RADIUS over wg-data (Reject vs timeout
   distinguishes "RADIUS reached the proxy" from "proxy never saw the
   packet" — both reproducible from the panel without a terminal).

All return shapes are plain dataclasses → trivial Jinja consumption.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.api.proxy_api import _derive_wg_data_ip
from app.services.reserved_subnets import is_reserved_address, is_reserved_range
from fleet.registry.models_chr import FleetChrNode


@dataclass(frozen=True)
class CheckRow:
    """One line in the troubleshooting verdict table."""

    key: str            # machine code
    label_ar: str       # row label (Arabic)
    ok: bool            # green/red dot
    value: str          # printable value the operator can copy
    detail_ar: str = "" # one-line hint on what to do when not ok
    severity: str = "info"   # ok | warn | error — feeds the dot colour


@dataclass(frozen=True)
class NodeTroubleshootView:
    """Full per-node verdict the page renders."""

    node_id: int
    name: str
    public_ip: str
    wg_mgmt_ip: str
    wg_data_ip: str
    proxy_recognised: bool
    wg_mgmt_key_ok: bool | None      # None ⇒ key check could not run (no creds etc.)
    rows: list[CheckRow] = field(default_factory=list)
    blockers: list[str] = field(default_factory=list)

    @property
    def all_green(self) -> bool:
        return not self.blockers and all(r.ok for r in self.rows)

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_id":         self.node_id,
            "name":            self.name,
            "public_ip":       self.public_ip,
            "wg_mgmt_ip":      self.wg_mgmt_ip,
            "wg_data_ip":      self.wg_data_ip,
            "proxy_recognised": self.proxy_recognised,
            "wg_mgmt_key_ok":  self.wg_mgmt_key_ok,
            "all_green":       self.all_green,
            "blockers":        list(self.blockers),
            "rows": [
                {"key": r.key, "label_ar": r.label_ar, "ok": r.ok,
                 "value": r.value, "detail_ar": r.detail_ar, "severity": r.severity}
                for r in self.rows
            ],
        }


def _routing_table_chr_entries() -> list[dict[str, Any]]:
    """Replay the panel's published chr_nodes[] (same code path the proxy
    consumes — so the verdict reflects what the proxy WOULD see).

    Local import avoids a route-time circular: ``fleet.ui.routes`` imports
    this module, ``app.api.proxy_api`` imports models that reference fleet.
    """
    from app.api.proxy_api import _derive_wg_data_ip  # noqa: F401  (used above)
    from app.models import ChrNode

    legacy = {n.id: n for n in ChrNode.query.all()}
    fleet: list[FleetChrNode] = []
    try:
        fleet = (
            FleetChrNode.query
            .filter(FleetChrNode.enabled.is_(True))
            .filter(FleetChrNode.drain.is_(False))
            .filter(FleetChrNode.status != "disabled")
            .all()
        )
    except Exception:  # noqa: BLE001
        fleet = []

    entries: list[dict[str, Any]] = []
    seen_names: set[str] = set()
    for n in fleet:
        if not n.name:
            continue
        entries.append({
            "name": n.name,
            "public_ip": n.public_ip,
            "wg_mgmt_ip": n.wg_mgmt_ip,
            "wg_data_ip": _derive_wg_data_ip(n.wg_mgmt_ip),
            "source": "fleet",
            "status": n.status,
        })
        seen_names.add(n.name)
    for n in legacy.values():
        if n.status != "active" or n.name in seen_names:
            continue
        entries.append({
            "name": n.name,
            "public_ip": n.public_ip,
            "wg_mgmt_ip": n.management_ip,
            "wg_data_ip": _derive_wg_data_ip(n.management_ip),
            "source": "legacy",
            "status": n.status,
        })
        seen_names.add(n.name)
    return entries


def _try_wg_verify(node: FleetChrNode) -> tuple[bool | None, str, str]:
    """Run the existing wg-verify check. Returns (ok|None, code, message)."""
    try:
        from fleet.health.wg_verify import verify_node_wg_identity
        r = verify_node_wg_identity(node)
        return (True if r.ok else False, r.code, r.message_ar)
    except Exception as exc:  # noqa: BLE001 — never break the page
        return (None, "verify_unavailable", f"تعذّر تشغيل فحص المفاتيح: {exc}")


def build_view(node: FleetChrNode) -> NodeTroubleshootView:
    """Build the troubleshooting view for one CHR node."""
    rows: list[CheckRow] = []
    blockers: list[str] = []

    # 1. wg-mgmt addressing — must be in 10.99/24, must be unique.
    mgmt_ip = (node.wg_mgmt_ip or "").strip()
    mgmt_ok = bool(mgmt_ip and mgmt_ip.startswith("10.99."))
    rows.append(CheckRow(
        key="wg_mgmt_ip",
        label_ar="عنوان wg-mgmt (قناة التحكم)",
        ok=mgmt_ok,
        value=mgmt_ip or "—",
        detail_ar=(
            "" if mgmt_ok else
            "العنوان يجب أن يكون داخل 10.99.0.0/24 — أعد تخصيص العقدة من «معالج الإضافة»."
        ),
        severity="ok" if mgmt_ok else "error",
    ))

    # 2. derived wg-data IP — what the proxy expects to see as the RADIUS source.
    data_ip = _derive_wg_data_ip(mgmt_ip)
    data_ok = bool(data_ip and data_ip.startswith("10.98."))
    rows.append(CheckRow(
        key="wg_data_ip",
        label_ar="عنوان wg-data المُشتق (مصدر RADIUS عند الوكيل)",
        ok=data_ok,
        value=data_ip or "—",
        detail_ar=(
            "" if data_ok else
            "لم يُشتق عنوان wg-data — هذا يعني أن wg-mgmt خارج 10.99/24 (أعلى)."
        ),
        severity="ok" if data_ok else "error",
    ))
    if not data_ok:
        blockers.append("derive_wg_data_ip_failed")

    # 3. Reserved-subnet collision sanity (the live 2026-06 root cause).
    from flask import current_app
    cfg = current_app.config
    local_addr = (cfg.get("CHR_PPP_LOCAL_ADDRESS") or "").strip()
    pool_range = (cfg.get("CHR_PPP_POOL_RANGES") or "").strip()
    coll_local = bool(local_addr) and is_reserved_address(local_addr)
    coll_range = bool(pool_range) and is_reserved_range(pool_range)
    coll = coll_local or coll_range
    rows.append(CheckRow(
        key="ppp_pool_safe",
        label_ar="عناوين PPP خارج الشبكات المحجوزة (10.98/10.99)",
        ok=not coll,
        value=(
            f"local={local_addr or '—'} · ranges={pool_range or '—'}"
        ),
        detail_ar=(
            "" if not coll else
            "إعدادات PPP تتقاطع مع شبكات الأسطول — غيّر CHR_PPP_LOCAL_ADDRESS/POOL_RANGES "
            "إلى نطاق خارج 10.98.0.0/24 و 10.99.0.0/24 (مثل 10.10.0.x)."
        ),
        severity="ok" if not coll else "error",
    ))
    if coll:
        blockers.append("ppp_collides_with_reserved")

    # 4. Proxy recognition — does the published chr_nodes[] include this node's
    #    derived wg_data_ip? This is the EXACT field the proxy looks up for the
    #    allowlist (see app/api/proxy_api.py routing_table()).
    entries = _routing_table_chr_entries()
    matching = next((e for e in entries if e.get("name") == node.name), None)
    proxy_recognised = bool(
        matching and matching.get("wg_data_ip") == data_ip and data_ok
    )
    rows.append(CheckRow(
        key="proxy_recognised",
        label_ar="هل يعرف الوكيل المركزي هذه العقدة؟",
        ok=proxy_recognised,
        value=(
            f"chr_nodes[]: wg_data_ip={matching['wg_data_ip']} (المصدر={matching['source']})"
            if matching else "العقدة غير منشورة في chr_nodes[]"
        ),
        detail_ar=(
            "" if proxy_recognised else
            "العقدة غير منشورة لـ /api/proxy/routing-table — تأكد من أن «enabled=نعم»، "
            "«drain=لا»، و«status≠disabled»."
        ),
        severity="ok" if proxy_recognised else "error",
    ))

    # 5. wg-mgmt KEY identity (panel ↔ CHR). Optional — needs creds.
    key_ok, key_code, key_msg = _try_wg_verify(node)
    if key_ok is None:
        # We don't have credentials / can't reach — surface as a warn, not a blocker:
        # the proxy can still accept RADIUS over wg-data even if mgmt is unreachable.
        rows.append(CheckRow(
            key="wg_mgmt_key",
            label_ar="تطابق مفتاح wg-mgmt (لوحة ↔ CHR)",
            ok=False,
            value=key_code,
            detail_ar=key_msg or "تعذّر تشغيل الفحص — اضبط بيانات API على العقدة ثم أعد التشغيل.",
            severity="warn",
        ))
    else:
        rows.append(CheckRow(
            key="wg_mgmt_key",
            label_ar="تطابق مفتاح wg-mgmt (لوحة ↔ CHR)",
            ok=key_ok,
            value=key_code,
            detail_ar=("" if key_ok else (key_msg or "المفاتيح لا تتطابق — راجع السكربت الصادر.")),
            severity="ok" if key_ok else "error",
        ))

    # 6. RADIUS reachability hint — derived from the above.
    if data_ok and proxy_recognised and not coll:
        radius_label = "Reject (لا timeout) — الوكيل يستقبل، عميل غير معروف يُرفض"
        radius_ok = True
        radius_detail = ""
    elif not data_ok:
        radius_label = "timeout — العنوان غير مشتق"
        radius_ok = False
        radius_detail = "أصلح صف wg-mgmt أعلاه أولاً."
    elif not proxy_recognised:
        radius_label = "unknown CHR IP — الوكيل يُسقط الحزمة"
        radius_ok = False
        radius_detail = "العقدة ليست في chr_nodes[] — راجع صف «هل يعرف الوكيل» أعلاه."
    else:
        radius_label = "تصادم محتمل — راجع التحذيرات أعلاه"
        radius_ok = False
        radius_detail = "تصادم PPP مع 10.98/10.99 — راجع صف PPP أعلاه."
    rows.append(CheckRow(
        key="radius_reachability",
        label_ar="السلوك المتوقّع لاختبار RADIUS من العقدة",
        ok=radius_ok,
        value=radius_label,
        detail_ar=radius_detail,
        severity="ok" if radius_ok else "warn",
    ))

    return NodeTroubleshootView(
        node_id=node.id or 0,
        name=node.name,
        public_ip=node.public_ip or "",
        wg_mgmt_ip=mgmt_ip,
        wg_data_ip=data_ip,
        proxy_recognised=proxy_recognised,
        wg_mgmt_key_ok=key_ok,
        rows=rows,
        blockers=blockers,
    )


def build_all_views() -> list[NodeTroubleshootView]:
    """Build the troubleshooting view for every fleet CHR (sorted by name)."""
    nodes = (
        FleetChrNode.query
        .order_by(FleetChrNode.name.asc())
        .all()
    )
    return [build_view(n) for n in nodes]


__all__ = [
    "CheckRow",
    "NodeTroubleshootView",
    "build_view",
    "build_all_views",
]
