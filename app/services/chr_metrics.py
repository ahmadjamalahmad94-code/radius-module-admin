"""جمع مقاييس عقد CHR المخصّصة وتخزينها في ChrNodeMetric.

يُنفَّذ من خلال أمر CLI ``flask collect-chr-metrics`` الذي يُجدول كل 5 دقائق
عبر systemd timer. لا يوجد وكيل مُنصَّب على CHR — لوحة التراخيص تسحب (pull)
البيانات مباشرةً عبر RouterOS REST API.

سياسة السرّ: كلمة مرور كل عقدة مشفّرة بـ Fernet في العمود ``routeros_password_enc``
ولا تظهر أبدًا في الـ logs أو الاستثناءات.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta
from decimal import Decimal
from typing import Any

from ..extensions import db
from ..models import ChrNode, ChrNodeMetric

log = logging.getLogger(__name__)

# عقدة لم تُرَ منذ أكثر من هذه المدة تُعدّ متأخّرة (stale)
STALE_MINUTES = 10


def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _build_client(node: ChrNode):
    """ينشئ RouterOSClient من بيانات العقدة. يُعيد None إذا تعذّر ذلك."""
    if not node.routeros_host or not node.routeros_user:
        return None
    if not node.routeros_password_enc:
        return None

    try:
        from .customer_vault_crypto import decrypt_secret, encryption_available
        if not encryption_available():
            log.warning("chr_metrics: vault encryption not configured — skipping node %s", node.name)
            return None
        password = decrypt_secret(node.routeros_password_enc)
    except Exception as exc:
        log.warning("chr_metrics: cannot decrypt password for node %s: %s", node.name, exc)
        return None

    from .routeros_client import RouterOSClient
    return RouterOSClient(
        host=node.routeros_host,
        port=node.routeros_port,
        username=node.routeros_user,
        password=password,
        use_tls=True,
        verify_tls=False,
        timeout=10,
    )


def _to_dec(val: Any, default: float = 0.0) -> Decimal:
    try:
        return Decimal(str(val))
    except Exception:
        return Decimal(str(default))


def _collect_one(node: ChrNode) -> ChrNodeMetric | None:
    """تسحب مقاييس عقدة واحدة وتُنشئ سجل ChrNodeMetric. تُعيد None عند الفشل."""
    client = _build_client(node)
    if client is None:
        return None

    from .routeros_client import RouterOSError

    # ── موارد النظام (CPU, RAM) ──────────────────────────────────────────────
    try:
        resource = client.system_resource()
        if isinstance(resource, list):
            resource = resource[0] if resource else {}
        cpu_pct = _to_dec(resource.get("cpu-load", 0))
        free_mem = int(resource.get("free-memory", 0))
        total_mem = int(resource.get("total-memory", 1)) or 1
        mem_pct = _to_dec(round((1 - free_mem / total_mem) * 100, 2))
    except RouterOSError as exc:
        log.warning("chr_metrics: system/resource failed for %s: %s", node.name, exc)
        return None
    except Exception as exc:
        log.warning("chr_metrics: unexpected error reading resources from %s: %s", node.name, exc)
        return None

    # ── حقائق الجهاز (نسخة/لوحة/uptime…) — كانت تُهمَل رغم أن RouterOS يعيدها
    # في نفس ردّ system/resource. تُخزَّن على العقدة لتظهر في صفحة التفاصيل.
    try:
        node.device_facts = {
            "version": str(resource.get("version", "") or ""),
            "board_name": str(resource.get("board-name", "") or ""),
            "platform": str(resource.get("platform", "") or ""),
            "architecture": str(resource.get("architecture-name", "") or ""),
            "cpu": str(resource.get("cpu", "") or ""),
            "cpu_count": str(resource.get("cpu-count", "") or ""),
            "total_memory_bytes": total_mem,
            "uptime": str(resource.get("uptime", "") or ""),
        }
    except Exception:  # facts هي إثراء فقط — لا تُفشِل القراءة
        pass

    # ── جلسات PPP النشطة ──────────────────────────────────────────────────────
    try:
        sessions = client.list_ppp_active()
        session_count = len(sessions) if sessions else 0
    except Exception:
        session_count = 0

    # ── حركة المرور من الواجهات ─────────────────────────────────────────────
    # نجمع بايت RX / TX لكل الواجهات التي ليست loopback/wireguard mgmt
    rx_total = 0
    tx_total = 0
    try:
        ifaces = client.list_interfaces()
        for iface in (ifaces or []):
            name = str(iface.get("name", ""))
            itype = str(iface.get("type", ""))
            # تجاهل loopback وتجاهل واجهات wg (mgmt) وبلاغات فارغة
            if name in ("lo",) or itype == "loopback":
                continue
            if name.startswith("wg") or name.startswith("wireguard"):
                continue
            rx_total += int(iface.get("rx-byte", 0) or 0)
            tx_total += int(iface.get("tx-byte", 0) or 0)
    except Exception:
        pass

    # ── معدّل Mbps من الفرق مع آخر قراءة ─────────────────────────────────────
    rx_mbps = Decimal("0")
    tx_mbps = Decimal("0")
    last_metric = (
        ChrNodeMetric.query
        .filter_by(chr_node_id=node.id)
        .order_by(ChrNodeMetric.measured_at.desc())
        .first()
    )
    now = _utcnow()
    if last_metric and last_metric.traffic_today_bytes and rx_total:
        elapsed_s = (now - last_metric.measured_at).total_seconds()
        if 0 < elapsed_s < 3600:  # فارق معقول (أقل من ساعة)
            rx_diff = max(0, rx_total - int(last_metric.traffic_today_bytes))
            tx_diff = max(0, tx_total - int(last_metric.traffic_month_bytes or 0))
            rx_mbps = _to_dec(round(rx_diff * 8 / elapsed_s / 1_000_000, 3))
            tx_mbps = _to_dec(round(tx_diff * 8 / elapsed_s / 1_000_000, 3))

    metric = ChrNodeMetric(
        chr_node_id=node.id,
        measured_at=now,
        current_rx_mbps=rx_mbps,
        current_tx_mbps=tx_mbps,
        active_sessions=session_count,
        cpu_percent=cpu_pct,
        memory_percent=mem_pct,
        # نستعمل traffic_today_bytes / traffic_month_bytes لحفظ raw counters
        # لحساب الفارق في القراءة القادمة
        traffic_today_bytes=rx_total,
        traffic_month_bytes=tx_total,
    )
    node.last_seen_at = now
    # ترقية تلقائية: استطلاع ناجح يعني أن العقدة موصولة وتستجيب — عقدة «قيد
    # التهيئة» (pending) تصبح «نشطة» تلقائيًا بدل أن تعلق على pending للأبد
    # رغم أنها ترسل قياسات حيّة. (maintenance/decommissioned لا تُمَسّ.)
    if node.status == "pending":
        node.status = "active"
        log.info("chr_metrics: node %s auto-promoted pending → active after successful poll", node.name)
    return metric


def collect_all_nodes() -> dict[str, int]:
    """تجمع مقاييس كل العقد النشطة وتحفظها في DB.

    تُعيد ملخّص ``{"polled": N, "ok": N, "skipped": N, "errors": N}``.
    """
    # تشمل العقد «قيد التهيئة» أيضًا: عقدة pending مكتملة البيانات لم تكن
    # تُستطلَع أبدًا (الفلتر كان active فقط) فلا شيء يرقّيها إلى active —
    # فتعلق على «قيد التهيئة» للأبد رغم أنها تعمل. الآن تُستطلَع، وعند أول
    # نجاح يرقّيها _collect_one تلقائيًا.
    nodes = ChrNode.query.filter(ChrNode.status.in_(("active", "pending"))).all()
    summary = {"polled": len(nodes), "ok": 0, "skipped": 0, "errors": 0}

    for node in nodes:
        if not node.routeros_host:
            summary["skipped"] += 1
            continue
        try:
            metric = _collect_one(node)
            if metric is None:
                summary["skipped"] += 1
            else:
                db.session.add(metric)
                db.session.commit()
                summary["ok"] += 1
        except Exception as exc:
            db.session.rollback()
            log.error("chr_metrics: failed for node %s: %s", node.name, exc)
            summary["errors"] += 1

    # تنظيف القراءات القديمة: احتفظ فقط بآخر 1000 قراءة لكل عقدة
    try:
        for node in nodes:
            _prune_old_metrics(node.id, keep=1000)
        db.session.commit()
    except Exception:
        db.session.rollback()

    return summary


def _prune_old_metrics(node_id: int, keep: int = 1000) -> None:
    """يحذف القراءات الزائدة ويبقي آخر ``keep`` قراءة للعقدة."""
    subq = (
        db.session.query(ChrNodeMetric.id)
        .filter(ChrNodeMetric.chr_node_id == node_id)
        .order_by(ChrNodeMetric.measured_at.desc())
        .limit(keep)
        .subquery()
    )
    db.session.query(ChrNodeMetric).filter(
        ChrNodeMetric.chr_node_id == node_id,
        ChrNodeMetric.id.notin_(subq),
    ).delete(synchronize_session=False)


def is_stale(node: ChrNode) -> bool:
    """True إذا لم تُرَ العقدة منذ أكثر من STALE_MINUTES دقيقة."""
    if node.last_seen_at is None:
        return False  # لم تُستطلَع بعد — لا نعتبرها stale
    threshold = _utcnow() - timedelta(minutes=STALE_MINUTES)
    return node.last_seen_at < threshold
