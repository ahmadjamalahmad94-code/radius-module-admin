"""تطبيق انتهاء صلاحية ServiceAllocation على جانب لوحة التراخيص.

الأوضاع:
  flask enforce-allocations                          ← dry-run (الافتراضي — بدون كتابة)
  flask enforce-allocations --apply                  ← تطبيق فعلي
  flask enforce-allocations --apply --customer-id 5  ← تطبيق محدود لعميل واحد

ما يفعله:
  1. يُعيَّر ServiceAllocation.expires_at < utcnow → status='expired'
  2. يُدقّق كل عملية في AuditLog

قواعد:
  - ServiceAllocation تُنشأ من المدير فقط — هذا المُنفّذ يقرأها فقط
  - idempotent: تجاهل التخصيصات التي هي منتهية أصلاً (status='active' فقط)
  - عزل الأخطاء: فشل تخصيص واحد لا يوقف البقية — يُسجَّل ويُتابع
  - في وضع dry-run: لا يُكتب شيء، لا يُعدَّل، لا يُرسَل
  - جميع الكتابات عبر SQLAlchemy session مع commit واحد في النهاية
  - --customer-id: يحدّ النطاق لعميل واحد (للمراجعة أو الإصلاح اليدوي)
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

_LOG = logging.getLogger(__name__)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)  # naive UTC كما تُخزَّن في DB


def run(
    dry_run: bool = True,
    customer_id: int | None = None,
) -> dict[str, Any]:
    """نقطة الدخول الرئيسية.

    المعاملات:
        dry_run:     True (default) — احسب ما سيتغيّر دون كتابة أي شيء.
                     False         — طبِّق التغييرات فعليًا (--apply في CLI).
        customer_id: None (default) — جميع العملاء.
                     int           — عميل محدد فقط (--customer-id في CLI).

    يُعيد:
    {
        allocations_expired: int,
        dry_run: bool,
        customer_id: int | None,
        errors: int,              # موجود فقط إذا وجدت أخطاء معزولة
        error: str,               # موجود فقط عند خطأ فادح
    }
    """
    results: dict[str, Any] = {
        "allocations_expired": 0,
        "dry_run": dry_run,
        "customer_id": customer_id,
    }
    mode = "DRY-RUN" if dry_run else "APPLY"

    try:
        from ..extensions import db
        from ..models import AuditLog, ServiceAllocation

        now = _utcnow()

        query = ServiceAllocation.query.filter(
            ServiceAllocation.status == "active",
            ServiceAllocation.expires_at.isnot(None),
            ServiceAllocation.expires_at < now,
        )
        if customer_id is not None:
            query = query.filter(ServiceAllocation.customer_id == customer_id)

        expired_allocs = query.all()

        for alloc in expired_allocs:
            try:
                if dry_run:
                    _LOG.info(
                        "[DRY-RUN] would expire allocation id=%d "
                        "customer_id=%d service_type=%s expires_at=%s",
                        alloc.id,
                        alloc.customer_id,
                        alloc.service_type,
                        alloc.expires_at,
                    )
                    results["allocations_expired"] += 1
                    continue

                alloc.status = "expired"
                audit = AuditLog(
                    entity_type="service_allocation",
                    entity_id=str(alloc.id),
                    action="expire",
                    summary=(
                        f"انتهت صلاحية التخصيص #{alloc.id} "
                        f"(عميل #{alloc.customer_id}, نوع: {alloc.service_type}) "
                        f"تلقائيًا — expires_at={alloc.expires_at}"
                    ),
                )
                db.session.add(audit)
                results["allocations_expired"] += 1
                _LOG.info(
                    "allocation_enforcer [APPLY]: expired id=%d "
                    "customer_id=%d service_type=%s",
                    alloc.id,
                    alloc.customer_id,
                    alloc.service_type,
                )

            except Exception as exc:  # noqa: BLE001
                _LOG.error(
                    "allocation_enforcer: error processing allocation id=%d: %s",
                    alloc.id, exc, exc_info=True,
                )
                results["errors"] = results.get("errors", 0) + 1

        # Commit هنا فقط عند التطبيق الفعلي وعند وجود تغييرات
        if not dry_run and results["allocations_expired"] > 0:
            db.session.commit()
            _LOG.info(
                "allocation_enforcer [APPLY]: committed %d expiry(ies)",
                results["allocations_expired"],
            )
        elif dry_run:
            _LOG.info(
                "allocation_enforcer [DRY-RUN]: would expire %d allocation(s) "
                "— no changes written",
                results["allocations_expired"],
            )

    except Exception as exc:  # noqa: BLE001
        _LOG.error(
            "allocation_enforcer: unhandled error: %s", exc, exc_info=True
        )
        try:
            from ..extensions import db as _db
            _db.session.rollback()
        except Exception:  # noqa: BLE001
            pass
        results["error"] = str(exc)

    _LOG.info("allocation_enforcer [%s]: done %s", mode, results)
    return results


__all__ = ["run"]
