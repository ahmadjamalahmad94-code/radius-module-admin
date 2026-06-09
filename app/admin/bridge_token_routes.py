"""Admin bridge-token surface — super-admin rotate + read.

POST /admin/customers/<id>/bridge-token/rotate
    Super-admin-only. Generates a fresh per-license bridge token, bumps
    its version, and returns the plaintext ONCE in the response (same
    pattern as the existing activation-token endpoint). The customer's
    radius-module picks up the new value on its next runtime-contract
    poll — convergence is automatic.

GET /admin/customers/<id>/bridge-token
    Super-admin-only. Returns a safe summary (no plaintext): version,
    fingerprint prefix, rotated_at, rotated_by, last_seen_at. Used by
    the customer-360 page to show "current bridge key" without ever
    exposing the secret.

Why a separate blueprint?
    Keeps file-ownership boundaries clean for parallel work and avoids
    enlarging the already-busy ``app/admin/routes.py``. Registered
    additively in ``app/__init__.py``.
"""

from __future__ import annotations

import logging

from flask import Blueprint, jsonify

from ..auth.routes import audit, current_admin, super_admin_required
from ..extensions import db
from ..models import Customer, License
from ..services.bridge_token_sync import (
    BridgeTokenError,
    rotate_token,
    serialize_for_admin,
)


logger = logging.getLogger(__name__)

bp = Blueprint("admin_bridge_token", __name__, url_prefix="/admin/customers")


def _pick_active_license(customer: Customer) -> License | None:
    """Same choice the activation flow uses: most recent license row."""
    return (
        License.query.filter_by(customer_id=customer.id)
        .order_by(License.created_at.desc())
        .first()
    )


@bp.get("/<int:customer_id>/bridge-token")
@super_admin_required
def get_bridge_token(customer_id: int):
    """Safe (no plaintext) summary of the current per-license bridge token."""
    customer = db.get_or_404(Customer, customer_id)
    lic = _pick_active_license(customer)
    if lic is None:
        return jsonify({"ok": True, "exists": False}), 200
    return jsonify({"ok": True, **serialize_for_admin(lic)}), 200


@bp.post("/<int:customer_id>/bridge-token/rotate")
@super_admin_required
def rotate_bridge_token(customer_id: int):
    """Rotate the bridge token for the customer's active license.

    Returns the plaintext exactly once. The audit row records only the
    fingerprint + version + actor admin id — never the plaintext.
    """
    customer = db.get_or_404(Customer, customer_id)
    lic = _pick_active_license(customer)
    if lic is None:
        return jsonify({"ok": False, "status": "no_license",
                        "message": "لا يوجد ترخيص مرتبط بهذا العميل."}), 404

    try:
        result = rotate_token(lic, actor="panel")
    except BridgeTokenError as exc:
        # Vault key missing / configuration error. Never returns plaintext.
        return jsonify({"ok": False, "status": exc.code, "message": exc.message}), 503

    admin = current_admin()
    audit(
        "bridge_token_rotate", "license", str(lic.id),
        f"تدوير مفتاح الجسر للعميل {customer.company_name} (v={result.version})",
        {
            "license_id": lic.id,
            "customer_id": customer.id,
            "version": result.version,
            "fingerprint_prefix": result.fingerprint[:8],
            "actor_admin_id": (admin.id if admin else None),
        },
    )
    db.session.commit()

    logger.info(
        "bridge_token: admin rotate license_id=%s v=%s fp=%s admin=%s",
        lic.id, result.version, result.fingerprint[:8],
        (admin.id if admin else "?"),
    )

    return jsonify({
        "ok": True,
        "status": "rotated",
        "license_key": lic.license_key,
        "token": result.plaintext,                   # ONE-TIME plaintext.
        "version": result.version,
        "fingerprint": result.fingerprint,
        "fingerprint_prefix": result.fingerprint[:8],
        "rotated_at": result.rotated_at.isoformat() + "Z",
        "rotated_by": result.rotated_by,
    }), 200


__all__ = ["bp"]
