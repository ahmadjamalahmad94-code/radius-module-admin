"""
Customer Secure Vault — admin routes (blueprint: admin_vault).

ADMIN-ONLY. Not reachable from the customer portal or any public/integration API.
Permission model (project has no granular roles, only Admin.is_super_admin):
  • view vault + private records + secret METADATA + manage records → any active admin
  • create/update/rotate/reveal/archive SECRETS → super_admin only

Every route checks permission server-side. The reveal endpoint returns plaintext
ONLY in its JSON response and writes an audit row; plaintext is never rendered
into a normal page and never logged.
"""
from __future__ import annotations

from flask import Blueprint, abort, flash, jsonify, redirect, render_template, request, session, url_for

from ..auth.routes import current_admin, login_required, super_admin_required
from ..extensions import db
from ..models import Customer
from ..services import customer_vault as vault
from ..services.customer_vault_crypto import encryption_available, mask_secret

bp = Blueprint("admin_vault", __name__, url_prefix="/admin/customers")


def _customer_or_404(customer_id: int) -> Customer:
    return db.get_or_404(Customer, customer_id)


def _actor_id():
    return session.get("admin_id")


def _back(customer_id: int, tab: str = ""):
    url = url_for("admin_vault.vault_home", customer_id=customer_id)
    return redirect(url + (f"#{tab}" if tab else ""))


# ───────────────────────── vault page (any active admin) ─────────────────────────

@bp.get("/<int:customer_id>/vault")
@login_required
def vault_home(customer_id: int):
    customer = _customer_or_404(customer_id)
    admin = current_admin()
    action_filter = (request.args.get("action") or "").strip()
    return render_template(
        "admin/customer_vault.html",
        customer=customer,
        records=vault.list_private_records(customer_id),
        secrets=vault.list_secret_metadata(customer_id),
        audit_logs=vault.list_vault_audit(customer_id, action=action_filter),
        action_filter=action_filter,
        encryption_ok=encryption_available(),
        can_manage_secrets=bool(getattr(admin, "is_super_admin", False)),
        mask_secret=mask_secret,
        record_types=sorted(vault.RECORD_TYPES),
        secret_types=sorted(vault.SECRET_TYPES),
    )


# ───────────────────────── private records (any active admin) ─────────────────────────

@bp.post("/<int:customer_id>/vault/records")
@login_required
def record_create(customer_id: int):
    _customer_or_404(customer_id)
    try:
        vault.create_private_record(customer_id, request.form, _actor_id())
        flash("تم حفظ البيان التشغيلي.", "success")
    except vault.VaultError as exc:
        flash(str(exc), "error")
    return _back(customer_id, "records")


@bp.post("/<int:customer_id>/vault/records/<int:record_id>/update")
@login_required
def record_update(customer_id: int, record_id: int):
    _customer_or_404(customer_id)
    try:
        vault.update_private_record(record_id, customer_id, request.form, _actor_id())
        flash("تم تحديث البيان.", "success")
    except vault.VaultError as exc:
        flash(str(exc), "error")
    return _back(customer_id, "records")


@bp.post("/<int:customer_id>/vault/records/<int:record_id>/archive")
@login_required
def record_archive(customer_id: int, record_id: int):
    _customer_or_404(customer_id)
    try:
        vault.archive_private_record(record_id, customer_id, _actor_id())
        flash("تمت أرشفة البيان.", "success")
    except vault.VaultError as exc:
        flash(str(exc), "error")
    return _back(customer_id, "records")


# ───────────────────────── secrets (super admin only) ─────────────────────────

@bp.post("/<int:customer_id>/vault/secrets")
@super_admin_required
def secret_create(customer_id: int):
    _customer_or_404(customer_id)
    try:
        vault.create_secret(customer_id, request.form,
                            request.form.get("secret_value") or "", _actor_id())
        flash("تم حفظ السر مشفّرًا.", "success")
    except vault.VaultError as exc:
        flash(str(exc), "error")
    return _back(customer_id, "secrets")


@bp.post("/<int:customer_id>/vault/secrets/<int:secret_id>/metadata")
@super_admin_required
def secret_metadata(customer_id: int, secret_id: int):
    _customer_or_404(customer_id)
    try:
        vault.update_secret_metadata(secret_id, customer_id, request.form, _actor_id())
        flash("تم تحديث بيانات السر.", "success")
    except vault.VaultError as exc:
        flash(str(exc), "error")
    return _back(customer_id, "secrets")


@bp.post("/<int:customer_id>/vault/secrets/<int:secret_id>/rotate")
@super_admin_required
def secret_rotate(customer_id: int, secret_id: int):
    _customer_or_404(customer_id)
    try:
        vault.rotate_secret(secret_id, customer_id,
                           request.form.get("secret_value") or "", _actor_id())
        flash("تم تدوير السر.", "success")
    except vault.VaultError as exc:
        flash(str(exc), "error")
    return _back(customer_id, "secrets")


@bp.post("/<int:customer_id>/vault/secrets/<int:secret_id>/archive")
@super_admin_required
def secret_archive(customer_id: int, secret_id: int):
    _customer_or_404(customer_id)
    try:
        vault.archive_secret(secret_id, customer_id, _actor_id())
        flash("تمت أرشفة السر.", "success")
    except vault.VaultError as exc:
        flash(str(exc), "error")
    return _back(customer_id, "secrets")


# Reveal — JSON only, super admin only, audited. Plaintext appears ONLY here.
@bp.post("/<int:customer_id>/vault/secrets/<int:secret_id>/reveal")
@super_admin_required
def secret_reveal(customer_id: int, secret_id: int):
    _customer_or_404(customer_id)
    reason = (request.form.get("reason") or "").strip()
    try:
        sec, plaintext = vault.reveal_secret(secret_id, customer_id, _actor_id(), reason=reason)
    except vault.VaultError as exc:
        return jsonify({"ok": False, "message": str(exc)}), 400
    return jsonify({
        "ok": True,
        "secret": plaintext,
        "masked": mask_secret(plaintext),
        "revealed_at": sec.last_revealed_at.isoformat() if sec.last_revealed_at else "",
        "label": sec.label,
    })
