from __future__ import annotations

from flask import Flask

from .config import Config
from .extensions import db
from .models import Admin


class BootstrapError(RuntimeError):
    pass


WEAK_ADMIN_PASSWORDS = {
    "",
    Config.DEFAULT_ADMIN_PASSWORD,
    "change-this-password",
    "admin",
    "password",
}


def is_production(app: Flask) -> bool:
    return str(app.config.get("LICENSE_PANEL_ENV", "")).strip().lower() in {"prod", "production"}


def bootstrap_admin_from_config(app: Flask, *, fail_if_exists: bool) -> Admin | None:
    existing = Admin.query.first()
    if existing:
        if fail_if_exists:
            raise BootstrapError("An admin already exists; refusing to bootstrap again.")
        return None

    username = str(app.config.get("ADMIN_USERNAME") or "").strip()
    password = str(app.config.get("ADMIN_PASSWORD") or "")
    email = str(app.config.get("ADMIN_EMAIL") or "").strip()

    if not username:
        raise BootstrapError("Admin username is required.")
    if not password:
        raise BootstrapError("Admin password is required.")
    if is_production(app) and password in WEAK_ADMIN_PASSWORDS:
        raise BootstrapError("Production bootstrap requires a strong non-default admin password.")

    admin = Admin(
        username=username,
        full_name="License Admin",
        email=email,
        active=True,
    )
    admin.set_password(password)
    db.session.add(admin)
    return admin
