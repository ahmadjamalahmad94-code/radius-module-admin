"""Product apps + downloadable releases — service layer.

The public landing "Downloads" section lists every visible product app with its
CURRENT Windows + Android release. Admins upload binaries (.exe/.msi for Windows,
.apk/.aab for Android) per app + channel and mark one as current. Binaries are
stored on disk under ``instance_path/app_releases/<slug>/<platform>/<channel>/``;
only metadata (version, sha256, size, filename) lives in the DB.

All OS/file work is isolated here so the routes stay thin and the logic is
unit-testable. Extensions are validated against a per-platform allowlist.
"""
from __future__ import annotations

import hashlib
import re
import shutil
from pathlib import Path
from typing import Optional

from flask import current_app

from ..extensions import db
from ..models import AppProduct, AppRelease, Setting

# ── domain constants ─────────────────────────────────────────────────────────
PLATFORMS = ("windows", "android")
CHANNELS = ("stable", "beta")

#: Allowed upload extensions per platform (lowercase, with dot).
ALLOWED_EXT_BY_PLATFORM: dict[str, set[str]] = {
    "windows": {".exe", ".msi"},
    "android": {".apk", ".aab"},
}

#: Hard cap on a single uploaded binary (500 MB) — generous for desktop installers.
MAX_UPLOAD_BYTES = 500 * 1024 * 1024

#: Content-types we tag stored files with (best-effort; download forces attachment).
_CONTENT_TYPE_BY_EXT = {
    ".exe": "application/vnd.microsoft.portable-executable",
    ".msi": "application/x-msi",
    ".apk": "application/vnd.android.package-archive",
    ".aab": "application/octet-stream",
}

#: Setting key for the externally-hosted Card-Print store URL (CMS-editable).
CARDPRINT_URL_SETTING = "landing.cardprint_url"

_SLUG_RE = re.compile(r"[^a-z0-9-]+")


class AppReleaseError(ValueError):
    """Raised on a rejected upload (bad extension, too big, bad input)."""


# ── storage ───────────────────────────────────────────────────────────────--
def releases_root() -> Path:
    root = Path(current_app.instance_path) / "app_releases"
    root.mkdir(parents=True, exist_ok=True)
    return root


def _release_dir(product: AppProduct, platform: str, channel: str) -> Path:
    d = releases_root() / product.slug / platform / channel
    d.mkdir(parents=True, exist_ok=True)
    return d


# ── helpers ─────────────────────────────────────────────────────────────────
def slugify(value: str) -> str:
    s = _SLUG_RE.sub("-", (value or "").strip().lower()).strip("-")
    return s or "app"


def file_ext(filename: str) -> str:
    """Lowercase extension incl. dot (e.g. ".apk"); "" when none."""
    name = (filename or "").strip().lower()
    dot = name.rfind(".")
    return name[dot:] if dot >= 0 else ""


def validate_extension(platform: str, filename: str) -> str:
    """Return the validated lowercase extension or raise AppReleaseError."""
    if platform not in ALLOWED_EXT_BY_PLATFORM:
        raise AppReleaseError(f"منصة غير معروفة: {platform}")
    ext = file_ext(filename)
    allowed = ALLOWED_EXT_BY_PLATFORM[platform]
    if ext not in allowed:
        pretty = " أو ".join(sorted(allowed))
        raise AppReleaseError(
            f"امتداد الملف «{ext or '—'}» غير مسموح لمنصة {platform}. المسموح: {pretty}.")
    return ext


def human_size(n: int) -> str:
    """Human-readable size for the public download button."""
    size = float(n or 0)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} GB"


# ── product CRUD ──────────────────────────────────────────────────────────--
def list_products() -> list[AppProduct]:
    return (AppProduct.query
            .order_by(AppProduct.sort_order.asc(), AppProduct.id.asc()).all())


def visible_products() -> list[AppProduct]:
    return [p for p in list_products() if p.is_visible]


def get_product(pid: int) -> Optional[AppProduct]:
    return db.session.get(AppProduct, pid)


def upsert_product(*, product: Optional[AppProduct], name: str, slug: str,
                   description: str = "", icon_name: str = "", sort_order: int = 100,
                   is_visible: bool = True) -> AppProduct:
    name = (name or "").strip()
    if not name:
        raise AppReleaseError("اسم التطبيق مطلوب.")
    slug = slugify(slug or name)
    # Enforce slug uniqueness (excluding self).
    clash = AppProduct.query.filter_by(slug=slug).first()
    if clash and (product is None or clash.id != product.id):
        raise AppReleaseError(f"المُعرّف «{slug}» مستخدم لتطبيق آخر.")
    if product is None:
        product = AppProduct(slug=slug)
        db.session.add(product)
    product.name = name[:160]
    product.slug = slug
    product.description = (description or "").strip()
    product.icon_name = (icon_name or "").strip()[:60]
    product.sort_order = int(sort_order or 100)
    product.is_visible = bool(is_visible)
    db.session.flush()
    return product


def delete_product(product: AppProduct) -> None:
    """Delete the product, its release rows, and their stored files."""
    for rel in product.releases.all():
        _delete_release_file(rel)
    # Best-effort: remove the now-empty product storage dir.
    slug_dir = releases_root() / product.slug
    if slug_dir.exists():
        shutil.rmtree(slug_dir, ignore_errors=True)
    db.session.delete(product)
    db.session.flush()


# ── release upload / current / delete ─────────────────────────────────────--
def create_release(*, product: AppProduct, platform: str, channel: str, version: str,
                   filename: str, content: bytes, set_current: bool = True,
                   admin_id: Optional[int] = None) -> AppRelease:
    """Validate + store an uploaded binary and create its release row.

    Raises AppReleaseError on bad platform/channel/extension/size/empty content.
    """
    if platform not in PLATFORMS:
        raise AppReleaseError(f"منصة غير معروفة: {platform}")
    if channel not in CHANNELS:
        raise AppReleaseError(f"قناة غير معروفة: {channel}")
    version = (version or "").strip()
    if not version:
        raise AppReleaseError("رقم الإصدار مطلوب.")
    ext = validate_extension(platform, filename)
    if not content:
        raise AppReleaseError("الملف فارغ.")
    if len(content) > MAX_UPLOAD_BYTES:
        raise AppReleaseError(f"الملف أكبر من الحد المسموح ({human_size(MAX_UPLOAD_BYTES)}).")

    sha = hashlib.sha256(content).hexdigest()
    stored = f"{platform}-{channel}-{version}-{sha[:12]}{ext}"
    stored = re.sub(r"[^A-Za-z0-9.\-]", "_", stored)
    target = _release_dir(product, platform, channel) / stored
    target.write_bytes(content)

    rel = AppRelease(
        product_id=product.id, platform=platform, channel=channel, version=version,
        file_ext=ext, original_filename=(filename or "")[:255], stored_filename=stored,
        size_bytes=len(content), sha256=sha,
        content_type=_CONTENT_TYPE_BY_EXT.get(ext, "application/octet-stream"),
        created_by=admin_id, is_current=False,
    )
    db.session.add(rel)
    db.session.flush()
    if set_current:
        set_current_release(rel)
    return rel


def validate_external_url(url: str) -> str:
    """Return a safe external download URL (http/https only) or raise."""
    u = (url or "").strip()
    if not u:
        raise AppReleaseError("رابط التنزيل مطلوب.")
    if not u.lower().startswith(("http://", "https://")):
        raise AppReleaseError("رابط التنزيل يجب أن يبدأ بـ http:// أو https://.")
    return u[:600]


def create_url_release(*, product: AppProduct, platform: str, channel: str, version: str,
                       download_url: str, sha256: str = "", set_current: bool = True,
                       admin_id: Optional[int] = None) -> AppRelease:
    """Create a release that links to an EXTERNAL url instead of a hosted file.

    For binaries too large to upload through the panel (e.g. 50+ MB APKs on a
    GitHub release). No file is stored; ``download_url`` is the source of truth.
    ``sha256`` is optional (display-only). Raises on bad platform/channel/url.
    """
    if platform not in PLATFORMS:
        raise AppReleaseError(f"منصة غير معروفة: {platform}")
    if channel not in CHANNELS:
        raise AppReleaseError(f"قناة غير معروفة: {channel}")
    version = (version or "").strip()
    if not version:
        raise AppReleaseError("رقم الإصدار مطلوب.")
    url = validate_external_url(download_url)
    ext = file_ext(url.split("?")[0])  # best-effort, for display only

    rel = AppRelease(
        product_id=product.id, platform=platform, channel=channel, version=version,
        file_ext=ext if ext in {e for exts in ALLOWED_EXT_BY_PLATFORM.values() for e in exts} else "",
        download_url=url, stored_filename="", size_bytes=0,
        sha256=(sha256 or "").strip().lower()[:64],
        content_type=_CONTENT_TYPE_BY_EXT.get(ext, ""),
        created_by=admin_id, is_current=False,
    )
    db.session.add(rel)
    db.session.flush()
    if set_current:
        set_current_release(rel)
    return rel


def set_current_release(release: AppRelease) -> None:
    """Mark ``release`` current for its (product, platform, channel) and clear
    the flag on every sibling — exactly one current per combo."""
    siblings = AppRelease.query.filter_by(
        product_id=release.product_id, platform=release.platform, channel=release.channel,
    ).all()
    for s in siblings:
        s.is_current = (s.id == release.id)
    db.session.flush()


def current_release(product: AppProduct, platform: str, channel: str = "stable") -> Optional[AppRelease]:
    return (AppRelease.query
            .filter_by(product_id=product.id, platform=platform, channel=channel, is_current=True)
            .order_by(AppRelease.id.desc()).first())


def _delete_release_file(release: AppRelease) -> None:
    try:
        if release.stored_filename and release.product is not None:
            path = (_release_dir(release.product, release.platform, release.channel)
                    / release.stored_filename)
            if path.exists():
                path.unlink()
    except OSError:
        pass


def delete_release(release: AppRelease) -> None:
    _delete_release_file(release)
    db.session.delete(release)
    db.session.flush()


def get_release_file(release: AppRelease) -> Optional[tuple[Path, str]]:
    """(absolute path, download filename) or None when the file is missing."""
    if release is None or release.product is None or not release.stored_filename:
        return None
    path = _release_dir(release.product, release.platform, release.channel) / release.stored_filename
    if not path.exists():
        return None
    base = slugify(release.product.slug)
    download_name = f"{base}-{release.version}-{release.platform}{release.file_ext}"
    return path, download_name


# ── public downloads view ─────────────────────────────────────────────────--
def public_downloads(channel: str = "stable") -> list[dict]:
    """Visible products with their current Windows/Android releases for the
    public landing. Each entry: ``{product, windows, android, has_any}``."""
    out: list[dict] = []
    for product in visible_products():
        win = current_release(product, "windows", channel)
        andr = current_release(product, "android", channel)
        out.append({
            "product": product,
            "windows": win,
            "android": andr,
            "has_any": bool(win or andr),
        })
    return out


def has_any_downloads(channel: str = "stable") -> bool:
    return any(d["has_any"] for d in public_downloads(channel))


# ── Card-Print store URL (CMS setting) ─────────────────────────────────────--
def get_cardprint_url() -> str:
    row = db.session.get(Setting, CARDPRINT_URL_SETTING)
    return (row.value or "").strip() if row else ""


def set_cardprint_url(url: str) -> str:
    """Persist the externally-hosted Card-Print store URL. Rejects unsafe
    schemes; empty clears it. Returns the stored value."""
    u = (url or "").strip()
    low = u.lower()
    if u and low.startswith(("javascript:", "data:", "vbscript:")):
        raise AppReleaseError("الرابط غير آمن.")
    if u and not (low.startswith(("http://", "https://", "/")) or low.startswith("#")):
        raise AppReleaseError("الرابط يجب أن يبدأ بـ http:// أو https:// أو /.")
    row = db.session.get(Setting, CARDPRINT_URL_SETTING)
    if row is None:
        row = Setting(key=CARDPRINT_URL_SETTING)
        db.session.add(row)
    row.value = u
    db.session.flush()
    return u


# ── seed: the two shipped Android apps (external GitHub release URLs) ───────--
#: (slug, name, icon, version, download_url, sha256). APKs are 50+ MB so they
#: are hosted on public GitHub releases, not uploaded through the panel.
_SEED_ANDROID_APPS = [
    {
        "slug": "radius_app",
        "name": "تطبيق الريدياس",
        "icon_name": "wifi",
        "version": "v0.1.0-test",
        "download_url": "https://github.com/ahmadjamalahmad94-code/radius-module-app-releases/"
                        "releases/download/v0.1.0-test/radius-app.apk",
        "sha256": "f44a34ac2de99b953aececd64bd6c0247010a1e4ac7808a60d83d879c85c343f",
    },
    {
        "slug": "card_print_app",
        "name": "تطبيق طباعة الكروت",
        "icon_name": "id-card",
        "version": "v0.1.0-test",
        "download_url": "https://github.com/ahmadjamalahmad94-code/card-print-store-releases/"
                        "releases/download/v0.1.0-test/app-release.apk",
        "sha256": "",  # optional — left blank (not computed offline)
    },
]


def seed_download_apps() -> None:
    """Idempotently create the two shipped Android apps + their current
    external-URL releases so the public Downloads section is populated after a
    deploy with no manual upload.

    Safe to re-run: a product is created only when its slug is absent (existing
    products are NOT clobbered), and a release is created only when no release
    with the same download_url already exists for that product.
    """
    changed = False
    for i, spec in enumerate(_SEED_ANDROID_APPS):
        product = AppProduct.query.filter_by(slug=spec["slug"]).first()
        if product is None:
            product = AppProduct(slug=spec["slug"], name=spec["name"],
                                 icon_name=spec["icon_name"], sort_order=(i + 1) * 10,
                                 is_visible=True)
            db.session.add(product)
            db.session.flush()
            changed = True
        # Already have this exact external release? then nothing to do.
        exists = AppRelease.query.filter_by(
            product_id=product.id, download_url=spec["download_url"]).first()
        if exists is None:
            create_url_release(
                product=product, platform="android", channel="stable",
                version=spec["version"], download_url=spec["download_url"],
                sha256=spec["sha256"], set_current=True)
            changed = True
    if changed:
        db.session.commit()


__all__ = [
    "PLATFORMS", "CHANNELS", "ALLOWED_EXT_BY_PLATFORM", "MAX_UPLOAD_BYTES",
    "CARDPRINT_URL_SETTING", "AppReleaseError",
    "releases_root", "slugify", "file_ext", "validate_extension", "validate_external_url",
    "human_size",
    "list_products", "visible_products", "get_product", "upsert_product", "delete_product",
    "create_release", "create_url_release", "set_current_release", "current_release",
    "delete_release", "get_release_file", "public_downloads", "has_any_downloads",
    "get_cardprint_url", "set_cardprint_url", "seed_download_apps",
]
