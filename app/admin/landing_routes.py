"""
Admin Landing Page CMS — isolated blueprint (admin_landing, /admin/landing).

Lets admins edit/enable/disable/reorder every public landing block: page meta,
sections, items, social links, contact methods. Immediate-save model.

Security: every route is @login_required; CSRF enforced by the app before_request;
user text is escaped on render (Jinja autoescape); URLs are validated/sanitised.
Edits are recorded via audit().
"""
from __future__ import annotations

from flask import Blueprint, flash, redirect, render_template, request, url_for

from ..auth.routes import audit, login_required
from ..extensions import db
from ..models import (
    AppRelease,
    LandingContactMethod,
    LandingItem,
    LandingPage,
    LandingSection,
    LandingSocialLink,
    utcnow,
)
from ..services.landing_cms import (
    HOME_SLUG,
    ITEM_STATUS_BADGES,
    all_items,
    all_sections,
    get_homepage,
)

bp = Blueprint("admin_landing", __name__, url_prefix="/admin/landing")

_ALLOWED_URL_PREFIXES = ("http://", "https://", "/", "#", "tel:", "mailto:", "wa.me", "https://wa.me")


def _s(name: str, default: str = "") -> str:
    return (request.form.get(name) or default).strip()


def _i(name: str, default: int = 0) -> int:
    try:
        return int(request.form.get(name) or default)
    except (TypeError, ValueError):
        return default


def _flag(name: str) -> bool:
    return bool(request.form.get(name))


def _safe_url(raw: str) -> str:
    """Allow only safe URL shapes; reject javascript:/data: etc."""
    u = (raw or "").strip()
    if not u:
        return ""
    low = u.lower()
    if low.startswith(("javascript:", "data:", "vbscript:")):
        return ""
    if u.startswith(_ALLOWED_URL_PREFIXES):
        return u
    # bare value (e.g. phone number) — keep as-is, escaped on render
    return u


def _home() -> LandingPage:
    page = get_homepage()
    if page is None:  # pragma: no cover - seeded at startup
        page = LandingPage(slug=HOME_SLUG, title="HobeRadius", status="draft", is_homepage=True)
        db.session.add(page)
        db.session.commit()
    return page


def _move(siblings: list, obj, direction: str) -> None:
    """Swap sort_order with the previous/next sibling."""
    ordered = sorted(siblings, key=lambda x: (x.sort_order, x.id))
    idx = next((i for i, x in enumerate(ordered) if x.id == obj.id), None)
    if idx is None:
        return
    swap = idx - 1 if direction == "up" else idx + 1
    if swap < 0 or swap >= len(ordered):
        return
    a, b = ordered[idx], ordered[swap]
    a.sort_order, b.sort_order = b.sort_order, a.sort_order


# ════════════════════════════ OVERVIEW ════════════════════════════

@bp.get("/")
@login_required
def overview():
    page = _home()
    sections = all_sections(page)
    visible = [s for s in sections if s.is_visible]
    return render_template(
        "admin/landing/overview.html",
        page=page, sections=sections,
        visible_count=len(visible), hidden_count=len(sections) - len(visible),
        social_count=LandingSocialLink.query.count(),
        contact_count=LandingContactMethod.query.count(),
    )


@bp.get("/preview")
@login_required
def preview():
    """Render the public landing page for admins WITHOUT the dashboard redirect.
    Shows the home page even if it is still a draft, so admins can preview edits."""
    from ..services.landing_cms import build_public_context
    page = _home()
    ctx = build_public_context(page)
    ctx["is_preview"] = True
    return render_template("public/landing.html", **ctx)


@bp.post("/page")
@login_required
def page_update():
    page = _home()
    page.title = _s("title", page.title)
    page.seo_title = _s("seo_title")
    page.seo_description = _s("seo_description")
    page.seo_keywords = _s("seo_keywords")
    page.og_image_url = _safe_url(_s("og_image_url"))
    status = _s("status", page.status)
    if status in {"draft", "published", "archived"}:
        if status == "published" and page.status != "published":
            page.published_at = utcnow()
        page.status = status
    audit("landing_page_updated", "landing_page", str(page.id), f"Updated landing page ({page.status})")
    db.session.commit()
    flash("تم حفظ إعدادات الصفحة. أي تعديل يظهر مباشرة في الصفحة العامة.", "success")
    return redirect(url_for("admin_landing.overview"))


# ════════════════════════════ SECTIONS ════════════════════════════

def _fill_section(sec: LandingSection) -> None:
    sec.eyebrow_text = _s("eyebrow_text")
    sec.title = _s("title")
    sec.subtitle = _s("subtitle")
    sec.description = _s("description")
    sec.badge_text = _s("badge_text")
    sec.primary_button_text = _s("primary_button_text")
    sec.primary_button_url = _safe_url(_s("primary_button_url"))
    sec.secondary_button_text = _s("secondary_button_text")
    sec.secondary_button_url = _safe_url(_s("secondary_button_url"))
    sec.image_url = _safe_url(_s("image_url"))
    sec.icon_name = _s("icon_name")
    note = _s("note")
    settings = sec.settings
    if note:
        settings["note"] = note
    elif "note" in settings:
        settings.pop("note")
    sec.settings = settings


@bp.get("/sections/<int:sid>")
@login_required
def section_edit(sid: int):
    sec = db.get_or_404(LandingSection, sid)
    return render_template("admin/landing/section_form.html", sec=sec)


@bp.post("/sections/<int:sid>")
@login_required
def section_update(sid: int):
    sec = db.get_or_404(LandingSection, sid)
    _fill_section(sec)
    audit("landing_section_updated", "landing_section", str(sec.id), f"Updated section {sec.section_key}")
    db.session.commit()
    flash("تم حفظ القسم.", "success")
    return redirect(url_for("admin_landing.overview"))


@bp.post("/sections/<int:sid>/toggle")
@login_required
def section_toggle(sid: int):
    sec = db.get_or_404(LandingSection, sid)
    sec.is_visible = not sec.is_visible
    audit("landing_section_toggled", "landing_section", str(sec.id),
          f"{'Shown' if sec.is_visible else 'Hidden'} section {sec.section_key}")
    db.session.commit()
    flash("تم تحديث ظهور القسم.", "success")
    return redirect(url_for("admin_landing.overview"))


@bp.post("/sections/<int:sid>/move")
@login_required
def section_move(sid: int):
    sec = db.get_or_404(LandingSection, sid)
    _move(all_sections(sec.page), sec, _s("dir", "up"))
    db.session.commit()
    return redirect(url_for("admin_landing.overview"))


# ════════════════════════════ ITEMS ════════════════════════════

def _fill_item(it: LandingItem) -> None:
    it.title = _s("title")
    it.subtitle = _s("subtitle")
    it.description = _s("description")
    it.value_text = _s("value_text")
    it.label_text = _s("label_text")
    it.icon_name = _s("icon_name")
    it.image_url = _safe_url(_s("image_url"))
    it.button_text = _s("button_text")
    it.button_url = _safe_url(_s("button_url"))
    it.badge_text = _s("badge_text")
    badge = _s("status_badge")
    it.status_badge = badge if badge in ITEM_STATUS_BADGES else ""
    it.price_text = _s("price_text")
    it.old_price_text = _s("old_price_text")
    it.period_text = _s("period_text")
    # features: textarea, one per line
    feats_raw = request.form.get("features") or ""
    feats = [ln.strip() for ln in feats_raw.splitlines() if ln.strip()]
    it.features = feats
    # category / column live in settings
    settings = it.settings
    cat = _s("category")
    col = _s("column")
    if cat:
        settings["category"] = cat
    if col:
        settings["column"] = col
    it.settings = settings


@bp.get("/sections/<int:sid>/items")
@login_required
def items(sid: int):
    sec = db.get_or_404(LandingSection, sid)
    return render_template("admin/landing/items.html", sec=sec, items=all_items(sec))


@bp.get("/sections/<int:sid>/items/new")
@login_required
def item_new(sid: int):
    sec = db.get_or_404(LandingSection, sid)
    return render_template("admin/landing/item_form.html", sec=sec, item=None,
                           statuses=ITEM_STATUS_BADGES)


@bp.post("/sections/<int:sid>/items/new")
@login_required
def item_create(sid: int):
    sec = db.get_or_404(LandingSection, sid)
    it = LandingItem(section_id=sec.id, item_type=_s("item_type", "feature"),
                     sort_order=(max([x.sort_order for x in all_items(sec)] + [0]) + 10))
    _fill_item(it)
    db.session.add(it)
    audit("landing_item_created", "landing_item", "", f"Added item to {sec.section_key}")
    db.session.commit()
    flash("تمت إضافة العنصر.", "success")
    return redirect(url_for("admin_landing.items", sid=sec.id))


@bp.get("/items/<int:iid>")
@login_required
def item_edit(iid: int):
    it = db.get_or_404(LandingItem, iid)
    return render_template("admin/landing/item_form.html", sec=it.section, item=it,
                           statuses=ITEM_STATUS_BADGES)


@bp.post("/items/<int:iid>")
@login_required
def item_update(iid: int):
    it = db.get_or_404(LandingItem, iid)
    _fill_item(it)
    audit("landing_item_updated", "landing_item", str(it.id), f"Updated item in {it.section.section_key}")
    db.session.commit()
    flash("تم حفظ العنصر.", "success")
    return redirect(url_for("admin_landing.items", sid=it.section_id))


@bp.post("/items/<int:iid>/toggle")
@login_required
def item_toggle(iid: int):
    it = db.get_or_404(LandingItem, iid)
    it.is_visible = not it.is_visible
    db.session.commit()
    return redirect(url_for("admin_landing.items", sid=it.section_id))


@bp.post("/items/<int:iid>/move")
@login_required
def item_move(iid: int):
    it = db.get_or_404(LandingItem, iid)
    _move(all_items(it.section), it, _s("dir", "up"))
    db.session.commit()
    return redirect(url_for("admin_landing.items", sid=it.section_id))


@bp.post("/items/<int:iid>/delete")
@login_required
def item_delete(iid: int):
    it = db.get_or_404(LandingItem, iid)
    sid = it.section_id
    audit("landing_item_deleted", "landing_item", str(it.id), "Deleted landing item")
    db.session.delete(it)
    db.session.commit()
    flash("تم حذف العنصر.", "success")
    return redirect(url_for("admin_landing.items", sid=sid))


# ════════════════════════ SOCIAL LINKS ════════════════════════

@bp.get("/social-links")
@login_required
def social_list():
    links = LandingSocialLink.query.order_by(LandingSocialLink.sort_order.asc(),
                                             LandingSocialLink.id.asc()).all()
    return render_template("admin/landing/social_links.html", links=links)


@bp.post("/social-links")
@login_required
def social_save():
    sid = _i("id")
    link = db.session.get(LandingSocialLink, sid) if sid else LandingSocialLink(
        sort_order=(max([x.sort_order for x in LandingSocialLink.query.all()] + [0]) + 10))
    link.platform = _s("platform") or "website"
    link.label = _s("label")
    link.url = _safe_url(_s("url"))
    link.icon_name = _s("icon_name") or link.platform
    link.is_visible = _flag("is_visible")
    if not link.id:
        db.session.add(link)
    audit("landing_social_saved", "landing_social_link", str(link.id or ""), f"Social {link.platform}")
    db.session.commit()
    flash("تم حفظ رابط التواصل.", "success")
    return redirect(url_for("admin_landing.social_list"))


@bp.post("/social-links/<int:lid>/delete")
@login_required
def social_delete(lid: int):
    link = db.get_or_404(LandingSocialLink, lid)
    db.session.delete(link)
    db.session.commit()
    flash("تم حذف الرابط.", "success")
    return redirect(url_for("admin_landing.social_list"))


# ════════════════════════ CONTACT METHODS ════════════════════════

@bp.get("/contact-methods")
@login_required
def contact_list():
    methods = LandingContactMethod.query.order_by(LandingContactMethod.sort_order.asc(),
                                                  LandingContactMethod.id.asc()).all()
    return render_template("admin/landing/contact_methods.html", methods=methods)


@bp.post("/contact-methods")
@login_required
def contact_save():
    cid = _i("id")
    m = db.session.get(LandingContactMethod, cid) if cid else LandingContactMethod(
        sort_order=(max([x.sort_order for x in LandingContactMethod.query.all()] + [0]) + 10))
    m.method_type = _s("method_type") or "email"
    m.label = _s("label")
    m.value = _s("value")
    m.url = _safe_url(_s("url"))
    m.icon_name = _s("icon_name")
    m.is_visible = _flag("is_visible")
    if not m.id:
        db.session.add(m)
    audit("landing_contact_saved", "landing_contact_method", str(m.id or ""), f"Contact {m.method_type}")
    db.session.commit()
    flash("تم حفظ طريقة الاتصال.", "success")
    return redirect(url_for("admin_landing.contact_list"))


@bp.post("/contact-methods/<int:cid>/delete")
@login_required
def contact_delete(cid: int):
    m = db.get_or_404(LandingContactMethod, cid)
    db.session.delete(m)
    db.session.commit()
    flash("تم حذف طريقة الاتصال.", "success")
    return redirect(url_for("admin_landing.contact_list"))


# ════════════════════ PRODUCT APPS + DOWNLOADS ════════════════════
# Upload Windows .exe/.msi + Android .apk/.aab per app+channel, mark a current
# version. The public Downloads section serves the current releases. The
# Card-Print intro link target is a CMS setting edited here too.

@bp.get("/apps")
@login_required
def apps():
    from ..services import app_releases as ar
    products = []
    for p in ar.list_products():
        products.append({"product": p, "releases": p.releases.order_by(
            AppRelease.platform.asc(), AppRelease.channel.asc(),
            AppRelease.created_at.desc()).all()})
    return render_template(
        "admin/landing/apps.html",
        products=products,
        platforms=ar.PLATFORMS, channels=ar.CHANNELS,
        allowed_ext=ar.ALLOWED_EXT_BY_PLATFORM,
        cardprint_url=ar.get_cardprint_url(),
    )


@bp.post("/apps/save")
@login_required
def app_save():
    from ..services import app_releases as ar
    pid = _i("product_id")
    product = ar.get_product(pid) if pid else None
    try:
        product = ar.upsert_product(
            product=product, name=_s("name"), slug=_s("slug"),
            description=_s("description"), icon_name=_s("icon_name"),
            sort_order=_i("sort_order", 100), is_visible=_flag("is_visible"))
    except ar.AppReleaseError as exc:
        flash(str(exc), "error")
        return redirect(url_for("admin_landing.apps"))
    audit("landing_app_saved", "app_product", str(product.id), f"App {product.slug}")
    db.session.commit()
    flash("تم حفظ التطبيق.", "success")
    return redirect(url_for("admin_landing.apps"))


@bp.post("/apps/<int:pid>/delete")
@login_required
def app_delete(pid: int):
    from ..services import app_releases as ar
    product = ar.get_product(pid)
    if product is None:
        flash("التطبيق غير موجود.", "error")
        return redirect(url_for("admin_landing.apps"))
    slug = product.slug
    ar.delete_product(product)
    audit("landing_app_deleted", "app_product", str(pid), f"App {slug}")
    db.session.commit()
    flash("تم حذف التطبيق وجميع إصداراته.", "success")
    return redirect(url_for("admin_landing.apps"))


@bp.post("/apps/<int:pid>/upload")
@login_required
def app_upload(pid: int):
    from flask import session
    from ..services import app_releases as ar
    product = ar.get_product(pid)
    if product is None:
        flash("التطبيق غير موجود.", "error")
        return redirect(url_for("admin_landing.apps"))
    upload = request.files.get("binary")
    if not upload or not (upload.filename or "").strip():
        flash("اختر ملفًا للرفع.", "error")
        return redirect(url_for("admin_landing.apps"))
    blob = upload.read(ar.MAX_UPLOAD_BYTES + 1)
    try:
        rel = ar.create_release(
            product=product, platform=_s("platform"), channel=_s("channel", "stable"),
            version=_s("version"), filename=upload.filename, content=blob,
            set_current=_flag("set_current"), admin_id=session.get("admin_id"))
    except ar.AppReleaseError as exc:
        flash(str(exc), "error")
        return redirect(url_for("admin_landing.apps"))
    audit("landing_app_release_uploaded", "app_release", str(rel.id),
          f"{product.slug} {rel.platform}/{rel.channel} v{rel.version}",
          {"sha256": rel.sha256, "size": rel.size_bytes, "current": rel.is_current})
    db.session.commit()
    flash(f"تم رفع الإصدار v{rel.version} ({rel.platform}).", "success")
    return redirect(url_for("admin_landing.apps"))


@bp.post("/releases/<int:rid>/set-current")
@login_required
def release_set_current(rid: int):
    from ..services import app_releases as ar
    rel = db.get_or_404(AppRelease, rid)
    ar.set_current_release(rel)
    audit("landing_app_release_current", "app_release", str(rel.id),
          f"current {rel.platform}/{rel.channel} v{rel.version}")
    db.session.commit()
    flash(f"تم تعيين v{rel.version} كإصدار حالي.", "success")
    return redirect(url_for("admin_landing.apps"))


@bp.post("/releases/<int:rid>/delete")
@login_required
def release_delete(rid: int):
    from ..services import app_releases as ar
    rel = db.get_or_404(AppRelease, rid)
    label = f"{rel.platform}/{rel.channel} v{rel.version}"
    ar.delete_release(rel)
    audit("landing_app_release_deleted", "app_release", str(rid), label)
    db.session.commit()
    flash("تم حذف الإصدار.", "success")
    return redirect(url_for("admin_landing.apps"))


@bp.post("/apps/cardprint-url")
@login_required
def cardprint_save():
    from ..services import app_releases as ar
    try:
        url = ar.set_cardprint_url(_s("cardprint_url"))
    except ar.AppReleaseError as exc:
        flash(str(exc), "error")
        return redirect(url_for("admin_landing.apps"))
    audit("landing_cardprint_url_saved", "setting", ar.CARDPRINT_URL_SETTING,
          "Card-Print store URL updated", {"set": bool(url)})
    db.session.commit()
    flash("تم حفظ رابط متجر بطاقات الطباعة.", "success")
    return redirect(url_for("admin_landing.apps"))
