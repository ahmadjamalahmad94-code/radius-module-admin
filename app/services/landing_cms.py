"""
Landing Page CMS service — seeding + read helpers.

The public landing page is rendered entirely from these tables so admins can
edit/enable/disable/reorder every visible block without touching code.

Accuracy rule: default seed content only advertises features that are actually
implemented in the platform. Unsupported / not-implemented claims are excluded
(or marked "قريبًا"). See docs/public_landing/LANDING_PAGE_CMS.md.
"""
from __future__ import annotations

from ..extensions import db
from ..models import (
    LandingContactMethod,
    LandingItem,
    LandingPage,
    LandingSection,
    LandingSocialLink,
    utcnow,
)

HOME_SLUG = "home"

SECTION_STATUS = {"draft", "published", "archived"}
ITEM_STATUS_BADGES = ("", "متاح", "قيد التجهيز", "حسب الخطة", "قريبًا")

# ── Status badge → CSS modifier (used by the public template) ──────────────
STATUS_BADGE_CLASS = {
    "متاح": "ok",
    "حسب الخطة": "plan",
    "قيد التجهيز": "soon",
    "قريبًا": "soon",
}


# ═══════════════════════ READ HELPERS (public + admin) ═══════════════════════

def get_homepage() -> LandingPage | None:
    return LandingPage.query.filter_by(slug=HOME_SLUG).first()


def get_published_homepage() -> LandingPage | None:
    return LandingPage.query.filter_by(slug=HOME_SLUG, status="published").first()


def all_sections(page: LandingPage):
    return (page.sections.order_by(LandingSection.sort_order.asc(),
                                   LandingSection.id.asc()).all()
            if page else [])


def visible_sections(page: LandingPage):
    return [s for s in all_sections(page) if s.is_visible]


def all_items(section: LandingSection):
    return section.items.order_by(LandingItem.sort_order.asc(),
                                  LandingItem.id.asc()).all()


def visible_items(section: LandingSection):
    return [i for i in all_items(section) if i.is_visible]


def visible_social_links():
    return [s for s in LandingSocialLink.query
            .order_by(LandingSocialLink.sort_order.asc(), LandingSocialLink.id.asc()).all()
            if s.is_visible and (s.url or "").strip()]


def visible_contact_methods():
    return [c for c in LandingContactMethod.query
            .order_by(LandingContactMethod.sort_order.asc(), LandingContactMethod.id.asc()).all()
            if c.is_visible and (c.value or "").strip()]


def build_public_context(page: LandingPage) -> dict:
    """Everything the public template needs, pre-filtered to visible content."""
    sections = []
    for sec in visible_sections(page):
        sections.append({"section": sec, "items": visible_items(sec)})
    return {
        "page": page,
        "sections": sections,
        "social_links": visible_social_links(),
        "contact_methods": visible_contact_methods(),
        "status_badge_class": STATUS_BADGE_CLASS,
    }


# ═══════════════════════════ SEED (idempotent) ═══════════════════════════

def _section(page_id, key, stype, order, **kw) -> LandingSection:
    return LandingSection(page_id=page_id, section_key=key, section_type=stype,
                          sort_order=order, is_visible=kw.pop("is_visible", True), **kw)


def _item(section_id, itype, order, **kw) -> LandingItem:
    feats = kw.pop("features", None)
    it = LandingItem(section_id=section_id, item_type=itype, sort_order=order,
                     is_visible=kw.pop("is_visible", True), **kw)
    if feats is not None:
        it.features = feats
    return it


def seed_landing_defaults() -> None:
    """Create the default home page + sections + items if missing. Idempotent."""
    page = get_homepage()
    if page is None:
        page = LandingPage(
            slug=HOME_SLUG, title="HobeRadius", language="ar", status="published",
            is_homepage=True, published_at=utcnow(),
            seo_title="HobeRadius — منصة إدارة شبكات الإنترنت و RADIUS",
            seo_description="منصة تشغيل وإدارة شبكات الإنترنت و RADIUS لأصحاب الشبكات ومزوّدي الخدمة: "
                            "مشتركون، كروت، باقات، راوترات، مراقبة، نسخ احتياطي، ودعم — من لوحة واحدة.",
            seo_keywords="RADIUS, MikroTik, Hotspot, PPPoE, ISP, إدارة شبكات, HobeRadius",
        )
        db.session.add(page)
        db.session.flush()

    # If sections already exist for this page, seeding is done.
    if page.sections.count() > 0:
        db.session.commit()
        return

    pid = page.id

    # 1) HERO
    hero = _section(pid, "hero", "hero", 10,
        eyebrow_text="منصة تشغيل الشبكات",
        title="منصة ذكية لإدارة شبكات الإنترنت و RADIUS",
        subtitle="أدر المشتركين، الكروت، الباقات، الراوترات، التنبيهات، النسخ الاحتياطي، "
                 "وعمليات الشبكة من لوحة واحدة مصممة لأصحاب الشبكات.",
        primary_button_text="ابدأ الآن", primary_button_url="#contact",
        secondary_button_text="استعرض النظام", secondary_button_url="#features",
        icon_name="diagram-project")
    db.session.add(hero)

    # 2) TRUST CHIPS
    chips = _section(pid, "trust_chips", "trust_chips", 20, title="")
    db.session.add(chips); db.session.flush()
    trust = [
        ("MikroTik Ready", "tower-broadcast"), ("RADIUS Core", "shield-halved"),
        ("Arabic RTL", "language"), ("Google Drive Backup", "cloud-arrow-up"),
        ("Network Monitoring", "wave-square"), ("Subscriber Portal", "user-group"),
    ]
    for i, (t, ic) in enumerate(trust):
        db.session.add(_item(chips.id, "trust_chip", (i + 1) * 10, title=t, icon_name=ic))

    # 3) METRICS (capability strip — no fabricated customer stats)
    metrics = _section(pid, "metrics", "stats", 30, title="")
    db.session.add(metrics); db.session.flush()
    caps = [
        ("إدارة المشتركين", "users"), ("كروت Hotspot", "ticket"),
        ("مراقبة الشبكة", "wave-square"), ("نسخ احتياطي", "database"),
        ("صلاحيات الإدارة", "user-shield"), ("سجل عمليات", "list-check"),
    ]
    for i, (label, ic) in enumerate(caps):
        db.session.add(_item(metrics.id, "metric", (i + 1) * 10,
                             label_text=label, value_text="✓", icon_name=ic))

    # 4) FEATURES
    features = _section(pid, "features", "cards_grid", 40,
        eyebrow_text="المزايا", title="كل ما تحتاجه لتشغيل شبكتك من مكان واحد")
    db.session.add(features); db.session.flush()
    feat_cards = [
        ("إدارة المشتركين", "ملفات مشتركين منظمة، بيانات الاتصال، الحالة، الباقات، الجلسات، والتنبيهات المرتبطة بكل مشترك.", "users"),
        ("كروت Hotspot", "إدارة كروت الاستخدام، الحزم، الحالات، الاستيراد، الفحص، والتصدير حسب ما يدعمه النظام.", "ticket"),
        ("الباقات والسرعات", "تنظيم الباقات، السرعات، الكوتة، المدة، وحدود الخدمة بشكل واضح.", "gauge-high"),
        ("MikroTik و RADIUS", "تكامل مع MikroTik و RADIUS لتشغيل الشبكة وإدارة العمليات الأساسية.", "network-wired"),
        ("مراقبة أجهزة الشبكة", "تابع الراوترات ونقاط الوصول، افحص Ping، راقب التأخير، واستقبل تنبيهات عند الانقطاع.", "wave-square"),
        ("النسخ الاحتياطي", "نسخ احتياطي منظم مع دعم Google Drive حسب إعدادات العميل والخدمة.", "cloud-arrow-up"),
        ("الدعم والتذاكر", "قنوات دعم ومتابعة طلبات العملاء داخل النظام.", "headset"),
        ("التقارير والسجلات", "سجلات عمليات وتقارير تساعد صاحب الشبكة على فهم النشاط اليومي.", "chart-line"),
    ]
    for i, (t, d, ic) in enumerate(feat_cards):
        db.session.add(_item(features.id, "feature", (i + 1) * 10, title=t, description=d, icon_name=ic))

    # 5) MODULES (grouped via settings.category)
    modules = _section(pid, "modules", "modules", 50,
        eyebrow_text="الوحدات", title="وحدات النظام", subtitle="كل ما تحتاجه مقسّم حسب المجال")
    db.session.add(modules); db.session.flush()
    mod_groups = [
        ("المشتركون والخدمات", [
            ("إدارة المشتركين", "users"), ("بوابة المشترك", "user-group"),
            ("طلبات الدعم", "headset"), ("حالة الخدمة", "circle-check"), ("سجل العمليات", "list-check")]),
        ("Hotspot والكروت", [
            ("إدارة الكروت", "ticket"), ("استيراد CSV / XLSX / PDF", "file-import"),
            ("فحص الكروت", "magnifying-glass"), ("حزم الكروت", "layer-group"), ("تصدير البيانات", "file-export")]),
        ("الشبكة و MikroTik", [
            ("إدارة NAS / الراوترات", "server"), ("تكامل RADIUS", "shield-halved"),
            ("مراقبة Ping", "wave-square"), ("سجل أجهزة الشبكة", "diagram-project"),
            ("فحص الـ IP", "magnifying-glass-location"), ("تجاوز الأجهزة", "route"),
            ("جلسات الوصول البعيد", "tower-cell")]),
        ("الأتمتة والتنبيهات", [
            ("تنبيهات Telegram", "paper-plane"), ("رسائل SMS", "comment-sms"),
            ("واتساب (Business Cloud API)", "whatsapp"), ("سجلات الأحداث", "clock-rotate-left"),
            ("قواعد التنبيهات", "bell")]),
        ("الإدارة والتراخيص", [
            ("لوحة التراخيص", "id-card"), ("صلاحيات المدراء", "user-shield"),
            ("خطط العملاء", "layer-group"), ("حدود الخدمات", "sliders"),
            ("طلبات التفعيل", "circle-plus"), ("Customer 360", "user-gear")]),
        ("النسخ الاحتياطي والاسترجاع", [
            ("نسخ احتياطي محلي", "database"), ("نسخ Google Drive", "cloud-arrow-up"),
            ("سياسة الاحتفاظ", "calendar-check"), ("طلب استرجاع", "rotate-left")]),
    ]
    order = 0
    for cat, cards in mod_groups:
        for (t, ic) in cards:
            order += 10
            it = _item(modules.id, "module", order, title=t, icon_name=ic)
            it.settings = {"category": cat}
            db.session.add(it)

    # 6) INTEGRATIONS
    integ = _section(pid, "integrations", "integrations", 60,
        eyebrow_text="التكاملات", title="تكاملات عملية بدون تعقيد")
    db.session.add(integ); db.session.flush()
    integrations = [
        ("MikroTik", "تكامل مباشر لإدارة الراوترات وتطبيق الإعدادات.", "tower-broadcast", "متاح"),
        ("FreeRADIUS / RADIUS", "طبقة المصادقة والمحاسبة المركزية للشبكة.", "shield-halved", "متاح"),
        ("نسخ Google Drive", "رفع النسخ الاحتياطية إلى Google Drive حسب إعداد العميل.", "cloud-arrow-up", "متاح"),
        ("تنبيهات Telegram", "إشعارات فورية عند تغيّر حالة الأجهزة.", "paper-plane", "متاح"),
        ("بوابة SMS", "إرسال رسائل قصيرة عبر بوابة HTTP حسب الإعداد.", "comment-sms", "متاح"),
        ("WhatsApp Business Cloud API", "قوالب وتنبيهات للمشتركين باستخدام رقم صاحب الشبكة.", "whatsapp", "حسب الخطة"),
        ("لوحة تراخيص HobeRadius", "إدارة التراخيص والخطط وحدود الخدمات.", "id-card", "متاح"),
        ("REST API", "واجهة برمجية للتكامل والأتمتة.", "code", "متاح"),
    ]
    for i, (t, d, ic, st) in enumerate(integrations):
        db.session.add(_item(integ.id, "integration", (i + 1) * 10,
                             title=t, description=d, icon_name=ic, status_badge=st))

    # 7) HOW IT WORKS
    how = _section(pid, "how_it_works", "steps", 70,
        eyebrow_text="طريقة العمل", title="كيف يبدأ صاحب الشبكة؟",
        subtitle="معالج الإعداد يساعدك خطوة بخطوة على تجهيز الربط الأساسي.")
    db.session.add(how); db.session.flush()
    steps = [
        ("تجهيز نسخة HobeRadius", "ابدأ نسختك الخاصة من المنصة."),
        ("ربط MikroTik / RADIUS", "اربط الراوتر وطبقة RADIUS المركزية."),
        ("إضافة الباقات والمشتركين", "نظّم باقاتك وأضف مشتركيك وكروتك."),
        ("تفعيل التنبيهات والنسخ الاحتياطي", "فعّل المراقبة والتنبيهات والنسخ الاحتياطي."),
        ("متابعة الشبكة من لوحة واحدة", "راقب وشغّل شبكتك من مكان واحد."),
    ]
    for i, (t, d) in enumerate(steps):
        db.session.add(_item(how.id, "step", (i + 1) * 10, value_text=str(i + 1), title=t, description=d))

    # 8) WHATSAPP SERVICE (honest framing)
    wa = _section(pid, "whatsapp_service", "cta", 80,
        eyebrow_text="واتساب", title="رسائل واتساب للمشتركين", badge_text="متاح حسب الخطة",
        icon_name="whatsapp",
        description="يمكن تجهيز خدمة واتساب بحيث يستخدم كل صاحب شبكة رقمه التجاري الخاص، "
                    "بينما يدير HobeRadius القوالب، السجلات، التنبيهات، وحالات الإرسال.")
    wa.settings = {"note": "العميل يستخدم رقم WhatsApp Business الخاص به ويدفع تكلفة رسائل Meta مباشرة. "
                           "HobeRadius يوفر طبقة الإدارة والأتمتة."}
    db.session.add(wa)

    # 9) WHY HOBERADIUS
    why = _section(pid, "why_hoberadius", "cards_grid", 90,
        eyebrow_text="لماذا نحن", title="لماذا HobeRadius؟")
    db.session.add(why); db.session.flush()
    why_cards = [
        ("مبني لأصحاب الشبكات", "تصميم موجّه لتشغيل شبكات الإنترنت لا للفوترة فقط.", "network-wired"),
        ("واجهة عربية RTL", "تجربة عربية كاملة ومريحة.", "language"),
        ("تكامل عملي مع MikroTik", "ربط مباشر وتطبيق إعدادات فعلي.", "tower-broadcast"),
        ("إدارة مشتركين وكروت", "كل أدوات المشتركين والكروت في مكان واحد.", "users"),
        ("مراقبة وتشغيل وليس فواتير فقط", "مراقبة الأجهزة والعمليات والتنبيهات.", "wave-square"),
        ("قابل للتوسع كمنصة SaaS", "بنية تتوسّع مع نمو شبكتك.", "layer-group"),
        ("فصل واضح بين لوحة الترخيص ونسخة العميل", "حوكمة وأمان أوضح.", "shield-halved"),
    ]
    for i, (t, d, ic) in enumerate(why_cards):
        db.session.add(_item(why.id, "feature", (i + 1) * 10, title=t, description=d, icon_name=ic))

    # 10) FAQ
    faq = _section(pid, "faq", "faq", 100, eyebrow_text="الأسئلة الشائعة", title="أسئلة متكررة")
    db.session.add(faq); db.session.flush()
    faqs = [
        ("هل HobeRadius مناسب لشبكات Hotspot و PPPoE؟",
         "نعم، الهدف إدارة خدمات الشبكة والمشتركين والباقات مع RADIUS و MikroTik حسب الإعدادات المتاحة."),
        ("هل أحتاج MikroTik؟",
         "التكامل الأساسي مصمم حول MikroTik، مع اعتماد RADIUS كطبقة مركزية."),
        ("هل خدمة واتساب تستخدم رقم صاحب الشبكة؟",
         "نعم، التصميم المعتمد أن يستخدم كل صاحب شبكة رقم WhatsApp Business الخاص به."),
        ("هل HobeRadius يدفع تكلفة رسائل واتساب؟",
         "لا. صاحب الشبكة يدفع Meta مباشرة، و HobeRadius يوفر الإدارة والأتمتة."),
        ("هل يوجد نسخ احتياطي؟",
         "نعم، نسخ احتياطي محلي مع دعم رفع إلى Google Drive حسب الإعداد والخطة."),
        ("هل يمكن طلب تفعيل خدمات إضافية؟",
         "نعم، من خلال لوحة التراخيص والخدمات حسب الخطة المتاحة."),
    ]
    for i, (q, a) in enumerate(faqs):
        db.session.add(_item(faq.id, "faq", (i + 1) * 10, title=q, description=a))

    # 11) CONTACT CTA
    cta = _section(pid, "contact_cta", "cta", 110,
        title="جاهز ترتب شبكتك بلوحة واحدة؟",
        primary_button_text="تواصل معنا", primary_button_url="#contact",
        secondary_button_text="شاهد المزايا", secondary_button_url="#features")
    db.session.add(cta)

    # 12) FOOTER
    footer = _section(pid, "footer", "footer", 120,
        title="HobeRadius",
        description="منصة تشغيل وإدارة شبكات الإنترنت و RADIUS لأصحاب الشبكات ومزوّدي الخدمة.")
    db.session.add(footer); db.session.flush()
    footer_links = [
        ("المنتج", "المزايا", "#features"), ("المنتج", "الوحدات", "#modules"),
        ("الوحدات", "التكاملات", "#integrations"), ("الوحدات", "طريقة العمل", "#how"),
        ("الدعم", "الأسئلة الشائعة", "#faq"), ("الدعم", "تواصل معنا", "#contact"),
        ("الشركة", "بوابة العميل", "/portal/login"),
    ]
    for i, (col, label, url) in enumerate(footer_links):
        it = _item(footer.id, "footer_link", (i + 1) * 10, title=label, button_url=url)
        it.settings = {"column": col}
        db.session.add(it)

    # Contact methods — hidden placeholders (admin enables + fills; we never invent data)
    if LandingContactMethod.query.count() == 0:
        for i, (mt, label, ic) in enumerate([
            ("phone", "هاتف", "phone"), ("whatsapp", "واتساب", "whatsapp"),
            ("email", "بريد إلكتروني", "envelope"), ("support_url", "رابط الدعم", "headset"),
        ]):
            db.session.add(LandingContactMethod(method_type=mt, label=label, icon_name=ic,
                                                 value="", is_visible=False, sort_order=(i + 1) * 10))

    db.session.commit()
