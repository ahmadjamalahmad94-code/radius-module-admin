# تقرير الفحص الشامل — HobeHub (radius-module-admin)
**التاريخ:** 2026-07-16 · **النطاق:** الكود، التصميم/UX، سهولة الوصول، الكود الميت/المكرر، جاهزية التحويل إلى SaaS

> المنهجية: 4 فحوصات متوازية متعمقة (بنية الكود، الكود الميت، الواجهة، جاهزية SaaS) مع تحقق يدوي من النقاط الحرجة. كل الأرقام والمسارات أدناه مأخوذة من الشجرة الرئيسية (باستثناء `.claude/worktrees/*`).

---

## 0. الخلاصة التنفيذية

المشروع **لوحة تشغيل ناضجة وظيفيًا** (فحوصات، مراقبة أسطول، ترخيص موقّع، نسخ احتياطي، تحديثات) لكنه:
- **تراكم 4 أجيال تصميم** بلا توحيد: `hub-*` → `cc-*` → `adm-*` → أنماط لكل صفحة. إحساسك بأن الواجهة سيئة صحيح والأرقام تؤكده.
- **~10,850 سطر CSS مضمّن داخل 58 قالبًا** (ضعف حجم كل ملفات CSS الخارجية) — يقتل التخزين المؤقت ويجعل إعادة التصميم الشاملة مستحيلة.
- **16 قالبًا ميتًا + 4 موديولات خدمات ميتة + خطأ NameError كامن مؤكد** في تعليق أنفاق CHR.
- **كـ SaaS**: الفوترة يدوية بالكامل، لا 2FA، لا RBAC حقيقي، SQLite + عامل gunicorn واحد، ولا Docker في الشجرة الرئيسية.

---

## 1. الكود الميت والمكرر (طلبك الأساسي)

### 1.1 قوالب ميتة — آمنة للحذف (16 قالبًا، صفر مراجع مؤكدة)

| القالب الميت | البديل الحي |
|---|---|
| `admin/base.html` | `admin/base_new.html` (يرثه 89–90 قالبًا) |
| `admin/dashboard.html` | `admin/dashboard_new.html` (routes.py:565) |
| `admin/customers_list.html` | `admin/customers/list_new.html` (routes.py:2099) |
| `admin/customer_detail.html` | `admin/customers/detail_new.html` |
| `admin/customer_vpn_tunnels.html` | `admin/customer_vpn_service.html` (routes.py:1891) |
| `admin/licenses_list.html` | `admin/licenses/list_new.html` (routes.py:2840) |
| `admin/license_detail.html` | `admin/licenses/detail_new.html` (routes.py:2884) |
| `admin/license_form.html` | `admin/licenses/create_new.html` (routes.py:2849) |
| `admin/plans_list.html` | `admin/licenses/plans_new.html` (routes.py:2482) |
| `admin/audit_logs.html` | `admin/logs/audit_new.html` |
| `admin/infra/health_overview.html` | `admin/logs/health_new.html` (infra_routes.py:1017) |
| `admin/infra/chr_nodes.html` | إدارة CHR انتقلت إلى `fleet/` (الجدول القديم حُذف "step 6") |
| `admin/infra/chr_node_detail.html` | `fleet/` |
| `admin/infra/allocation_snapshots.html` | — (صفر مراجع) |
| `admin/settings/whatsapp_new.html` | لوحة `#whatsapp-cloud` داخل الإعدادات العامة (routes.py:3538 يوثّقها كنسخة ميتة) |
| `public/customer_portal_whatsapp.html` | pane داخل داشبورد البوابة `?view=whatsapp` (المسار الآن redirect فقط) |

لا يوجد أي زوج "كلاهما مستخدم" — كل زوج قديم/جديد له طرف حي واحد، فالحذف منخفض الخطورة.

### 1.2 موديولات خدمات ميتة (`app/services/`)

| الموديول | الحالة |
|---|---|
| `admin_permissions.py` | **ميت تمامًا** — صفر مستوردين (حتى الاختبارات). طبقة الصلاحيات الفعلية = `is_super_admin` الثنائية فقط |
| `node_capacity.py` | **ميت تمامًا** — صفر مراجع |
| `customer_speed_enforcement.py` | ميت إنتاجيًا — يستورده اختبار واحد فقط رغم أن docstring يسميه "THE business model" |
| `data_connection_script.py` | ميت إنتاجيًا — اختبار واحد فقط |

### 1.3 خطأ كامن مؤكد (ليس مجرد كود ميت) ⚠️

`app/services/vpn_tunnels.py:443` و `app/services/wireguard_peers.py:392` يستدعيان `chr_settings.build_client()` — **الموديول `chr_settings` محذوف من المشروع ولا يوجد أي import له**. أي تعليق/تفعيل نفق أو قرين WireGuard مُجهّز على CHR (`chr_provisioned=True`) سيرمي `NameError` (وحتى جملة `except chr_settings.ChrSettingsError` نفسها سترمي NameError ثانيًا). يجب إما توجيه الاستدعاء عبر `fleet_node_router` أو حذف الفرع.

### 1.4 أصول ثابتة ميتة
- `app/static/css/customer_portal.css` (البوابة تستخدم `portal_pro.css` + `portal_redesign.css`)
- `app/static/js/chr_settings.js`

### 1.5 مسارات/صفحات زائدة
- `/settings/whatsapp` (routes.py:3534) — redirect فقط، قالبه ميت.
- `/portal/whatsapp` (public/routes.py:1016) — redirect فقط (مقصود للروابط القديمة، يمكن إبقاؤه).
- نقاط CHR القديمة في `infra_routes.py` (~347–544) — تمرر `chr_nodes=[]` فارغة دائمًا؛ الإدارة الفعلية في `fleet/`.
- ملاحظة: `fleet/p7_dashboard` و`p8_dashboard` **ليسا** تكرارًا — P7 = live-apply/placement وP8 = rebalance/failover. يبقيان.

### 1.6 مخلفات في جذر المستودع (~30 ملفًا + 10 نسخ كاملة)
- 3 سكربتات probe (`_render_addcustomer*.py`) + 14 لقطة PNG + 3 لقطات HTML + `_sample_chr_unified.rsc` + 3 مجلدات لقطات (`_tweetsms_shots/`, `_wa_shots/`, `_verify_shots/`) + `_MOCK_INVENTORY.md` + `migrate_backup_artifacts.py`.
- **`.claude/worktrees/` يحوي 10 نسخ كاملة من المشروع** (worktrees لفروع قديمة) — أكبر مصدر لحجم الـ655MB. تُحذف بـ `git worktree remove`.

---

## 2. جودة الكود والبنية — أهم المخاطر (مرتبة)

1. **تعديل المخطط وقت الإقلاع مع DDL مدمّر**: `ensure_schema_compatibility()` في `app/__init__.py:600–1043` (~440 سطرًا) تعمل عند كل إقلاع: `db.create_all()` ثم `ALTER TABLE` يدوية عبر ~15 جدولًا ثم `DROP TABLE chr_node_metrics/chr_nodes` و`RENAME COLUMN` وتحديثات بيانات — كلها داخل try/except يبتلع الفشل بصمت. **لا يوجد Alembic/Flask-Migrate إطلاقًا** (مجلد `migrations/` = 9 سكربتات يدوية لجداول fleet فقط، بلا version table).
2. **Fail-open على الأسرار الافتراضية**: نسيان ضبط `LICENSE_PANEL_ENV` في الإنتاج يعني الإقلاع بـ `dev-secret-change-me` / `admin12345` مع مجرد تحذير سجل (config.py:47–48، `__init__.py:353–443`).
3. **ملفات عملاقة**: `admin/routes.py` = **5,703 سطر / 168 مسارًا** (54 مسارًا تحت `/customers/<id>/` وحدها)، `customer_control.py` = 2,461 سطر / 82 دالة، `__init__.py` = 1,675، `models.py` = 2,363 / 57 كلاسًا، `api/routes.py` = 1,773.
4. **الحماية لكل مسار وليس على مستوى البلوبرنت**: 138 `@login_required` يدويًا؛ `before_request` الوحيد يفرض إخفاء الأقسام لا المصادقة — مسار جديد بلا decorator يصبح عامًا.
5. **خيوط خلفية لكل عامل بلا leader election**: `threading.Thread(daemon=True)` لـ metrics_poller وwg_autosync وip_change_sweep — تحت gunicorn متعدد العمال تتضاعف وتتسابق. لا Celery/RQ/APScheduler.
6. **Rate limiting في الذاكرة** على نقاط `/api` العامة — لكل عملية، يتصفر عند إعادة التشغيل، لا يمتد عبر العمال.
7. **مقارنة CSRF غير ثابتة الزمن** (`__init__.py:1389` تستخدم `!=` بدل `hmac.compare_digest`) + إعفاء `/api/*` بالكامل من CSRF.
8. تكرار helpers (مثل `get_or_404` معاد كتابته في 5 ملفات مسارات) وتاريخ المشروع مكتوب كتعليقات نثرية بدل git.

**نقاط قوة**: فصل services عن routes صحي عمومًا، ~200 ملف اختبار منظم بالميزات، تشفير Fernet للأسرار لكل عميل، ترويسات أمان + HSTS، جلسات آمنة.

---

## 3. الواجهة / UX / سهولة الوصول

### التشخيص بالأرقام
- **CSS**: 11 ملفًا خارجيًا (~5,779 سطرًا) تُحمَّل بترتيب "طبقات ترقيع" متعمد (design_sweep ثم polish "فوق الكل") + **~10,849 سطر CSS مضمّن** في 58 قالبًا. أسوأ القوالب: `customers/add_new.html` (728 سطر style)، `detail_new.html` (658 + 166 خاصية style= سطرية)، `licenses/services_new.html` (616).
- **4 أنظمة أزرار متنافسة**: `hub-btn--primary` (90×) / `btn--primary` (70×) / `btn-primary` (17×) / `c-btn` (14×).
- **i18n شكلي**: نظام ترجمة كامل بمبدّل 4 لغات، لكن 33 قالبًا فقط من 112 يستخدم `_()`؛ **~95% من النصوص عربية مكتوبة يدويًا** (5,888 سطرًا عربيًا مقابل 327 استدعاء ترجمة)؛ كتالوجات اللغات مجمّدة عند 127 مفتاحًا.
- **249 تجاوز `dir="ltr"` يدويًا** لمحاربة RTL على القيم التقنية.

### سهولة الوصول (WCAG)
- **تباين فاشل**: `--cc-text-mute: #94A3B8` (admin_tokens.css:54) ≈ 2.6:1 على الأبيض (المطلوب 4.5:1) ويُستخدم 84 مرة.
- **123 حقل إدخال عنوانه الوحيد placeholder** (يختفي عند الكتابة).
- **≥17 زر أيقونة فقط بلا نص ولا aria-label**.
- **لا يوجد skip-link** — مستخدم لوحة المفاتيح يعبر ~40 رابط سايدبار في كل صفحة.
- **مودالات يدوية بلا focus-trap ولا Esc ولا إعادة تركيز** (والقاعدة نفسها توثّق حادثة تصادم IDs مكررة عطّلت زر التأكيد بصمت — base_new.html:619–625).
- عنوان الصفحة `<div>` وليس `<h1>`؛ 88 جدولًا وscope شبه غائب.

### بنية التنقل (IA)
- ~40 وجهة في سايدبار واحد؛ مجموعة "أسطول CHR" وحدها 10 روابط؛ مجموعة "البنية التحتية" قابلة للطي من أجل **رابط واحد**.
- `section_visibility.py` لم يعد يطابق التنقل الفعلي: مجموعات fleet/landing **لا يمكن إخفاؤها**، ومفاتيح مثل `infra.macros` لا تتحكم بشيء.

### الأداء الأمامي
- لا bundling/minification/fingerprinting؛ خطوط Google + Font Awesome من CDN (بنسختين متشعبتين 6.5.1 و6.5.2).
- استجابة موبايل شبه غائبة: ~30 media query فقط لكل اللوحة + 180 عرضًا بكسليًا ثابتًا مضمّنًا.
- JS التوست/المودال/النسخ منسوخ يدويًا في 11+ قالبًا رغم وجود `showToast()` عام و`#hub-toast-root` في القاعدة.

---

## 4. جاهزية SaaS — موجود / جزئي / مفقود

| المحور | الحالة | التفصيل |
|---|---|---|
| نمذجة العملاء (tenancy) | ✅ قوية | Customer/License/CustomerUser بأدوار بوابة + entitlements، كل الجداول بـ customer_id |
| عزل حقيقي | ⚠️ جزئي | العزل انضباط كود على SQLite مشتركة — لا RLS ولا فصل مخططات |
| أدوار مديري اللوحة | ❌ | 4 تسميات UI كلها تنهار إلى boolean واحد `is_super_admin` (routes.py:3585–3722) |
| 2FA | ❌ | غير موجود إطلاقًا (كل نتائج otp/mfa = قوالب رسائل واتساب) |
| كتالوج أسعار وباقات | ✅ | 6 باقات بسعة الجلسات (subscription_pricing.py) + خصومات مدد + تجربة 14 يومًا |
| بوابة دفع آلية | ❌ | `manual_wallet` + `jawwal_pay` (stub) فقط — تحويل يدوي + مراجعة إيصال بشرية. لا Stripe/بطاقات/تجديد تلقائي/dunning |
| تسجيل ذاتي | ⚠️ | `/portal/signup` ينشئ طلبًا pending — التفعيل والترخيص يدويان |
| التزويد الآلي | ⚠️ | اللبنات موجودة ومنفصلة (subdomain حتمي، Cloudflare DNS، معالج CHR بحالة draft→active، cloud-init) لكن الحلقة لا تُغلق بلا مدير |
| النسخ/المراقبة/التحديثات/التدقيق | ✅ | ناضجة (customer_backups + Google Drive، fleet/health، module_updates اختياري، AuditLog شامل) |
| قاعدة البيانات | ⚠️ | SQLite افتراضيًا؛ Postgres مدعوم كودًا (`POSTGRESQL_READINESS.md`) لكنه غير المسار المُختبَر |
| النشر | ❌ | systemd + `gunicorn --workers 1` + nginx يدويًا؛ لا Dockerfile في الشجرة الرئيسية |
| I/O متزامن في الطلبات | ⚠️ | استدعاءات RouterOS/Cloudflare داخل معالجات الويب بمهلة 15 ثانية — راوتر بطيء يجمّد العامل الوحيد |
| صفحة حالة عامة / مركز مساعدة للعملاء | ❌ | البيانات موجودة داخليًا فقط |

---

## 5. خارطة الطريق المقترحة

### المرحلة 0 — تنظيف فوري (أيام، صفر مخاطرة تقريبًا)
1. حذف 16 قالبًا ميتًا + ملفَي static + 4 موديولات خدمات (مع اختباراتها اليتيمة).
2. **إصلاح NameError في `vpn_tunnels.py:443` و`wireguard_peers.py:392`** (توجيه عبر fleet_node_router أو حذف الفرع).
3. حذف ~30 ملف probe/لقطات من الجذر + تنظيف 10 worktrees (`git worktree remove`) → استرداد معظم الـ655MB.
4. تحويل مقارنة CSRF إلى `hmac.compare_digest`.
5. جعل غياب `LICENSE_PANEL_ENV` **يمنع الإقلاع** على الأسرار الافتراضية بدل التحذير.

### المرحلة 1 — أساسات الهندسة (2–4 أسابيع)
6. **إدخال Alembic** وتجميد `ensure_schema_compatibility` (تحويل منطقها إلى هجرات مرقّمة؛ إزالة DROP/RENAME من الإقلاع).
7. تفكيك `admin/routes.py` (5,703 سطر) إلى blueprints بالنطاق: customers / licenses / payments / settings / vpn — مع `before_request` يفرض المصادقة على مستوى كل blueprint.
8. نقل الخيوط الخلفية إلى عامل مستقل (RQ/Celery أو حتى عملية systemd منفصلة واحدة) لحل مشكلة التضاعف تحت عمال متعددين.
9. Rate limiting خارج الذاكرة (Redis) أو على مستوى nginx.
10. Dockerfile + compose في الشجرة الرئيسية، والانتقال الافتراضي إلى Postgres + عمال متعددين.

### المرحلة 2 — إعادة بناء الواجهة (3–6 أسابيع، أعلى أثر محسوس)
11. **استخراج الـ10,849 سطر CSS المضمّن** إلى نظام مكوّنات واحد فوق `admin_tokens.css`، وتوحيد الأزرار/الجداول/البطاقات في عائلة واحدة (`adm-*`)، ثم حذف طبقات sweep/polish الترقيعية.
12. مكوّن مودال/توست/نسخ واحد مشترك (حذف النسخ الـ11+).
13. إصلاح الوصول: رفع `--cc-text-mute` إلى ≥ `#64748B`، skip-link، `<h1>` للعناوين، aria-label للأزرار الأيقونية، labels حقيقية بدل placeholder، focus-trap + Esc للمودالات.
14. إعادة هيكلة السايدبار: دمج ~40 وجهة في 5–6 أقسام (توحيد fleet/infra)، ومزامنة `section_visibility.py` مع الواقع.
15. قرار i18n: إمّا تمرير حقيقي للنصوص عبر `_()` (ورشة مسح مثل ما فعلته في radius-module) أو إزالة مبدّل اللغات مؤقتًا — الوضع الحالي "مسرحية ترجمة".
16. تجاوب موبايل للجداول الثقيلة (نمط cc-table-wrapper موجود — يُعمم).

### المرحلة 3 — التحول التجاري إلى SaaS (4–8 أسابيع)
17. RBAC حقيقي للوحة (الأدوار الأربعة موجودة كتسميات — تُربط بفحوصات فعلية) + **2FA/TOTP** للمديرين.
18. بوابة دفع آلية (Stripe أو مزود إقليمي) فوق النماذج الجاهزة (`LicensePaymentTransaction`/`Webhook`/`ProvisioningOrder`) + تجديد تلقائي وdunning.
19. **إغلاق حلقة التزويد الذاتي**: signup → موافقة (أو آلي بالدفع) → إصدار ترخيص + subdomain + DNS + نفق دون تدخل مدير — كل اللبنات موجودة.
20. تخزين كائنات (S3-متوافق) للنسخ/الإيصالات/الملفات بدل قرص `instance_path`.
21. صفحة حالة عامة (البيانات في `fleet/health` جاهزة) + مركز مساعدة للعملاء.

---

## ملاحق — أكبر 10 قوالب (سطور)
`customers/detail_new.html` 2,151 · `customers/add_new.html` 1,816 · `public/customer_portal_dashboard.html` 1,615 · `settings/general_new.html` 1,591 · `fleet/dashboard.html` 1,507 · `licenses/services_new.html` 1,056 · `customers/list_new.html` 1,024 · `licenses/create_new.html` 1,002 · `licenses/plans_new.html` 952 · `licenses/detail_new.html` 914
