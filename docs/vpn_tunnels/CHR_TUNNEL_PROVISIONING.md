# تزويد أنفاق SSTP / PPTP / IPsec مركزيًا عبر CHR

هذه الوثيقة تصف الطبقة المبنية في **لوحة التراخيص** (radius-module-admin) لتزويد
أنفاق VPN مركزيًا على CHR واحد يملكه المالك، **والعقد المطلوب تنفيذه لاحقًا على
جانب لوحة العميل** (radius-module).

---

## 1) القرار المعماري

- الريديوس يُباع للعملاء؛ **ممنوع** أن تكون بيانات اعتماد CHR أو توليد النفق في
  لوحة العميل. كل ذلك مركزي في لوحة التراخيص.
- CHR مركزي واحد: المضيف والمنفذ والمستخدم تُدخل في **إعدادات لوحة التراخيص**،
  وكلمة المرور **يدخلها المالك** وتُخزَّن **مشفّرة** (Fernet عبر
  `CUSTOMER_VAULT_ENCRYPTION_KEY`) — لا تُكتب بالكود أبدًا.
- الجسر **سحب (pull)**: لوحة العميل تستدعي نقاط لوحة التراخيص الموقّعة؛ اللوحة لا
  تدفع شيئًا. كلمة مرور النفق تُسلَّم صريحة **مرة واحدة** حتى يؤكّد العميل الاستلام.

## 2) ما بُني في لوحة التراخيص

| المكوّن | الملف |
|---|---|
| إعدادات اتصال CHR (مشفّرة) + اختبار + كشف | `app/services/chr_settings.py` |
| عميل RouterOS REST (urllib) | `app/services/routeros_client.py` |
| خدمة التزويد (توليد/حدود/إنشاء/إلغاء/تسليم) | `app/services/vpn_tunnels.py` |
| نموذج النفق | `CustomerVpnTunnel` في `app/models.py` |
| نقاط الجسر | `app/api/routes.py` |
| واجهة إعدادات CHR | `app/templates/admin/settings.html` + `app/static/js/chr_settings.js` |
| واجهة أنفاق العميل 360 | `app/templates/admin/customer_vpn_tunnels.html` + مسارات `admin/routes.py` |

### إعدادات CHR (المالك)
الإعدادات ← قسم «MikroTik CHR — تزويد الأنفاق المركزي»: host / port / username /
password / HTTPS / verify-TLS. زر **اختبار اتصال CHR** يقرأ هوية ونسخة RouterOS.
كلمة المرور لا تُعرض بعد الحفظ (معاينة مقنّعة + كشف مؤقت للمسؤول العام فقط).

### تدفّق SSTP التلقائي (عبر الجسر)
1. ريديوس العميل يطلب نفقًا عبر `POST /api/integration/hoberadius/vpn/tunnels/request`.
2. اللوحة تتحقق من الحدّ المسموح للعضو (`max_vpn_users` من صلاحية VPN، وإلا
   `CHR_DEFAULT_MAX_TUNNELS`)، تولّد يوزر/باس فريدين، تنشئ `/ppp/secret` فعليًا على
   CHR (service=sstp)، تحفظ السجل، وتعيد بيانات الاعتماد **مرة واحدة**.
3. ريديوس العميل يحقن البيانات في الريديوس ثم يؤكّد الاستلام (ack).

### تدفّق PPTP/IPsec اليدوي (بقرار المدير)
من «عرض العميل 360» ← زر **«أنفاق CHR»** ← نموذج إنشاء يدوي (النوع/البروفايل/عدد
الاتصالات). SSTP/PPTP/L2TP تُنشأ فعليًا كـ `/ppp/secret`؛ IPsec يُنشأ عبر
`/ip/ipsec` (انظر القسم التالي). ثم يسحبها العميل عبر الجسر.

### تدفّق IPsec / IKEv2 الآلي (`/ip/ipsec`، عبر `routeros_client`)
IPsec نظام مستقل عن `/ppp/secret`. المصادقة بكلمة مرور عبر **IKEv2 EAP-MSCHAPv2**،
وبيانات الاعتماد لكل مستخدم هي عنصر `/ip/ipsec/user`. التزويد:

1. **البنية المشتركة (مرّة واحدة، idempotent)** — تُهيَّأ تلقائيًا عبر
   `_ensure_ipsec_infra` بأسماء ثابتة (افتراضي `hoberadius`):
   - `/ip/ipsec/mode-config` (responder؛ مع `address-pool`/`dns` إن ضُبطا)،
   - `/ip/ipsec/peer` (`exchange-mode=ike2`, `passive=yes`)،
   - `/ip/ipsec/identity` (`auth-method=eap`, `eap-methods=eap-mschapv2`,
     `generate-policy=port-strict`, مع `certificate` الخادم إن ضُبط).
   كل خطوة تبحث قبل الإنشاء فلا تُكرّر عنصرًا موجودًا. يمكن تعطيلها بـ
   `CHR_IPSEC_MANAGE_INFRA=0` إن ضبط المالك المستمع يدويًا.
2. **لكل مستخدم** — يُنشأ `/ip/ipsec/user` (اسم/كلمة مرور) idempotent (يُتحقَّق
   بالاسم قبل الإنشاء). معرّفه يُخزَّن في `chr_secret_id`، و`chr_provisioned=True`.
3. الإلغاء يحذف `/ip/ipsec/user`؛ التعليق يعطّله (`disabled`).

> **متطلّب لمرّة واحدة على CHR:** IKEv2 EAP يتطلّب أن يُقدّم المستمعُ **شهادة خادم**.
> يثبّتها المالك مرّة على CHR ويضبط اسمها في `CHR_IPSEC_CERTIFICATE`؛ كذلك
> `CHR_IPSEC_ADDRESS_POOL` كي تحصل الأجهزة على عناوين. هذان لا يُولَّدان من الكود.

> تعطيل الأتمتة كليًّا: `CHR_IPSEC_AUTO_PROVISION=0` → يعود IPsec إلى «سجل فقط».

## 3) نقاط الجسر (تستهلكها لوحة العميل)

كلها تحت الحماية الثلاثية القياسية: **HTTPS** (وإلا 426) + **توقيع HMAC**
(`verify_license_signature`، وإلا 401) + **حلّ الترخيص** من `license_key` +
`server_fingerprint`. التوقيع نفسه المستخدم في باقي نقاط `/api/integration/...`
(انظر `app/license_signing.py`): canonical JSON مرتّب + `timestamp` + `nonce`.

### `POST /api/integration/hoberadius/vpn/tunnels/request`
طلب تزويد SSTP تلقائي. يتطلب ترخيصًا نشطًا.

طلب (إضافة لحقول التوقيع المشتركة):
```json
{ "license_key": "...", "server_fingerprint": "...",
  "timestamp": 1733500000, "nonce": "uuid", "signature": "hex",
  "tunnel_type": "sstp" }
```
رد النجاح (201):
```json
{ "ok": true, "tunnel": {
    "username": "c12-ab3d9k2m", "password": "•••• (صريحة مرة واحدة)",
    "tunnel_type": "sstp", "service": "sstp", "profile": "default",
    "status": "active", "max_connections": 1,
    "chr_host": "vpn-test.hoberadius.com",
    "chr_public_host": "vpn.hoberadius.com", "service_port": 443,
    "chr_provisioned": true,
    "delivery_status": "pending", "created_at": "...Z" } }
```
`chr_public_host` + `service_port` هما العنوان والمنفذ اللذان يتصل بهما **جهازُ
عميل العميل** لهذه الخدمة (قد يختلفان عن `chr_host` الإداري إن كان CHR خلف NAT).
يضبطهما المالك في إعدادات اللوحة؛ الفراغ ⇒ `chr_host` والمنفذ الافتراضي للخدمة.
رد رفض عمل (200، `ok:false`): `error_code ∈ {limit_reached, chr_disabled,
chr_not_configured, chr_create_failed, type_not_auto}` مع `message_ar`.

### `POST /api/integration/hoberadius/vpn/tunnels`
سحب كل أنفاق العميل غير الملغاة. كلمة المرور الصريحة تُدرج فقط للأنفاق التي لم
يؤكَّد استلامها بعد (`delivery_status != delivered`). يُستخدم للتسليم «مرة واحدة على
الأقل» (re-sync إن ضاع الرد الأول) ولالتقاط الأنفاق اليدوية (PPTP/L2TP).
```json
{ "ok": true, "tunnels": [ { "username": "...", "password": "...", ... } ] }
```

### `POST /api/integration/hoberadius/vpn/tunnels/ack`
تأكيد الاستلام لإيقاف إرجاع كلمة المرور لاحقًا.
```json
{ ...توقيع..., "usernames": ["c12-ab3d9k2m"] }
→ { "ok": true, "acknowledged": 1 }
```

## 4) العقد المطلوب تنفيذه على لوحة العميل (radius-module) — متابعة

> لا يُعدَّل radius-module من هنا. هذه هي قائمة المهام لتنفيذها لاحقًا هناك.

1. **عميل جسر موقّع** يوقّع الطلبات بنفس آلية `license_signing` (نفس السر المشترك
   لكل ترخيص) ويرسل `license_key` + `server_fingerprint` + `timestamp` + `nonce`.
2. **طلب SSTP**: عند حاجة العميل لنفق، نادِ `vpn/tunnels/request`. خزّن النفق محليًا
   (يوزر/باس) واحقنه في الريديوس/الراوتر (إعداد عميل SSTP يتصل بـ CHR).
3. **مزامنة دورية**: نادِ `vpn/tunnels` دوريًا لالتقاط الأنفاق الجديدة (خصوصًا
   اليدوية PPTP/IPsec). لكل نفق فيه `password`، احقنه ثم نادِ `vpn/tunnels/ack`
   بأسماء المستخدمين التي خُزِّنت بنجاح.
4. **عرض في بوابة العميل**: قسم «الأنفاق» يعرض الأنفاق وحالتها (بدون السماح للعميل
   بإنشاء/توليد بيانات اعتماد CHR — العرض والطلب فقط).
5. **التعامل مع الإلغاء/التعليق**: نفق غير ظاهر في `vpn/tunnels` (لأنه revoked) →
   احذفه محليًا. نفق `status=suspended` → عطّله محليًا.

## 5) المتغيّرات البيئية

انظر `.env.example` قسم «MikroTik CHR». المطلوب: `CUSTOMER_VAULT_ENCRYPTION_KEY`
(لتشفير كلمة مرور CHR والأنفاق)، و`CHR_PROVISIONING_ENABLED=1`. باقي القيم اختيارية.

**كل الإعدادات تُدار من الواجهة (DB-backed):** المالك يضبط من صفحة الإعدادات: المضيف/
منفذ REST/المستخدم/كلمة المرور (مشفّرة)/TLS+التحقق، العنوان العام، `CHR_PUBLIC_IP`،
`CHR_IPSEC_CERTIFICATE` (اسم الشهادة — قد يحتوي مسافات، يُخزَّن/يُستعمل حرفيًا)،
`CHR_IPSEC_ADDRESS_POOL`، `CHR_API_ALLOWED_IP` (معلوماتي)، ومنافذ كل خدمة. **ترتيب
الحلّ لكل قيمة: إعداد قاعدة البيانات (الواجهة) → متغيّر البيئة → افتراضي مدمج**، فالبيئة
اختيارية. الاستثناء الوحيد: `CUSTOMER_VAULT_ENCRYPTION_KEY` يبقى **بيئيًا حصرًا** (هو
المفتاح الذي يشفّر هذه الإعدادات فلا يمكن تخزينه ذاتيًا) — تُظهر الواجهة تحذيرًا واضحًا
عند غيابه ولا تعرض تخزينه أبدًا. كلمة مرور CHR مقنّعة مع كشف مؤقت للمسؤول العام، وكل
تغيير مُدقَّق، ويبقى مفهوم القفل ساريًا. الواجهة تعرض أيضًا أوامر RouterOS الجاهزة
لقفل نقطة REST على IP اللوحة (`chr_settings.lockdown_commands()`).

**النقل (transport) — مهم:** اللوحة تتصل بـ CHR عبر **REST API لـ RouterOS v7 فوق
HTTPS** (`https://<host>:<port>/rest`) المخدوم بخدمة **www-ssl**، وليس واجهة API
الثنائية (8728/8729). بما أن **SSTP يشغل 443** في نشر المالك، يجب أن تعمل www-ssl
على منفذ بديل (**8443**) — وهو الافتراضي الآن (`CHR_REST_DEFAULT_PORT=8443`،
`_default_port()`). منفذ SSTP الذي يتصل به العميل يبقى 443 (منفصل عن منفذ الإدارة).
الشهادة Let's Encrypt صالحة على النطاق فيمكن تفعيل `CHR_TLS_VERIFY=1` بأمان، مع بقاء
تجاوز التحقق متاحًا كاحتياط للشهادات الموقّعة ذاتيًا.

**تقييد IP المتحكّم بـ CHR — على جانب RouterOS لا التطبيق:** السماح لعنوان اللوحة وحده
(`178.105.180.6/32`) بالتحكّم في نقطة REST يُفرَض على RouterOS عبر `address=` لخدمة
www-ssl (و/أو جدار النار)، لا في الكود. التطبيق يتصل صادرًا فقط. `CHR_API_ALLOWED_IP`
في الإعدادات توثيقية فقط (غير مقروءة للتنفيذ).

**نشر المالك الحالي:** RouterOS 7.21.4، المضيف `vpn-test.hoberadius.com` /
`178.105.244.112`، شهادة `Lets encrypt1780754140`، SSTP على 443، REST (www-ssl)
على 8443، وعنوان اللوحة المسموح `178.105.180.6`.

**أتمتة IPsec:** `CHR_IPSEC_AUTO_PROVISION` (افتراضي 1)، `CHR_IPSEC_MANAGE_INFRA`
(افتراضي 1)، أسماء البنية `CHR_IPSEC_PEER`/`CHR_IPSEC_MODE_CONFIG`/`CHR_IPSEC_PROFILE`
(افتراضي `hoberadius`/`hoberadius`/`default`)، `CHR_IPSEC_EAP_METHODS`
(افتراضي `eap-mschapv2`)، ومتطلّبات المالك لمرّة واحدة:
`CHR_IPSEC_ADDRESS_POOL`، `CHR_IPSEC_DNS`، `CHR_IPSEC_CERTIFICATE`.

**العنوان العام للعملاء:** يُدخله المالك في إعدادات اللوحة (لا في البيئة):
العنوان العام + منفذ كل خدمة (SSTP/PPTP/L2TP/IPsec). يُسلَّم في رد الجسر كحقلَي
`chr_public_host` و`service_port` لكل نفق.

## 6) قفل اتصال CHR (ملكية حصرية للّوحة)

اتصال CHR (مضيف/منفذ/مستخدم/كلمة مرور مشفّرة/TLS) يُخزَّن **هنا فقط** ولا يُعاد أبداً
في أي رد جسر للوحات العملاء. ضماناً لذلك يُسلَّم في الجسر **العنوان العام فقط**
(`chr_public_host`/`service_port`)؛ مضيف REST الإداري لا يُسرَّب (حتى حقل `chr_host`
في رد الجسر صار يحمل العنوان العام لا الإداري).

**القفل:** بمجرد اكتمال الاتصال ونجاح اختباره يُقفَل تلقائياً (`chr.locked`). بعد القفل
لا يُكتب فوق الإعدادات إلا بـ: مسؤول عام + تأكيد صريح (`confirm_locked_change`) ويُسجَّل
بإجراء `chr_settings_overwritten_while_locked`. قفل/فكّ يدوي صريح متاح للمسؤول العام
(`/admin/settings/chr/lock` و`/unlock`، مُدقَّقان). كلمة مرور CHR تبقى مقنّعة ولا
تُكشف إلا للمسؤول العام مؤقتاً (نمط whatsapp/vault).

## 7) وحدة تحكّم CHR المركزية (CHR Console)

صفحة `/admin/chr/console` (محروسة بصلاحية `chr_console` — المسؤول العام دائماً مسموح،
عبر `chr_console_required`؛ مفعّلة بعلم `CHR_CONSOLE_ENABLED`). تعطي تحكّماً كاملاً عبر
`routeros_client`: عرض نظام/هوية/إصدار CHR، مستخدمي الأنفاق (`/ppp/secret`) ومستخدمي
IPsec (تعطيل/تفعيل/حذف)، الجلسات النشطة (`ppp/active`, `ip/ipsec/active-peers`)،
والواجهات. الإجراءات غير القابلة للتراجع (حذف مستخدم، إعادة تشغيل CHR) خلف تأكيد صريح
ومحصورة بالمسؤول العام ومُدقَّقة. الطبقة في `app/services/chr_console.py` (لا ترفع).

**المرونة (resilience):** `overview()` يجلب **كل قسم على حِدة**. إن رفض CHR نداء REST
واحداً (مثلاً 400 «Bad Request» على مسار بعينه) يبقى الخطأ محصوراً في قسمه فيظهر
«غير متاح (رسالة الخطأ)» وتظل بقية الأقسام تعمل — لا تسقط الوحدة كلها كما كان يحدث.
`ok=False` فقط حين لا يكون CHR مضبوطاً؛ `reachable=False` حين لا يستجيب أي قسم.
للتشخيص: `routeros_client._request` يسجّل سطراً آمناً عند أي خطأ HTTP يحوي المنهج
والمسار والحالة بالضبط (`RouterOS REST GET /rest/<path> -> HTTP 400`)، فيُعرَف المسار
المرفوض فوراً دون كشف أسرار. مسارات v7 المستخدمة (مطابقة لشجرة CLI): `system/resource`،
`system/identity`، `ppp/secret`، `ppp/active`، `ip/ipsec/user`، `ip/ipsec/identity`،
`ip/ipsec/active-peers`، `interface`.

## 8) التحكّم بالسرعة (Speed control) — جوهر المنتج

عند إنشاء النفق يحدّد المدير سرعته: إمّا **بروفايل سرعة محفوظ** أو **سرعة مخصّصة**
(تنزيل/رفع Mbps). تُطبَّق فعلًا على CHR لا مجرّد البروفايل الافتراضي.

**كيف تُطبَّق على CHR (PPP):** السرعة تُترجَم إلى `rate-limit` على `/ppp/profile`، ثم
يُسنَد ذلك البروفايل إلى `/ppp/secret`. اتجاه RouterOS `rx/tx` من منظور الراوتر:
`rx`=رفع العميل، `tx`=تنزيله ⇒ السلسلة `<upload>M/<download>M`. التهيئة idempotent
عبر `routeros_client.ensure_ppp_profile(name, rate_limit)` (تُنشئ البروفايل أو تُحدّث
سرعته إن اختلفت) قبل إنشاء الحساب. ينطبق على **SSTP/PPTP/L2TP**.

**بروفايلات السرعة (CRUD):** نموذج `ChrSpeedProfile` (اسم/رمز/تنزيل/رفع/حدّ جلسات/نشط)
يُدار من صفحة «بروفايلات السرعة» (`/admin/chr/speed-profiles`)، ويُطابَق إلى
`/ppp/profile` باسم `hob-<code>` (قابل للتخصيص). السرعة المخصّصة تُنشئ بروفايلًا باسم
`hob-<down>d-<up>u`. الطبقة في `app/services/speed_profiles.py`. زرّ «مزامنة CHR» يهيّئ
البروفايل على الراوتر يدويًا للتحقق.

**IPsec:** لا يُشكَّل عبر `rate-limit` الخاص بـ PPP — تُسجَّل السرعة على النفق فقط مع
ملاحظة صريحة (طبّق `simple queue` على CHR إن لزم). لا تجاهل صامت.

**العرض:** السرعة المطبَّقة تظهر في قائمة الأنفاق، وتُدرَج في رد الجسر كحقلَي
`download_mbps`/`upload_mbps` (معلومة لا سرّ) — دون أي وصول CHR للعميل.

## 9) قرارات/نقاط مؤجَّلة (لم تُخترَع)

- **حدّ الاتصالات المتزامنة لكل حساب** — لـ PPP (`only-one` على `/ppp/profile`)
  ولـ IPsec (لا يدعم RouterOS حدًّا لكل مستخدم EAP بسهولة) غير مفروض آليًا بعد؛
  الحدّ الحالي على **عدد الأنفاق** لكل عميل (`max_vpn_users`/`CHR_DEFAULT_MAX_TUNNELS`).
  `max_connections` مخزَّن ويُمرَّر للعميل كإشارة.
- **شهادة خادم IKEv2 ومجمّع العناوين** متطلّبان لمرّة واحدة على CHR يضبطهما المالك
  (`CHR_IPSEC_CERTIFICATE`/`CHR_IPSEC_ADDRESS_POOL`) — لا يُولَّدان من الكود لأن
  توليد/تثبيت الشهادات عملية حسّاسة منفصلة على RouterOS.
