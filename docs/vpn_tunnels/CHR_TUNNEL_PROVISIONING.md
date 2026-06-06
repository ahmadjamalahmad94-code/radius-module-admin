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
الاتصالات). SSTP/PPTP/L2TP تُنشأ فعليًا على CHR؛ ثم يسحبها العميل عبر الجسر.

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
    "chr_host": "vpn-test.hoberadius.com", "chr_provisioned": true,
    "delivery_status": "pending", "created_at": "...Z" } }
```
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

## 6) قرارات/نقاط مؤجَّلة (لم تُخترَع)

- **IPsec (IKEv2)** نظام مختلف على RouterOS (`/ip/ipsec` لا `/ppp/secret`). في
  المرحلة الأولى يُسجَّل سجل النفق ويُسلَّم عبر الجسر **دون** إنشاء تلقائي على CHR
  (المدير يضبط الند/الهوية يدويًا). الأتمتة الكاملة لـ IPsec = مرحلة لاحقة.
- **حدّ الاتصالات المتزامنة لكل حساب** (`only-one` على `/ppp/profile`) غير مفروض
  آليًا بعد؛ `max_connections` مخزَّن ويُمرَّر للعميل كإشارة. ربطه ببروفايل مخصص على
  CHR = تحسين لاحق.
- **عنوان CHR العام/المنفذ لكل خدمة** (الذي يتصل به عميل العميل) لم يُضمَّن في الرد
  بعد — يمكن إضافته كحقل إعداد (مثل `chr.public_endpoint`) عند الحاجة.
