# خيار «سوبر يوزر» الصريح لمستخدم العميل (Super User Toggle)

## الهدف
منح مالك الحساب في لوحة التراخيص تحكّماً **صريحاً ومرئياً وموثوقاً** بجعل مستخدم
عميل معيّن **مشرفاً كاملاً (`is_super_admin = 1`)** على راديوس العميل عبر الجسر،
بصرف النظر عن دوره (`role_key`). بعد ذلك يفتح له الراديوس كل الأقسام ويدير هو
صلاحيات بقية المدراء محلياً من الراديوس.

سابقاً كان السوبر يُشتق ضمنياً من `role_key == "owner"` فقط على جانب الراديوس،
ولم يكن هناك تحكّم صريح من المركز. الآن أصبح علماً صريحاً يسافر في حمولة المزامنة.

## ما تم تنفيذه في لوحة التراخيص (هذا الريبو)

| الطبقة | الملف | التغيير |
|--------|-------|---------|
| النموذج | `app/models.py` | عمود `CustomerUser.is_super` (Boolean, default False) + خاصية `is_effective_super` (= `is_super` أو `role_key=="owner"`). |
| الهجرة | `app/__init__.py` → `ensure_schema_compatibility` | إضافة عمود `is_super` للجدول `customer_users` بشكل idempotent (يتجاهل إن وُجد). |
| الجسر | `app/services/customer_control.py` → `build_identity_sync_contract` | كل مستخدم في الحمولة صار يحمل `"is_super": user.is_effective_super`. |
| المعالج | `app/admin/routes.py` → `_fill_customer_user` | قراءة خانة `is_super` من النموذج وحفظها + تضمينها في سجل التدقيق. |
| النموذج (واجهة) | `app/templates/admin/customer_user_form.html` | خانة «سوبر يوزر — صلاحية كاملة» (مفعّلة ومقفلة لمالك الحساب). |
| التفاصيل (واجهة) | `app/templates/admin/customer_detail.html` | شارة «سوبر يوزر» 👑 بجانب الدور لكل مستخدم سوبر فعلي. |

### عقد المزامنة بعد التعديل
نقطة النهاية: `POST /api/integration/hoberadius/identity-sync` (موقّعة HMAC، تتطلب HTTPS).

```jsonc
{
  "ok": true,
  "customer_id": 12,
  "license_key": "....",
  "version": 4,
  "users": [
    {
      "external_user_id": 5,
      "username": "manager",
      "email": "m@example.com",
      "full_name": "Manager",
      "role_key": "admin",
      "is_super": true,            // ← جديد: العلم الصريح
      "active": true,
      "password_hash": "scrypt:...",
      "password_hash_scheme": "werkzeug",
      "password_version": 4,
      "updated_at": "2026-06-06T00:00:00Z"
    }
  ]
}
```

`is_super` = `true` إذا كان العلم الصريح مفعّلاً **أو** الدور `owner` (توافق رجعي).

## العقد المطلوب على جانب الراديوس (radius-module) — لإكماله لاحقاً

> لم يُعدَّل `radius-module` من هنا. هذا هو التغيير المطلوب هناك ليقرأ العلم الصريح.

في دالة استهلاك مزامنة الهوية (`upsert_license_admin_user` أو ما يكافئها) التي
تقرأ كل عنصر من `users[]`:

**قبل (السلوك القديم — تخمين ضمني):**
```python
is_super_admin = 1 if user.get("role_key") == "owner" else 0
```

**بعد (المطلوب — قراءة العلم الصريح مع إبقاء توافق owner):**
```python
# يفضّل العلم الصريح القادم من المركز؛ يسقط إلى تخمين owner إن غاب الحقل
# (توافق مع لوحات أقدم لا ترسل is_super بعد).
is_super_admin = 1 if user.get(
    "is_super",
    user.get("role_key") == "owner",
) else 0
```

### خصائص السلوك المطلوبة على الراديوس
1. **Idempotent ولا يُداس:** عند كل تسجيل دخول (إن كان
   `HOBERADIUS_ADMIN_IDENTITY_SYNC_ON_LOGIN` مفعّلاً) يُعاد ضبط
   `is_super_admin` من العلم الصريح في الحمولة — فالمصدر الموثوق هو المركز.
   لذلك أي تعديل SQL يدوي على الراديوس مؤقت ويُداس عند المزامنة التالية (مقصود).
2. **توافق رجعي:** إن لم يحتوِ العنصر على `is_super` (لوحة أقدم) يبقى المنطق
   القديم `role_key=="owner"` ساريًا عبر القيمة الافتراضية في `.get`.
3. **لا تخفيض صامت للمالك:** بما أن المركز يرسل `is_super=true` للمالك دائماً
   (عبر `is_effective_super`)، يظل المالك سوبر بعد المزامنة.

## السلوك النهائي للمستخدم
1. المالك يفتح «تعديل مستخدم العميل» في لوحة التراخيص ويفعّل «سوبر يوزر — صلاحية كاملة».
2. عند دخول المستخدم على راديوسه (أو أول مزامنة هوية) يصبح `is_super_admin = 1` تلقائياً.
3. تُفتح له كل الأقسام، ويدير صلاحيات بقية المدراء بنفسه محلياً من الراديوس.
4. لإلغاء السوبر: يلغي المالك الخانة من المركز → تُدفع `is_super=false` في المزامنة
   التالية (إلا لمالك الحساب فيبقى سوبراً ضمنياً).

## التحقق
- `python -m py_compile` على الملفات المعدّلة — ناجح.
- اختبارات `tests/test_customer_control_layer.py` — ناجحة، وتشمل:
  - `test_identity_sync_carries_explicit_is_super_flag` (دفع العلم للسوبر/المالك ونفيه للعادي).
  - `test_customer_user_form_persists_explicit_is_super` (حفظ العلم من النموذج).
