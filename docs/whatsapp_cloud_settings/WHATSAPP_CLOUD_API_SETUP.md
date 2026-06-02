# WhatsApp Cloud API — settings panel setup guide

Manage the house **Meta WhatsApp Cloud API** credentials from the license panel
UI instead of editing environment variables. Credentials are stored encrypted
(Fernet) in the panel `settings` table; environment variables act as a fallback.

## Required Meta values

| Field (UI) | Required | Notes |
|---|---|---|
| رمز الوصول (Access Token) | ✅ | Secret. Stored encrypted, never shown. |
| Phone Number ID | ✅ | Numeric. From Meta → WhatsApp → API setup. |
| WhatsApp Business Account ID (WABA) | ✅ | Numeric. |
| Meta App ID | optional | Numeric. Needed for Embedded Signup / template management. |
| Meta App Secret | optional | Secret. Stored encrypted. Used to verify webhook signatures. |
| Embedded Signup Config ID | optional | Numeric. For the customer-portal self-service signup. |

## Where to paste them

License panel → **الإعدادات** → section **«واتساب Cloud API»**
(visible only when `WHATSAPP_CLOUD_SETTINGS_ENABLED=1`).

1. Fill the fields above. Secrets are **write-only**: leave a secret field blank
   to keep the stored value; type a new value to replace it.
2. Click **«حفظ الإعدادات»**.
3. Each field shows its **source**: «محفوظ في إعدادات اللوحة» (DB) or
   «مُحمّل من البيئة» (env). A saved DB value overrides its env fallback.
4. Super admins can use **«إظهار مؤقت»** to reveal a stored secret for ~20s
   (this action is written to the audit log).

## Test the connection

Click **«اختبار الاتصال»**. The panel calls Meta to verify the access token +
phone number, and (best-effort) that the Business Account is reachable. You get
a friendly Arabic success/failure message; both outcomes are audited.

## Discover your templates

Click **«اكتشاف القوالب المعتمدة»**. The panel lists the WABA's templates as
chips (`name · language · status`) with a requirement hint:

- **جاهز / موصى به** — approved, no variables, no media → safest one-click test
  (e.g. `hello_world`, `jaspers_market_plain_text_v1`).
- **N متغيّر (تلقائي)** — has body variables; the test auto-fills placeholder text.
- **يحتاج وسائط** — needs an image/video/document header → can't be auto-tested.

Click a chip to fill the template name + language automatically.

## Send a test message

Enter the recipient's WhatsApp number in **international format without `+`**
(e.g. `9705xxxxxxxx`), pick a template (default `hello_world` / `en_US`), and
click **«إرسال رسالة اختبار»**.

> WhatsApp does **not** allow free-form text outside the 24-hour customer-service
> window, so the test always sends an **approved template**. Templates with body
> variables are auto-filled with placeholder text; media-header templates are
> refused with a clear message — use `hello_world` for a quick check.

## Test / sandbox vs production

- A **test number** provided by Meta can only message recipients you add to the
  app's allow-list, and uses Meta's test credits.
- A **production number** (verified business, payment method attached) can
  message any opted-in number and is billed by Meta per conversation.
- Approve your own templates in Meta before relying on them in production. The
  default `jaspers_market_*` samples are for trials; create your own (e.g. an
  Arabic `utility` template) for real notifications.
- Point the Meta app's webhook callback to `https://<panel-host>/api/whatsapp/webhook`.

## Security — do NOT expose access tokens

- The access token and app secret are **secrets**. They are stored **encrypted**,
  never rendered into the page, never written to logs, and never returned in
  error messages.
- Treat a leaked token as full control of your WhatsApp sending — **rotate it in
  Meta immediately** if exposed, then paste the new one here.
- Only super admins can reveal a stored secret, and every reveal is audited.
- Never commit real tokens to git or share screenshots that show them.
