# Runbook — onboarding a new CHR node (clean, deterministic)

**Audience:** the panel owner/operator. Every step is UI or one CHR-side
import — **no manual SQL**. If a step forces you into SQL, that's a bug;
stop and report it.

This runbook bakes in every lesson from the first live install
(wrong peer pubkey, /32 routing trap, api-ssl vs www-ssl, service ACL
direction, firewall rule order, SQLite split-brain).

---

## 0. The architecture you are building

```
License Panel VPS                         RADIUS Proxy
  wg-mgmt 10.99.0.1  ◄────────►  CHR      wg-data 10.98.0.1 ◄────► CHR
  (REST 8443, health,            wg-mgmt = 10.99.0.11/24
   metrics, provisioning)        wg-data = 10.98.0.11/24
                                          (RADIUS 1812/1813 + CoA 3799 only)
```

* The panel does NOT have `wg-data`. `ping 10.98.0.11` from the panel
  **fails by design** — test the data plane from the CHR
  (`/ping 10.98.0.1`) or from the proxy.
* The panel talks to the CHR **only** via REST over HTTPS on
  `https://10.99.0.X:8443/rest/...` (`www-ssl`). Never the binary
  api/api-ssl (8728/8729).

## 1. One-time fleet prerequisites (before the FIRST node ever)

Open **أسطول CHR → إعدادات بنية الأسطول** and complete ALL of:

| القيمة | من أين |
|---|---|
| مفتاح اللوحة العام (wg-mgmt) | زر «توليد مفتاح اللوحة» — انسخ المفتاح العام |
| نقطة وصول اللوحة Host:Port | عنوان اللوحة العام + 51820 |
| مفتاح وكيل RADIUS العام (wg-data) | من جهاز الـ proxy: `wg show wg-data public-key` |
| نقطة وصول الوكيل Host:Port | عنوان الـ proxy العام + 51821 |
| السر المشترك لـ RADIUS | زر التوليد أو الصقه (نفسه على الـ proxy) |
| بيانات اعتماد قراءة المقاييس | اسم مستخدم + كلمة مرور REST الافتراضية للأسطول |

**The wizard will REFUSE to generate a script while any of the first
five are missing** — and tells you exactly which («بانتظار: …»). That
refusal is intentional; do not work around it with SQL.

## 2. Create the node

أسطول CHR → معالج إضافة CHR → fill provider / name / public IP → submit.
The node appears on the dashboard as `provisioning` with its assigned
wg-mgmt IP (`10.99.0.X`).

## 3. Generate + import the script

1. «عرض السكربت» on the node row → copy the full `.rsc`.
2. On the CHR (console or Winbox terminal): paste/import. Re-importing
   is always safe — every block removes its prior copy first.
3. Watch the CHR log (`/log print follow`) — the script prints:
   - `hobe-fleet: resolved <host> -> <ip>` (endpoint resolution),
   - the THREE key-identity lines (expected panel key, expected proxy
     key, this CHR's own key). **Compare the panel key against
     «إعدادات بنية الأسطول» right now** — a mismatch here was the
     hardest field bug to find after the fact.

## 4. Wire the panel side of wg-mgmt

On the panel host, add/update the CHR peer (the panel's wg-mgmt is a
real WireGuard interface on the VPS):

```sh
sudo wg set wg-mgmt peer <CHR_WG_MGMT_PUBKEY> allowed-ips 10.99.0.X/32
```

The CHR's pubkey is on the node row in the dashboard, and the CHR also
logs it («this CHR wg-mgmt pubkey (give to panel)»).
Peer `allowed-ips` is **/32** — always. Only interface addresses are /24.

## 5. Verify — all from the panel UI

1. Node row → «فحص الآن» → ping over wg-mgmt goes green.
2. Node row → **«تحقق من مفاتيح WireGuard»** (the new verify endpoint)
   → must say «مفاتيح WireGuard متطابقة في الاتجاهين». If it says
   `panel_key_mismatch`, re-import the freshly generated script.
3. Node row → «اقرأ المقاييس الآن» → CPU/sessions populate.
   If it errors, the message now names the exact broken credential
   source (per-node decrypt failure vs fleet default missing) — go to
   the screen it names.

## 6. Data-plane check (CHR side, not panel side)

```
/ping 10.98.0.1                  ← proxy reachable over wg-data
/radius print detail             ← address=10.98.0.1 src-address=10.98.0.X, NOT disabled
```

Then run a real PPP test-auth through the proxy.

## 7. What you should NEVER need

* `sqlite3` against the panel DB for onboarding. If a value is missing,
  it has a UI home (إعدادات بنية الأسطول / صف العقدة).
* Touching `/ip service` by hand — §11 of the script configures
  www-ssl 8443 + cert + source-ACL (panel IP /32) and disables
  api/api-ssl/www.
* Re-ordering firewall rules by hand — the script hoists its allow
  rules above any stale drop on every import.

## Troubleshooting quick table

| العرض | السبب الأرجح | الفحص |
|---|---|---|
| ping 10.99.0.X يفشل من اللوحة | مفتاح peer خاطئ على أحد الطرفين | زر «تحقق من مفاتيح WireGuard»؛ سجل CHR يطبع المفاتيح المتوقعة |
| TLS ينجح على المنفذ لكن REST يفشل | المنفذ binary api-ssl وليس www-ssl | `/ip service print` — يجب www-ssl=8443 مفعّلة بشهادة |
| nc إلى 8443 يعلق | drop قديم فوق allow، أو ACL الخدمة يشير لغير IP اللوحة | أعد استيراد السكربت (يرفع الـ allows ويصحح ACL) |
| «لا توجد بيانات اعتماد API» رغم وجودها | فشل فك تشفير (مفتاح Fernet تغيّر) | الرسالة الجديدة تسمي المصدر؛ أعد إدخال كلمة المرور من الشاشة المسماة |
| ping 10.98.0.11 من اللوحة يفشل | طبيعي — اللوحة بلا wg-data | افحص من CHR: `/ping 10.98.0.1` |
