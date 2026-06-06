"""عميل RouterOS REST API (لـ MikroTik CHR) مبني على urllib من المكتبة القياسية.

نتبع نفس فلسفة ``app/services/whatsapp/providers.py``:

* المكان الوحيد الذي يلمس الشبكة هو :meth:`RouterOSClient._request` — صغير عمدًا
  كي تستطيع الاختبارات استبداله (monkeypatch) دون الاتصال بأي CHR حقيقي.
* كلمات المرور أسرار: تُمرَّر فقط داخل ترويسة ``Authorization: Basic`` أو جسم
  الطلب، ولا تُوضع أبدًا في نص استثناء أو سجل.
* الأخطاء تُرفع كـ :class:`RouterOSError` بحقل ``code`` آلي ورسالة عربية آمنة
  وعلم ``retryable`` كي تقرّر طبقة التزويد إعادة المحاولة من عدمها.

RouterOS v7 يوفّر REST API على ``https://<host>:<port>/rest/...`` فوق HTTPS.
``requests`` ليست من اعتماديات المشروع، لذا نستخدم ``urllib``.
"""
from __future__ import annotations

import base64
import json
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from typing import Any


class RouterOSError(Exception):
    """فشل على مستوى CHR يُعرض لطبقة التزويد.

    الأمان: الصيغة النصية لهذا الاستثناء يجب ألا تحتوي أبدًا كلمة مرور أو جسم
    طلب خام — فقط ``code`` والرسالة العربية المُنسّقة.
    """

    def __init__(
        self,
        code: str,
        message: str,
        *,
        retryable: bool = False,
        http_status: int | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.retryable = bool(retryable)
        self.http_status = http_status


class RouterOSClient:
    """غلاف رفيع حول REST API الخاص بـ RouterOS.

    لا يخزّن أي حالة عدا بيانات الاتصال؛ آمن لإنشائه عند الطلب لكل عملية.
    """

    def __init__(
        self,
        *,
        host: str,
        port: int = 443,
        username: str,
        password: str,
        use_tls: bool = True,
        verify_tls: bool = False,
        timeout: int = 15,
    ) -> None:
        self.host = (host or "").strip()
        self.port = int(port or (443 if use_tls else 80))
        self.username = username or ""
        self._password = password or ""
        self.use_tls = bool(use_tls)
        self.verify_tls = bool(verify_tls)
        self.timeout = int(timeout or 15)

    # ───────────────────────── network (the only I/O point) ─────────────────

    def _base_url(self) -> str:
        scheme = "https" if self.use_tls else "http"
        return f"{scheme}://{self.host}:{self.port}/rest"

    def _auth_header(self) -> str:
        raw = f"{self.username}:{self._password}".encode("utf-8")
        return "Basic " + base64.b64encode(raw).decode("ascii")

    def _ssl_context(self) -> ssl.SSLContext | None:
        if not self.use_tls:
            return None
        if self.verify_tls:
            return ssl.create_default_context()
        # CHR يأتي بشهادة موقّعة ذاتيًا — نتجاوز التحقق ما لم يفعّله المالك.
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        body: dict[str, Any] | None = None,
    ) -> Any:
        """ينفّذ طلب REST واحدًا ويعيد JSON المُحلَّل (dict/list) أو None.

        يرفع :class:`RouterOSError` عند أي فشل نقل/مصادقة/تحقق.
        """
        if not self.host:
            raise RouterOSError("not_configured", "لم يتم ضبط مضيف CHR.")
        url = self._base_url() + "/" + path.lstrip("/")
        if params:
            url += "?" + urllib.parse.urlencode(params)

        data = None
        headers = {
            "Authorization": self._auth_header(),
            "Accept": "application/json",
        }
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"

        req = urllib.request.Request(url, data=data, method=method.upper(), headers=headers)
        ctx = self._ssl_context()
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as resp:
                raw = resp.read()
        except urllib.error.HTTPError as exc:
            raise self._http_error(exc) from None
        except (urllib.error.URLError, socket.timeout, TimeoutError, ConnectionError, OSError) as exc:
            # لا نُدرج تفاصيل النظام الخام (قد تكشف بنية الشبكة)؛ كود عام قابل لإعادة المحاولة.
            reason = getattr(exc, "reason", None)
            if isinstance(reason, ssl.SSLError) or isinstance(exc, ssl.SSLError):
                raise RouterOSError(
                    "tls_error",
                    "تعذّر إنشاء اتصال TLS آمن مع CHR (تحقق من الشهادة أو عطّل التحقق).",
                    retryable=False,
                ) from None
            raise RouterOSError(
                "connect_failed",
                "تعذّر الاتصال بمضيف CHR (تحقق من العنوان والمنفذ وأن REST مفعّل).",
                retryable=True,
            ) from None

        if not raw:
            return None
        try:
            return json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            raise RouterOSError("bad_response", "رد CHR غير صالح (ليس JSON).") from None

    def _http_error(self, exc: urllib.error.HTTPError) -> RouterOSError:
        status = exc.code
        # نحاول قراءة رسالة RouterOS لكن دون كشف أسرار؛ نُبقي الرسالة عربية موجزة.
        detail = ""
        try:
            payload = json.loads(exc.read().decode("utf-8"))
            if isinstance(payload, dict):
                detail = str(payload.get("message") or payload.get("detail") or "")[:160]
        except Exception:  # noqa: BLE001 — أي فشل قراءة لا يجب أن يُخفي الكود الأصلي
            detail = ""
        if status in (401, 403):
            return RouterOSError(
                "auth_failed",
                "فشل مصادقة CHR (تحقق من اسم المستخدم وكلمة المرور وصلاحياتهما).",
                http_status=status,
            )
        if status == 404:
            return RouterOSError("not_found", "العنصر المطلوب غير موجود على CHR.", http_status=status)
        if status >= 500:
            return RouterOSError(
                "chr_server_error",
                "خطأ داخلي في CHR" + (f" — {detail}" if detail else "") + ".",
                retryable=True,
                http_status=status,
            )
        return RouterOSError(
            "request_invalid",
            "طلب غير مقبول من CHR" + (f" — {detail}" if detail else "") + ".",
            http_status=status,
        )

    # ───────────────────────── high-level helpers ─────────────────────────

    def test_connection(self) -> dict[str, str]:
        """فحص حيوية الاتصال: يقرأ هوية ومورد النظام. يرفع RouterOSError عند الفشل."""
        resource = self._request("GET", "system/resource") or {}
        identity = self._request("GET", "system/identity") or {}
        if isinstance(resource, list):  # بعض الإصدارات تُعيد قائمة بعنصر واحد
            resource = resource[0] if resource else {}
        if isinstance(identity, list):
            identity = identity[0] if identity else {}
        return {
            "identity": str(identity.get("name") or ""),
            "version": str(resource.get("version") or ""),
            "board_name": str(resource.get("board-name") or ""),
            "uptime": str(resource.get("uptime") or ""),
        }

    def list_ppp_secrets(self, *, service: str | None = None) -> list[dict[str, Any]]:
        params = {"service": service} if service else None
        result = self._request("GET", "ppp/secret", params=params)
        return result if isinstance(result, list) else []

    def find_ppp_secret(self, name: str) -> dict[str, Any] | None:
        result = self._request("GET", "ppp/secret", params={"name": name})
        if isinstance(result, list) and result:
            return result[0]
        return None

    def create_ppp_secret(
        self,
        *,
        name: str,
        password: str,
        service: str = "sstp",
        profile: str = "default",
        remote_address: str = "",
        comment: str = "",
    ) -> dict[str, Any]:
        """ينشئ ``/ppp/secret`` ويُعيد العنصر المُنشأ (يتضمن ``.id``)."""
        body: dict[str, Any] = {
            "name": name,
            "password": password,
            "service": service,
            "profile": profile or "default",
        }
        if remote_address:
            body["remote-address"] = remote_address
        if comment:
            body["comment"] = comment
        created = self._request("PUT", "ppp/secret", body=body)
        if isinstance(created, list):
            created = created[0] if created else {}
        return created if isinstance(created, dict) else {}

    def remove_ppp_secret(self, secret_id: str) -> None:
        """يحذف ``/ppp/secret`` بمعرّفه (.id). يتجاهل 404 (محذوف مسبقًا)."""
        if not secret_id:
            return
        try:
            self._request("DELETE", "ppp/secret/" + urllib.parse.quote(secret_id, safe=""))
        except RouterOSError as exc:
            if exc.code == "not_found":
                return
            raise

    def set_ppp_secret_disabled(self, secret_id: str, disabled: bool) -> None:
        """يفعّل/يعطّل ``/ppp/secret`` (للتعليق دون حذف)."""
        if not secret_id:
            return
        self._request(
            "PATCH",
            "ppp/secret/" + urllib.parse.quote(secret_id, safe=""),
            body={"disabled": "yes" if disabled else "no"},
        )

    # ───────────────────────── IPsec (IKEv2) helpers ─────────────────────────
    # IPsec على RouterOS نظام مستقل عن ``/ppp/secret``. لمستخدمي IKEv2 بكلمة مرور
    # (EAP-MSCHAPv2) تُخزَّن بيانات الاعتماد في ``/ip/ipsec/user``، وتُهيَّأ البنية
    # المشتركة (mode-config/peer/identity) مرّة واحدة. كل الدوال idempotent: تبحث
    # قبل الإنشاء فلا تُكرّر عنصرًا موجودًا.

    def _find_one(self, path: str, query: dict[str, Any]) -> dict[str, Any] | None:
        """GET على ``path`` مع ترشيح ``query``؛ يعيد أول تطابق أو None."""
        result = self._request("GET", path, params=query)
        if isinstance(result, list) and result:
            first = result[0]
            return first if isinstance(first, dict) else None
        if isinstance(result, dict):
            return result
        return None

    @staticmethod
    def _new_id(created: Any) -> str:
        if isinstance(created, list):
            created = created[0] if created else {}
        if isinstance(created, dict):
            return str(created.get(".id") or created.get("id") or "")
        return ""

    def find_ipsec_user(self, name: str) -> dict[str, Any] | None:
        return self._find_one("ip/ipsec/user", {"name": name})

    def create_ipsec_user(self, *, name: str, password: str, comment: str = "") -> dict[str, Any]:
        """ينشئ ``/ip/ipsec/user`` (بيانات اعتماد EAP لمستخدم IKEv2) ويعيد العنصر."""
        body: dict[str, Any] = {"name": name, "password": password}
        if comment:
            body["comment"] = comment
        created = self._request("PUT", "ip/ipsec/user", body=body)
        if isinstance(created, list):
            created = created[0] if created else {}
        return created if isinstance(created, dict) else {}

    def remove_ipsec_user(self, user_id: str) -> None:
        """يحذف ``/ip/ipsec/user`` بمعرّفه. يتجاهل 404 (محذوف مسبقًا)."""
        if not user_id:
            return
        try:
            self._request("DELETE", "ip/ipsec/user/" + urllib.parse.quote(user_id, safe=""))
        except RouterOSError as exc:
            if exc.code == "not_found":
                return
            raise

    def set_ipsec_user_disabled(self, user_id: str, disabled: bool) -> None:
        """يفعّل/يعطّل ``/ip/ipsec/user`` (للتعليق دون حذف)."""
        if not user_id:
            return
        self._request(
            "PATCH",
            "ip/ipsec/user/" + urllib.parse.quote(user_id, safe=""),
            body={"disabled": "yes" if disabled else "no"},
        )

    def ensure_ipsec_mode_config(
        self,
        *,
        name: str,
        address_pool: str = "",
        static_dns: str = "",
        system_dns: bool = True,
    ) -> dict[str, Any]:
        """يضمن وجود ``/ip/ipsec/mode-config`` باسمٍ ثابت (يُنشئه إن غاب)."""
        existing = self._find_one("ip/ipsec/mode-config", {"name": name})
        if existing:
            return existing
        body: dict[str, Any] = {"name": name, "responder": "yes"}
        if address_pool:
            body["address-pool"] = address_pool
        if static_dns:
            body["static-dns"] = static_dns
        elif system_dns:
            body["system-dns"] = "yes"
        created = self._request("PUT", "ip/ipsec/mode-config", body=body)
        return created if isinstance(created, dict) else {"name": name}

    def ensure_ipsec_peer(
        self,
        *,
        name: str,
        profile: str = "default",
        exchange_mode: str = "ike2",
        passive: bool = True,
        address: str = "0.0.0.0/0",
    ) -> dict[str, Any]:
        """يضمن وجود ``/ip/ipsec/peer`` مستمعٍ (responder) لـ IKEv2."""
        existing = self._find_one("ip/ipsec/peer", {"name": name})
        if existing:
            return existing
        body: dict[str, Any] = {
            "name": name,
            "exchange-mode": exchange_mode,
            "passive": "yes" if passive else "no",
            "address": address,
        }
        if profile:
            body["profile"] = profile
        created = self._request("PUT", "ip/ipsec/peer", body=body)
        return created if isinstance(created, dict) else {"name": name}

    def ensure_ipsec_identity(
        self,
        *,
        peer: str,
        mode_config: str,
        auth_method: str = "eap",
        eap_methods: str = "eap-mschapv2",
        generate_policy: str = "port-strict",
        certificate: str = "",
    ) -> dict[str, Any]:
        """يضمن وجود ``/ip/ipsec/identity`` لمصادقة EAP المرتبطة بالـpeer المشترك."""
        existing = self._find_one("ip/ipsec/identity", {"peer": peer})
        if existing:
            return existing
        body: dict[str, Any] = {
            "peer": peer,
            "auth-method": auth_method,
            "generate-policy": generate_policy,
            "mode-config": mode_config,
        }
        if auth_method == "eap" and eap_methods:
            body["eap-methods"] = eap_methods
        if certificate:
            body["certificate"] = certificate
        created = self._request("PUT", "ip/ipsec/identity", body=body)
        return created if isinstance(created, dict) else {"peer": peer}

    # ───────────────────────── console read helpers ─────────────────────────
    # قراءات فقط لوحدة تحكّم CHR (لا تغيّر شيئًا). كلها تعيد قائمة (أو dict للهوية/
    # المورد)؛ تُبقي الأخطاء كـ RouterOSError كي تعالجها طبقة الخدمة برسالة عربية.

    @staticmethod
    def _as_list(result: Any) -> list[dict[str, Any]]:
        if isinstance(result, list):
            return [r for r in result if isinstance(r, dict)]
        if isinstance(result, dict):
            return [result]
        return []

    @staticmethod
    def _as_dict(result: Any) -> dict[str, Any]:
        if isinstance(result, list):
            result = result[0] if result else {}
        return result if isinstance(result, dict) else {}

    def system_resource(self) -> dict[str, Any]:
        return self._as_dict(self._request("GET", "system/resource"))

    def system_identity(self) -> dict[str, Any]:
        return self._as_dict(self._request("GET", "system/identity"))

    def list_ppp_active(self) -> list[dict[str, Any]]:
        """الجلسات النشطة حاليًا (PPP) — مَن متصل الآن."""
        return self._as_list(self._request("GET", "ppp/active"))

    def list_ipsec_users(self) -> list[dict[str, Any]]:
        return self._as_list(self._request("GET", "ip/ipsec/user"))

    def list_ipsec_identities(self) -> list[dict[str, Any]]:
        return self._as_list(self._request("GET", "ip/ipsec/identity"))

    def list_ipsec_peers(self) -> list[dict[str, Any]]:
        return self._as_list(self._request("GET", "ip/ipsec/peer"))

    def list_ipsec_active_peers(self) -> list[dict[str, Any]]:
        """نظراء IPsec النشطون (جلسات IKEv2 الحالية)."""
        return self._as_list(self._request("GET", "ip/ipsec/active-peers"))

    def list_interfaces(self) -> list[dict[str, Any]]:
        return self._as_list(self._request("GET", "interface"))

    # ───────────────────────── admin action (destructive) ─────────────────────────

    def reboot(self) -> None:
        """يعيد تشغيل CHR. إجراء حسّاس — تحصره طبقة المسار بمسؤول عام + تأكيد + تدقيق."""
        self._request("POST", "system/reboot")
