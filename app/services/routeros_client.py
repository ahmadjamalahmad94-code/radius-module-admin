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
