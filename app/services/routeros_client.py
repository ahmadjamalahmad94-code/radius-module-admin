"""عميل RouterOS REST API (لـ MikroTik CHR) مبني على urllib من المكتبة القياسية.

نتبع نفس فلسفة ``app/services/whatsapp/providers.py``:

* المكان الوحيد الذي يلمس الشبكة هو :meth:`RouterOSClient._request` — صغير عمدًا
  كي تستطيع الاختبارات استبداله (monkeypatch) دون الاتصال بأي CHR حقيقي.
* كلمات المرور أسرار: تُمرَّر فقط داخل ترويسة ``Authorization: Basic`` أو جسم
  الطلب، ولا تُوضع أبدًا في نص استثناء أو سجل.
* الأخطاء تُرفع كـ :class:`RouterOSError` بحقل ``code`` آلي ورسالة عربية آمنة
  وعلم ``retryable`` كي تقرّر طبقة التزويد إعادة المحاولة من عدمها.

RouterOS v7 يوفّر REST API على ``https://<host>:<port>/rest/...`` فوق HTTPS عبر خدمة
``www-ssl`` (ليس واجهة API الثنائية 8728/8729). في نشر المالك يشغل SSTP المنفذ 443،
لذا تعمل ``www-ssl`` على منفذ بديل (8443). شهادة Let's Encrypt صالحة على النطاق فيمكن
تفعيل ``verify_tls`` بأمان، مع بقاء تجاوز التحقق متاحًا كاحتياط للشهادات الموقّعة ذاتيًا.
``requests`` ليست من اعتماديات المشروع، لذا نستخدم ``urllib``.
"""
from __future__ import annotations

import base64
import json
import logging
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

_log = logging.getLogger(__name__)


class RouterOSError(Exception):
    """فشل على مستوى CHR يُعرض لطبقة التزويد.

    الأمان: الصيغة النصية لهذا الاستثناء يجب ألا تحتوي أبدًا كلمة مرور أو جسم
    طلب خام — فقط ``code`` والرسالة العربية المُنسّقة.

    fix/chr-rest-500-and-api-auth — also carries the HTTP method + REST
    path that produced the failure (``request_method``/``request_path``)
    + a truncated REST-body excerpt (``response_excerpt``) so the
    troubleshoot UI can show «GET /rest/interface/wireguard?name=wg-mgmt
    → 500» instead of the unactionable «Internal Server Error».
    Secrets in the request body are NEVER stored on the exception
    (only the response body, which RouterOS authors).
    """

    def __init__(
        self,
        code: str,
        message: str,
        *,
        retryable: bool = False,
        http_status: int | None = None,
        request_method: str = "",
        request_path: str = "",
        response_excerpt: str = "",
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.retryable = bool(retryable)
        self.http_status = http_status
        self.request_method = request_method or ""
        self.request_path = request_path or ""
        self.response_excerpt = (response_excerpt or "")[:160]

    def endpoint_label(self) -> str:
        """Compact «METHOD /rest/<path>» token for log/UI surfaces."""
        if not self.request_method or not self.request_path:
            return ""
        path = self.request_path.lstrip("/")
        return f"{self.request_method.upper()} /rest/{path}"


class RouterOSClient:
    """غلاف رفيع حول REST API الخاص بـ RouterOS.

    لا يخزّن أي حالة عدا بيانات الاتصال؛ آمن لإنشائه عند الطلب لكل عملية.
    """

    def __init__(
        self,
        *,
        host: str,
        port: int = 8443,
        username: str,
        password: str,
        use_tls: bool = True,
        verify_tls: bool = False,
        timeout: int = 15,
    ) -> None:
        self.host = (host or "").strip()
        # REST عبر www-ssl؛ المنفذ الافتراضي 8443 (لا 443 لأنه مشغول بـ SSTP).
        self.port = int(port or (8443 if use_tls else 80))
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
        # fix/chr-rest-500-and-api-auth — keep the bare REST path (the
        # token AFTER /rest/, including any query string) and the
        # method so RouterOSError can surface «GET /rest/interface/
        # wireguard?name=wg-mgmt → 500». The body is omitted on
        # purpose: it may carry private keys / passwords.
        request_method = method.upper()
        rest_path = path.lstrip("/")
        if params:
            rest_path = rest_path + "?" + urllib.parse.urlencode(params)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as resp:
                raw = resp.read()
        except urllib.error.HTTPError as exc:
            # تشخيص آمن: المنهج والمسار والحالة فقط (دون أسرار/جسم) كي نحدّد بالضبط
            # أي نداء REST رُفض (مثلاً 400 على مسار معيّن في وحدة التحكّم).
            _log.warning("RouterOS REST %s /rest/%s -> HTTP %s", request_method, rest_path, exc.code)
            raise self._http_error(exc, method=request_method, path=rest_path) from None
        except (urllib.error.URLError, socket.timeout, TimeoutError, ConnectionError, OSError) as exc:
            # لا نُدرج تفاصيل النظام الخام (قد تكشف بنية الشبكة)؛ كود عام قابل لإعادة المحاولة.
            reason = getattr(exc, "reason", None)
            if isinstance(reason, ssl.SSLError) or isinstance(exc, ssl.SSLError):
                raise RouterOSError(
                    "tls_error",
                    "تعذّر إنشاء اتصال TLS آمن مع CHR (تحقق من الشهادة أو عطّل التحقق).",
                    retryable=False,
                    request_method=request_method, request_path=rest_path,
                ) from None
            raise RouterOSError(
                "connect_failed",
                "تعذّر الاتصال بمضيف CHR (تحقق من العنوان والمنفذ وأن REST مفعّل).",
                retryable=True,
                request_method=request_method, request_path=rest_path,
            ) from None

        if not raw:
            return None
        try:
            return json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            raise RouterOSError(
                "bad_response", "رد CHR غير صالح (ليس JSON).",
                request_method=request_method, request_path=rest_path,
                response_excerpt=raw[:120].decode("utf-8", errors="replace"),
            ) from None

    def _http_error(
        self,
        exc: urllib.error.HTTPError,
        *,
        method: str = "",
        path: str = "",
    ) -> RouterOSError:
        status = exc.code
        # نحاول قراءة رسالة RouterOS لكن دون كشف أسرار؛ نُبقي الرسالة عربية موجزة.
        detail = ""
        body_excerpt = ""
        try:
            raw_body = exc.read()
            body_excerpt = raw_body[:160].decode("utf-8", errors="replace")
            payload = json.loads(raw_body.decode("utf-8"))
            if isinstance(payload, dict):
                detail = str(payload.get("message") or payload.get("detail") or "")[:160]
        except Exception:  # noqa: BLE001 — أي فشل قراءة لا يجب أن يُخفي الكود الأصلي
            detail = detail or ""
        endpoint = (f"{method} /rest/{path}" if method and path else "").strip()
        if status in (401, 403):
            return RouterOSError(
                "auth_failed",
                "فشل مصادقة CHR (تحقق من اسم المستخدم وكلمة المرور وصلاحياتهما)"
                + (f" — {endpoint}" if endpoint else "") + ".",
                http_status=status,
                request_method=method, request_path=path,
                response_excerpt=body_excerpt,
            )
        if status == 404:
            return RouterOSError(
                "not_found",
                "العنصر المطلوب غير موجود على CHR"
                + (f" — {endpoint}" if endpoint else "") + ".",
                http_status=status,
                request_method=method, request_path=path,
                response_excerpt=body_excerpt,
            )
        if status >= 500:
            return RouterOSError(
                "chr_server_error",
                "خطأ داخلي في CHR"
                + (f" — {detail}" if detail else "")
                + (f" — {endpoint}" if endpoint else "")
                + ".",
                retryable=True,
                http_status=status,
                request_method=method, request_path=path,
                response_excerpt=body_excerpt,
            )
        return RouterOSError(
            "request_invalid",
            "طلب غير مقبول من CHR"
            + (f" — {detail}" if detail else "")
            + (f" — {endpoint}" if endpoint else "")
            + ".",
            http_status=status,
            request_method=method, request_path=path,
            response_excerpt=body_excerpt,
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

    # ───────────────────────── PPP profiles (speed / rate-limit) ─────────────────────────
    # السرعة على PPP تُطبَّق عبر ``rate-limit`` على ``/ppp/profile`` ثم يُسنَد البروفايل
    # إلى ``/ppp/secret``. صيغة rate-limit على RouterOS: ``rx/tx`` من منظور الراوتر —
    # rx = ما يستقبله الراوتر من العميل (رفع العميل)، tx = ما يرسله للعميل (تنزيله).

    def list_ppp_profiles(self) -> list[dict[str, Any]]:
        result = self._request("GET", "ppp/profile")
        return result if isinstance(result, list) else ([result] if isinstance(result, dict) else [])

    def find_ppp_profile(self, name: str) -> dict[str, Any] | None:
        result = self._request("GET", "ppp/profile", params={"name": name})
        if isinstance(result, list) and result:
            return result[0]
        if isinstance(result, dict):
            return result
        return None

    def ensure_ip_pool(self, *, name: str, ranges: str) -> dict[str, Any]:
        """يضمن وجود ``/ip/pool`` بالاسم ``name`` ومجاله ``ranges`` (idempotent).

        بدون pool يصادق العميل لكن لا يحصل على IPv4. pool **مشترك واحد** لكل أنفاق
        PPP — لا pool لكل بروفايل سرعة. يُنشئه إن غاب، ويعيده."""
        if not name or not ranges:
            return {}
        existing = self._find_one("ip/pool", {"name": name})
        if existing:
            return existing
        created = self._request("PUT", "ip/pool", body={"name": name, "ranges": ranges})
        if isinstance(created, list):
            created = created[0] if created else {}
        return created if isinstance(created, dict) else {"name": name}

    def ensure_ppp_profile(
        self,
        *,
        name: str,
        rate_limit: str = "",
        local_address: str = "",
        remote_address: str = "",
        use_encryption: bool = True,
    ) -> dict[str, Any]:
        """يضمن وجود ``/ppp/profile`` باسمٍ ثابت (idempotent) **مع تخصيص العناوين**.

        حرج: لو غاب ``local-address``/``remote-address`` يصادق العميل لكن لا يأخذ IPv4
        (Local/Remote Address فارغان، لا ping). لذا نضبط دائمًا:
          * ``local-address`` = بوابة الـCHR لكل وصلة PPP.
          * ``remote-address`` = اسم الـpool المشترك (لا pool لكل بروفايل).
          * ``use-encryption`` = yes افتراضيًا.
        لا نترك هذه الحقول فارغة أبدًا. إن وُجد البروفايل وكان أيٌّ منها مختلفًا/فارغًا
        صحّحناه (PATCH)؛ وإلا أنشأناه كاملًا."""
        enc = "yes" if use_encryption else "no"
        desired: dict[str, Any] = {}
        if rate_limit:
            desired["rate-limit"] = rate_limit
        if local_address:
            desired["local-address"] = local_address
        if remote_address:
            desired["remote-address"] = remote_address
        desired["use-encryption"] = enc

        existing = self.find_ppp_profile(name)
        if existing:
            pid = str(existing.get(".id") or existing.get("id") or "")
            patch: dict[str, Any] = {}
            for key, val in desired.items():
                if str(existing.get(key) or "") != str(val):
                    patch[key] = val
            if patch and pid:
                self._request(
                    "PATCH", "ppp/profile/" + urllib.parse.quote(pid, safe=""),
                    body=patch,
                )
                existing.update(patch)
            return existing
        body: dict[str, Any] = {"name": name}
        body.update(desired)
        created = self._request("PUT", "ppp/profile", body=body)
        if isinstance(created, list):
            created = created[0] if created else {}
        return created if isinstance(created, dict) else {"name": name}

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

    # ───────────────────────── WireGuard helpers ─────────────────────────
    # WireGuard on RouterOS lives at ``/interface/wireguard`` (one row per server
    # interface) and ``/interface/wireguard/peers`` (one row per client peer).
    # Each peer carries the client's public-key + the allowed-address list it can
    # claim. All helpers idempotent — they search before they create.

    def find_wireguard_interface(
        self, name: str, *, proplist: list[str] | None = None,
    ) -> dict[str, Any] | None:
        # fix/chr-rest-500-and-api-auth — RouterOS v7 REST returns HTTP
        # 500 «Internal Server Error» on `GET /rest/interface/wireguard?
        # name=X` on at least some builds (the field-incident CHR was
        # one). The owner saw the live failure here: wg_verify calls
        # this, the JSON path returned 500, and the message bubbled up
        # as «rest_failed: تعذّر القراءة عبر REST — خطأ داخلي في CHR
        # — Internal Server Error» with no hint as to which endpoint.
        # The robust pattern is to fetch the bare list (which works
        # uniformly across v7 builds) and filter client-side.
        #
        # fix/chr-rest-wireguard-permission — optional `.proplist` so a
        # READ-ONLY caller (wg_verify) requests ONLY the non-secret
        # fields it needs (name, public-key) and never pulls the
        # interface private-key over REST. `.proplist` is a field
        # selector (not a server-side filter), so it does NOT re-trigger
        # the `?interface=`-filter 500 the fetch-all pattern avoids.
        params = {".proplist": ",".join(proplist)} if proplist else None
        rows = self._request("GET", "interface/wireguard", params=params)
        if isinstance(rows, dict):
            rows = [rows]
        if not isinstance(rows, list):
            return None
        for row in rows:
            if isinstance(row, dict) and str(row.get("name") or "") == name:
                return row
        return None

    def ensure_wireguard_interface(
        self,
        *,
        name: str,
        listen_port: int,
        private_key: str = "",
    ) -> dict[str, Any]:
        """Create or return ``/interface/wireguard`` row.

        ``private_key=""`` lets RouterOS auto-generate one (preferred — the key
        never leaves the router). We then read back the public key from the same
        row for the panel to share with peers.
        """
        existing = self.find_wireguard_interface(name)
        if existing:
            return existing
        body: dict[str, Any] = {"name": name, "listen-port": str(int(listen_port))}
        if private_key:
            body["private-key"] = private_key
        created = self._request("PUT", "interface/wireguard", body=body)
        if isinstance(created, list):
            created = created[0] if created else {}
        if not isinstance(created, dict) or not created.get(".id"):
            # Some RouterOS builds return the bare ack; re-fetch to surface the pubkey.
            refetched = self.find_wireguard_interface(name)
            if refetched:
                return refetched
        return created if isinstance(created, dict) else {"name": name}

    def list_wireguard_peers(
        self, *, interface: str | None = None, proplist: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        # fix/chr-rest-500-and-api-auth — same fetch-all-then-filter
        # treatment as find_wireguard_interface above. The server-side
        # `?interface=X` filter on this endpoint also 500s on the live
        # CHR; fetching the bare list returns the same peers in every
        # build we've seen, and an in-memory filter on `interface`
        # equals is trivially correct.
        #
        # fix/chr-rest-wireguard-permission — optional `.proplist` so a
        # READ-ONLY caller (wg_verify) requests ONLY the non-secret peer
        # fields it needs (public-key/endpoint/handshake/rx/tx) and never
        # pulls the peer preshared-key over REST. If `.proplist` is set
        # we must keep `interface` in it so the client-side filter still
        # works.
        params = None
        if proplist:
            cols = list(proplist)
            if interface and "interface" not in cols:
                cols.append("interface")
            params = {".proplist": ",".join(cols)}
        rows = self._as_list(self._request("GET", "interface/wireguard/peers", params=params))
        if interface:
            rows = [r for r in rows if str(r.get("interface") or "") == interface]
        return rows

    def find_wireguard_peer(self, *, interface: str, public_key: str) -> dict[str, Any] | None:
        return self._find_one(
            "interface/wireguard/peers",
            {"interface": interface, "public-key": public_key},
        )

    def create_wireguard_peer(
        self,
        *,
        interface: str,
        public_key: str,
        allowed_address: str,
        preshared_key: str = "",
        comment: str = "",
        persistent_keepalive: str = "",
    ) -> dict[str, Any]:
        """Create ``/interface/wireguard/peers`` and return it (with ``.id``)."""
        body: dict[str, Any] = {
            "interface": interface,
            "public-key": public_key,
            "allowed-address": allowed_address,
        }
        if preshared_key:
            body["preshared-key"] = preshared_key
        if comment:
            body["comment"] = comment
        if persistent_keepalive:
            body["persistent-keepalive"] = persistent_keepalive
        created = self._request("PUT", "interface/wireguard/peers", body=body)
        if isinstance(created, list):
            created = created[0] if created else {}
        return created if isinstance(created, dict) else {}

    def remove_wireguard_peer(self, peer_id: str) -> None:
        """Delete a peer by .id; idempotent for 404."""
        if not peer_id:
            return
        try:
            self._request(
                "DELETE",
                "interface/wireguard/peers/" + urllib.parse.quote(peer_id, safe=""),
            )
        except RouterOSError as exc:
            if exc.code == "not_found":
                return
            raise

    def set_wireguard_peer_disabled(self, peer_id: str, disabled: bool) -> None:
        if not peer_id:
            return
        self._request(
            "PATCH",
            "interface/wireguard/peers/" + urllib.parse.quote(peer_id, safe=""),
            body={"disabled": "yes" if disabled else "no"},
        )

    def list_wireguard_active(self) -> list[dict[str, Any]]:
        """All WG peers across interfaces (with live ``last-handshake`` info)."""
        return self._as_list(self._request("GET", "interface/wireguard/peers"))

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

    def find_ppp_active(self, name: str) -> dict[str, Any] | None:
        """جلسة PPP النشطة لمستخدمٍ معيّن (إن كان متصلًا الآن) — تحوي
        ``bytes-in``/``bytes-out`` للجلسة الحالية (تُصفَّر عند إعادة الاتصال)."""
        res = self._request("GET", "ppp/active", params={"name": name})
        if isinstance(res, list) and res:
            first = res[0]
            return first if isinstance(first, dict) else None
        if isinstance(res, dict):
            return res
        return None

    def set_secret_profile(self, secret_id: str, profile: str) -> None:
        """يغيّر ``/ppp/profile`` المُسنَد لحساب ``/ppp/secret`` (للتخفيض/الاستعادة).

        يطبّق فعليًا عند إعادة الاتصال — استخدم ``remove_ppp_active`` لفصل الجلسة
        الحالية كي تُعاد بالبروفايل الجديد فورًا."""
        if not secret_id or not profile:
            return
        self._request(
            "PATCH", "ppp/secret/" + urllib.parse.quote(secret_id, safe=""),
            body={"profile": profile},
        )

    def remove_ppp_active(self, active_id: str) -> None:
        """يفصل جلسة PPP نشطة بمعرّفها (تُعاد فورًا بالبروفايل المُحدَّث).
        يتجاهل 404 (انفصلت مسبقًا)."""
        if not active_id:
            return
        try:
            self._request("DELETE", "ppp/active/" + urllib.parse.quote(active_id, safe=""))
        except RouterOSError as exc:
            if exc.code == "not_found":
                return
            raise

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
