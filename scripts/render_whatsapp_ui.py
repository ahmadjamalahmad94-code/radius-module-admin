"""RENDER-ONLY harness — captures the WhatsApp Cloud API integration UI.

Boots the real Flask panel on a throwaway sqlite DB, seeds a super-admin plus a
customer with a CONNECTED multi-tenant WhatsApp account (encrypted token, an
approved template, a few message-queue rows), configures the central Meta app
(Embedded Signup) + house credentials via env, then drives system Chrome via
Playwright to capture:

  1. _shot_settings_whatsapp.png  — provider-level Settings: WhatsApp Cloud API
     (house creds) + Embedded Signup (central Meta app) cards.
  2. _shot_customer_whatsapp.png  — per-tenant control: account / settings /
     templates / message log / webhook events.
  3. _shot_whatsapp_gateway.png   — global gateway dashboard (per-customer KPIs).

Output dir is argv[1] (default: this repo root). Pure rendering — no app code
is modified.
"""
from __future__ import annotations

import asyncio
import os
import sys
import threading
import time
import traceback
from pathlib import Path
from wsgiref.simple_server import make_server, WSGIRequestHandler

ROOT = Path(__file__).resolve().parent.parent
DB_PATH = ROOT / "_render_whatsapp_ui.sqlite3"
if DB_PATH.exists():
    DB_PATH.unlink()

os.environ["DATABASE_URL"] = "sqlite:///" + str(DB_PATH).replace("\\", "/")
os.environ["CUSTOMER_VAULT_ENCRYPTION_KEY"] = "e1R4rJoOuYz751w-g5Xd1HzPIUPuIWwXdI8bD8Zty_8="
os.environ["WHATSAPP_FERNET_KEY"] = "e1R4rJoOuYz751w-g5Xd1HzPIUPuIWwXdI8bD8Zty_8="
os.environ["AUTO_INIT_DB"] = "1"
os.environ["RATE_LIMITS_ENABLED"] = "0"
os.environ["LICENSE_PANEL_ENV"] = "local"
# Provider-level config shown in Settings (resolved as source=env when unset in DB).
os.environ["WHATSAPP_CLOUD_SETTINGS_ENABLED"] = "1"
os.environ["META_EMBEDDED_SIGNUP_ENABLED"] = "1"
os.environ["META_APP_ID"] = "1234567890123456"
os.environ["META_APP_SECRET"] = "appsecret_demo_value_never_real_000000"
os.environ["META_CONFIG_ID"] = "9876543210987654"
os.environ["META_GRAPH_VERSION"] = "v21.0"
os.environ["WHATSAPP_ACCESS_TOKEN"] = "EAABhouseTOKENdemo000000000000000000"
os.environ["WHATSAPP_PHONE_NUMBER_ID"] = "1169165929613113"
os.environ["WHATSAPP_BUSINESS_ACCOUNT_ID"] = "27438053492514303"

sys.path.insert(0, str(ROOT))

from app import create_app  # noqa: E402
from app.extensions import db  # noqa: E402
from app import models as M  # noqa: E402
from app.services.license_service import generate_license_key  # noqa: E402
from app.services.whatsapp import settings as wa_settings  # noqa: E402

PORT = 5099
BASE = f"http://127.0.0.1:{PORT}"

app = create_app(WTF_CSRF_ENABLED=False, RATE_LIMITS_ENABLED=False)

CUSTOMER_ID = {"id": None}


def seed():
    from datetime import timedelta
    with app.app_context():
        admin = M.Admin.query.filter_by(username="admin").first()
        if not admin:
            admin = M.Admin(username="admin", full_name="مالك اللوحة")
            db.session.add(admin)
        admin.is_super_admin = True
        admin.active = True
        admin.set_password("admin12345")

        plan = M.Plan.query.filter_by(slug="pro").first()
        if plan is None:
            plan = M.Plan.query.first()
        customer = M.Customer(company_name="شركة النور للإنترنت", contact_name="مالك")
        db.session.add(customer)
        db.session.flush()
        now = M.utcnow()
        lic = M.License(
            customer_id=customer.id,
            plan_id=plan.id,
            license_key=generate_license_key(),
            status="active",
            starts_at=now - timedelta(days=1),
            expires_at=now + timedelta(days=300),
            grace_until=now + timedelta(days=307),
            max_fingerprints=3,
        )
        db.session.add(lic)
        db.session.commit()
        CUSTOMER_ID["id"] = customer.id

        # Connected multi-tenant WhatsApp account (token encrypted at rest).
        wa_settings.upsert_account(
            customer.id,
            license_id=lic.id,
            meta_business_id="102938475610293",
            whatsapp_business_account_id="27438053492514303",
            phone_number_id="1169165929613113",
            display_phone_number="+963 11 234 5678",
            business_display_name="النور نت",
            access_token="EAABtenantTOKENdemo0000000000000000",
        )
        acc = wa_settings.get_account(customer.id)
        acc.onboarding_method = "embedded"
        acc.quality_rating = "GREEN"
        acc.messaging_limit_tier = "TIER_1K"
        acc.token_expires_at = now + timedelta(days=58)
        db.session.commit()
        wa_settings.set_connection_status(customer.id, "connected")
        wa_settings.update_settings(
            customer.id, enabled=True, plan_code="whatsapp_pro",
            monthly_message_limit=2000, daily_message_limit=300, per_minute_limit=30,
            allow_otp=True, allow_expiry_notice=True, allow_maintenance_notice=True,
        )
        wa_settings.upsert_template(
            customer.id, local_key="otp", provider_template_name="otp_ar",
            language="ar", category="AUTHENTICATION", status="approved",
        )
        wa_settings.upsert_template(
            customer.id, local_key="expiry_notice", provider_template_name="expiry_ar",
            language="ar", category="UTILITY", status="approved",
        )
        # A few message-queue rows for the gateway dashboard + log.
        for i, st in enumerate(["delivered", "read", "sent", "failed"]):
            row = M.WhatsAppMessageQueue(
                customer_id=customer.id, license_id=lic.id,
                source_system="radius_module", source_event_type="otp",
                recipient_phone=f"+96359900000{i}", normalized_recipient_phone=f"+96359900000{i}",
                template_key="otp", template_name="otp_ar", language="ar",
                status=st, idempotency_key=f"seed-{i}",
                provider_message_id=f"wamid.SEED{i}",
            )
            if st == "failed":
                row.error_code = "131049"
                row.error_message = "تعذّر التسليم — الرقم لا يستخدم واتساب."
            db.session.add(row)
        wa_settings.bump_usage(customer.id, now, queued=4, sent=4, delivered=2, failed=1)
        db.session.commit()


class _QuietHandler(WSGIRequestHandler):
    def log_message(self, *a):
        pass


def serve():
    make_server("127.0.0.1", PORT, app, handler_class=_QuietHandler).serve_forever()


async def _login(page):
    await page.goto(f"{BASE}/login", wait_until="load")
    await page.fill("input[name=username]", "admin")
    await page.fill("input[name=password]", "admin12345")
    await page.click("button[type=submit]")
    await page.wait_for_load_state("load")


async def _shoot(page, url, out, *, selector=None):
    resp = await page.goto(url, wait_until="load", timeout=25000)
    try:
        await page.wait_for_load_state("networkidle", timeout=4000)
    except Exception:
        pass
    await page.wait_for_timeout(700)
    if selector:
        try:
            el = page.locator(selector).first
            await el.scroll_into_view_if_needed()
            await page.wait_for_timeout(300)
            await el.screenshot(path=str(out))
            return f"OK {out.name}  http={resp.status if resp else '?'} (selector {selector})"
        except Exception as exc:
            pass  # fall back to full page
    await page.screenshot(path=str(out), full_page=True)
    return f"OK {out.name}  http={resp.status if resp else '?'} (full page)"


async def render(out_dir: Path):
    from playwright.async_api import async_playwright
    cid = CUSTOMER_ID["id"]
    notes = []
    async with async_playwright() as p:
        browser = await p.chromium.launch(channel="chrome", headless=True)
        ctx = await browser.new_context(viewport={"width": 1440, "height": 1200}, locale="ar")
        page = await ctx.new_page()
        await _login(page)
        notes.append(f"login -> {page.url}")
        notes.append(await _shoot(page, f"{BASE}/admin/settings#whatsapp-cloud",
                                  out_dir / "_shot_settings_whatsapp.png"))
        notes.append(await _shoot(page, f"{BASE}/admin/customers/{cid}/whatsapp",
                                  out_dir / "_shot_customer_whatsapp.png"))
        notes.append(await _shoot(page, f"{BASE}/admin/whatsapp-gateway",
                                  out_dir / "_shot_whatsapp_gateway.png"))
        await browser.close()
    return notes


def main():
    out_dir = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else ROOT
    out_dir.mkdir(parents=True, exist_ok=True)
    seed()
    threading.Thread(target=serve, daemon=True).start()
    time.sleep(1.5)
    notes = asyncio.run(render(out_dir))
    print("\n=== RENDER NOTES ===")
    for n in notes:
        print(n)
    print("=== END ===")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        traceback.print_exc()
        sys.exit(1)
