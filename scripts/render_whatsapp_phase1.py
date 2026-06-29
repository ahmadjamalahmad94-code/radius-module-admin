"""RENDER-ONLY harness — Phase 1 (manual per-tenant credentials path).

Boots the real panel on a throwaway sqlite DB and captures the per-tenant
WhatsApp page in its two key Phase-1 states, driving system Chrome via
Playwright:

  1. _shot_p1_manual_entry.png — a FRESH customer with no account: the manual
     credentials form (access_token / phone_number_id / waba_id /
     display_phone_number), status badge "غير مهيأ", "فحص الربط" + test buttons.
  2. _shot_p1_connected.png    — a customer whose creds were entered + validated:
     status "متصل", approved templates, test-message card, message log.

Output dir is argv[1] (default repo root). No app code is modified. The token
is stored encrypted and only ever shown masked — these shots prove the UI never
renders a clear token.
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
DB_PATH = ROOT / "_render_whatsapp_phase1.sqlite3"
if DB_PATH.exists():
    DB_PATH.unlink()

os.environ["DATABASE_URL"] = "sqlite:///" + str(DB_PATH).replace("\\", "/")
os.environ["CUSTOMER_VAULT_ENCRYPTION_KEY"] = "e1R4rJoOuYz751w-g5Xd1HzPIUPuIWwXdI8bD8Zty_8="
os.environ["WHATSAPP_FERNET_KEY"] = "e1R4rJoOuYz751w-g5Xd1HzPIUPuIWwXdI8bD8Zty_8="
os.environ["AUTO_INIT_DB"] = "1"
os.environ["RATE_LIMITS_ENABLED"] = "0"
os.environ["LICENSE_PANEL_ENV"] = "local"

sys.path.insert(0, str(ROOT))

from app import create_app  # noqa: E402
from app.extensions import db  # noqa: E402
from app import models as M  # noqa: E402
from app.services.whatsapp import settings as wa_settings  # noqa: E402

PORT = 5101
BASE = f"http://127.0.0.1:{PORT}"
app = create_app(WTF_CSRF_ENABLED=False, RATE_LIMITS_ENABLED=False)
IDS = {"fresh": None, "connected": None}


def seed():
    from datetime import timedelta
    with app.app_context():
        admin = M.Admin.query.filter_by(username="admin").first() or M.Admin(username="admin", full_name="مالك اللوحة")
        admin.is_super_admin = True
        admin.active = True
        admin.set_password("admin12345")
        db.session.add(admin)

        # 1) Fresh customer — no WhatsApp account yet (empty manual form state).
        fresh = M.Customer(company_name="شركة الفجر (إعداد جديد)", contact_name="مالك")
        db.session.add(fresh)
        # 2) Connected customer — manual creds entered + validated.
        conn = M.Customer(company_name="شركة النور للإنترنت", contact_name="مالك")
        db.session.add(conn)
        db.session.commit()
        IDS["fresh"], IDS["connected"] = fresh.id, conn.id

        now = M.utcnow()
        wa_settings.upsert_account(
            conn.id,
            meta_business_id="102938475610293",
            whatsapp_business_account_id="27438053492514303",
            phone_number_id="1169165929613113",
            display_phone_number="+963 11 234 5678",
            business_display_name="النور نت",
            access_token="EAABtenantTOKENdemo0000000000000000",
        )
        acc = wa_settings.get_account(conn.id)
        acc.quality_rating = "GREEN"
        acc.messaging_limit_tier = "TIER_1K"
        acc.token_expires_at = now + timedelta(days=58)
        db.session.commit()
        wa_settings.set_connection_status(conn.id, "connected")
        wa_settings.update_settings(
            conn.id, enabled=True, plan_code="whatsapp_pro",
            monthly_message_limit=2000, daily_message_limit=300, per_minute_limit=30,
            allow_otp=True, allow_expiry_notice=True,
        )
        wa_settings.upsert_template(
            conn.id, local_key="otp", provider_template_name="otp_ar",
            language="ar", category="AUTHENTICATION", status="approved",
        )
        for i, st in enumerate(["delivered", "read", "sent", "failed"]):
            row = M.WhatsAppMessageQueue(
                customer_id=conn.id, source_system="admin_panel", source_event_type="admin_test",
                recipient_phone=f"+96359900000{i}", normalized_recipient_phone=f"+96359900000{i}",
                template_key="otp", template_name="otp_ar", language="ar",
                status=st, idempotency_key=f"seed-{i}", provider_message_id=f"wamid.SEED{i}",
            )
            if st == "failed":
                row.error_code = "131049"
                row.error_message = "تعذّر التسليم — الرقم لا يستخدم واتساب."
            db.session.add(row)
        wa_settings.bump_usage(conn.id, now, queued=4, sent=4, delivered=2, failed=1)
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


async def _shoot(page, url, out):
    resp = await page.goto(url, wait_until="load", timeout=25000)
    try:
        await page.wait_for_load_state("networkidle", timeout=4000)
    except Exception:
        pass
    await page.wait_for_timeout(600)
    await page.screenshot(path=str(out), full_page=True)
    return f"OK {out.name}  http={resp.status if resp else '?'}"


async def render(out_dir: Path):
    from playwright.async_api import async_playwright
    notes = []
    async with async_playwright() as p:
        browser = await p.chromium.launch(channel="chrome", headless=True)
        ctx = await browser.new_context(viewport={"width": 1440, "height": 1200}, locale="ar")
        page = await ctx.new_page()
        await _login(page)
        notes.append(await _shoot(page, f"{BASE}/admin/customers/{IDS['fresh']}/whatsapp",
                                  out_dir / "_shot_p1_manual_entry.png"))
        notes.append(await _shoot(page, f"{BASE}/admin/customers/{IDS['connected']}/whatsapp",
                                  out_dir / "_shot_p1_connected.png"))
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
