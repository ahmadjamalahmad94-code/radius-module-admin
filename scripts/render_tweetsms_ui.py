"""RENDER-ONLY harness — TweetSMS owner→customer SMS UI.

Boots the real panel on a throwaway sqlite DB, seeds the owner's TweetSMS creds
(stored encrypted) + a couple of customers, and captures:

  1. _shot_tweetsms_settings.png      — Settings → الرسائل النصية (SMS) tab:
     credential form (masked api_key), فحص الرصيد + إرسال تجربة.
  2. _shot_tweetsms_detail.png        — customer 360 → إرسال SMS compose box
     with the live 60-char counter.
  3. _shot_tweetsms_list_bulk.png     — customers list with select-checkboxes +
     the bulk «إرسال للمحدَّدين» bar.
  4. _shot_tweetsms_detail_mobile.png — the compose box at ~390px.

No real api_key is used (a dummy one is seeded). Output dir is argv[1].
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
DB_PATH = ROOT / "_render_tweetsms.sqlite3"
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
from app.services.tweetsms import settings as tss  # noqa: E402

PORT = 5107
BASE = f"http://127.0.0.1:{PORT}"
app = create_app(WTF_CSRF_ENABLED=False, RATE_LIMITS_ENABLED=False)
IDS = {"c1": None}


class _Form(dict):
    def get(self, k, default=""):
        return dict.get(self, k, default)


def seed():
    with app.app_context():
        admin = M.Admin.query.filter_by(username="admin").first() or M.Admin(username="admin", full_name="مالك اللوحة")
        admin.is_super_admin = True
        admin.active = True
        admin.set_password("admin12345")
        db.session.add(admin)

        c1 = M.Customer(company_name="شركة النور للإنترنت", contact_name="مالك",
                        email="nour@example.com", phone="0599123456", status="active",
                        city="رام الله", country="فلسطين")
        c2 = M.Customer(company_name="شبكة الفجر", contact_name="أحمد",
                        email="fajr@example.com", phone="0598777666", status="active",
                        city="نابلس", country="فلسطين")
        c3 = M.Customer(company_name="عميل بلا هاتف", contact_name="—",
                        email="", phone="", status="inactive")
        db.session.add_all([c1, c2, c3])
        db.session.commit()
        IDS["c1"] = c1.id

        # Seed the owner's TweetSMS creds (dummy api_key — stored encrypted, shown masked).
        tss.validate_and_save(_Form(api_key="TS_DUMMY_KEY_1234567890", sender="HobeRadius"),
                              actor_audit=lambda *a, **k: None)
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


async def _shoot(page, url, out, *, click=None, fill=None, hash_=""):
    target = url + (hash_ or "")
    resp = await page.goto(target, wait_until="load", timeout=25000)
    try:
        await page.wait_for_load_state("networkidle", timeout=4000)
    except Exception:
        pass
    if click:
        try:
            await page.click(click, timeout=4000)
        except Exception:
            pass
    if fill:
        for sel, val in fill:
            try:
                await page.fill(sel, val, timeout=4000)
            except Exception:
                pass
    await page.wait_for_timeout(700)
    await page.screenshot(path=str(out), full_page=True)
    return f"OK {out.name}  http={resp.status if resp else '?'}"


async def render(out_dir: Path):
    from playwright.async_api import async_playwright
    notes = []
    async with async_playwright() as p:
        browser = await p.chromium.launch(channel="chrome", headless=True)

        # Desktop
        ctx = await browser.new_context(viewport={"width": 1440, "height": 1300}, locale="ar")
        page = await ctx.new_page()
        await _login(page)
        notes.append(await _shoot(page, f"{BASE}/admin/settings",
                                  out_dir / "_shot_tweetsms_settings.png",
                                  click="#tab-btn-sms"))
        notes.append(await _shoot(page, f"{BASE}/admin/customers/{IDS['c1']}",
                                  out_dir / "_shot_tweetsms_detail.png",
                                  fill=[("textarea[name=message]",
                                         "مرحبًا، تم تجديد اشتراككم بنجاح. شكرًا لثقتكم بنا — فريق HobeRadius.")],
                                  hash_="#sms"))
        notes.append(await _shoot(page, f"{BASE}/admin/customers",
                                  out_dir / "_shot_tweetsms_list_bulk.png",
                                  fill=[("textarea[name=message]", "تنبيه: صيانة مجدولة الليلة 12-2 صباحًا.")]))
        await ctx.close()

        # Mobile ~390px
        mctx = await browser.new_context(viewport={"width": 390, "height": 1400}, locale="ar",
                                         device_scale_factor=2)
        mpage = await mctx.new_page()
        await _login(mpage)
        notes.append(await _shoot(mpage, f"{BASE}/admin/customers/{IDS['c1']}",
                                  out_dir / "_shot_tweetsms_detail_mobile.png",
                                  fill=[("textarea[name=message]",
                                         "رسالة قصيرة تجريبية للعميل عبر TweetSMS.")],
                                  hash_="#sms"))
        await mctx.close()
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
