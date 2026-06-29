"""RENDER-ONLY harness — proves the «دفع الإشعارات (Firebase)» settings tab
opens (instead of falling back to the default tab) and shows the service-account
upload field + status.

Boots the real Flask panel on a throwaway sqlite DB, seeds a super-admin, then
drives system Chrome via Playwright to:

  1. click the Firebase tab button  → _shot_firebase_tab_click.png
  2. deep-link /admin/settings#firebase (the post-upload redirect anchor)
     → _shot_firebase_deeplink.png

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
DB_PATH = ROOT / "_render_firebase_tab.sqlite3"
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

PORT = 5098
BASE = f"http://127.0.0.1:{PORT}"

app = create_app(WTF_CSRF_ENABLED=False, RATE_LIMITS_ENABLED=False)


def seed():
    with app.app_context():
        admin = M.Admin.query.filter_by(username="admin").first()
        if not admin:
            admin = M.Admin(username="admin", full_name="مالك اللوحة")
            db.session.add(admin)
        admin.is_super_admin = True
        admin.active = True
        admin.set_password("admin12345")
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


async def render(out_dir: Path):
    from playwright.async_api import async_playwright
    notes = []
    async with async_playwright() as p:
        browser = await p.chromium.launch(channel="chrome", headless=True)
        ctx = await browser.new_context(viewport={"width": 1440, "height": 1200}, locale="ar")
        page = await ctx.new_page()
        await _login(page)
        notes.append(f"login -> {page.url}")

        # 1) Land on the settings page, then CLICK the Firebase tab button.
        resp = await page.goto(f"{BASE}/admin/settings", wait_until="load")
        await page.wait_for_timeout(500)
        await page.click("#tab-btn-firebase")
        await page.wait_for_timeout(500)
        pane_active = await page.eval_on_selector(
            "#tab-firebase", "el => el.classList.contains('active')")
        upload_visible = await page.is_visible("#sg-fcm-cred")
        await page.screenshot(path=str(out_dir / "_shot_firebase_tab_click.png"), full_page=True)
        notes.append(f"click tab: http={resp.status if resp else '?'} "
                     f"pane_active={pane_active} upload_field_visible={upload_visible}")

        # 2) Deep-link to #firebase (the anchor the upload/remove POST redirects to).
        resp = await page.goto(f"{BASE}/admin/settings#firebase", wait_until="load")
        await page.wait_for_timeout(600)
        pane_active2 = await page.eval_on_selector(
            "#tab-firebase", "el => el.classList.contains('active')")
        site_active = await page.eval_on_selector(
            "#tab-site", "el => el.classList.contains('active')")
        await page.screenshot(path=str(out_dir / "_shot_firebase_deeplink.png"), full_page=True)
        notes.append(f"deeplink #firebase: firebase_pane_active={pane_active2} "
                     f"site_pane_active={site_active}")

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
