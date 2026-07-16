import os

# fail-closed: نقطة دخول gunicorn/الإنتاج. إن نُسي ضبط LICENSE_PANEL_ENV فالافتراض
# هنا «production» كي تعمل فحوصات _validate_production_config (رفض الأسرار
# الافتراضية dev-secret-change-me / admin12345) بدل الإقلاع الصامت بها.
# التشغيل التطويري يستخدم run.py الذي لا يمر من هنا. (SEC M7)
os.environ.setdefault("LICENSE_PANEL_ENV", "production")

from app import create_app

app = create_app()
