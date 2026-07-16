# الهجرات — Alembic (اعتبارًا من 2026-07-16)

أُدخل Alembic كإطار الهجرات الرسمي، تمهيدًا للاستغناء التدريجي عن
`ensure_schema_compatibility()` في `app/__init__.py` (التي تعدّل المخطط عند كل
إقلاع وتبتلع الأخطاء).

## الاستخدام اليومي
```bash
# بعد أي تعديل على الموديلات:
.venv/Scripts/python.exe -m alembic revision --autogenerate -m "وصف التغيير"
# راجع الملف المتولد في migrations_alembic/versions/ ثم:
.venv/Scripts/python.exe -m alembic upgrade head
```
رابط القاعدة يُقرأ من `DATABASE_URL` وإلا فمسار SQLite القياسي (`app/db_path.py`).

## الحالة الحالية
- الأساس: `1b12d2e96730` (no-op) — القاعدة الحالية مختومة عليه.
- **انحراف معروف** بين ORM والقاعدة الحية (خلّفه نظام الترقيع القديم) سيظهر في
  أول `--autogenerate`: فهارس `chr_node_id` قديمة على `service_allocations`
  مقابل `fleet_chr_node_id` الجديدة، وفهرس `legacy_chr_node_id` مفقود، وفرق FK
  على `service_allocations`. راجعه وطبّقه بهجرة مقصودة عندما يناسبك.

## خطة التقاعد التدريجي لـ ensure_schema_compatibility
1. جمّد إضافة أي منطق جديد إليها — كل تغيير مخطط جديد = هجرة Alembic.
2. انقل الـ backfills الموجودة فيها إلى هجرات مرقّمة (مرة واحدة لكل بيئة).
3. عندما تكون كل البيئات مختومة على head: احذف الدالة واستبدلها بفحص
   `alembic current == head` عند الإقلاع (رفض الإقلاع على قاعدة غير مُهاجَرة).

ملاحظة: مجلد `migrations/` القديم (سكربتات fleet اليدوية 001–009) تاريخي —
لا تضف إليه.
