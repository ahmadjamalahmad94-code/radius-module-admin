"""صلاحيات لوحة المالك (panel admins) القابلة للتسمية/العرض.

ملاحظة معمارية: هذه اللوحة لا تملك نظام أدوار دقيق لمدرائها — التحكّم الوحيد هو
``Admin.is_super_admin`` (انظر ``app/admin/vault_routes.py``). لذا نُعرّف هنا
سجلّ صلاحيات مُعنوَن (labels) ليكون المصدر الوحيد لأسماء الصلاحيات وعرضها، بحيث:

* المسؤول العام (super-admin) يملك كل الصلاحيات دائمًا.
* عند إضافة محرّر أدوار/صلاحيات للمدراء لاحقًا، تُقرأ التسميات من هنا مباشرةً.

الصلاحية المضافة الآن: ``chr_console`` — الدخول إلى وحدة تحكّم CHR المركزية.
"""
from __future__ import annotations

# مفاتيح الصلاحيات (ثابتة، تُستخدم في الكود).
CHR_CONSOLE = "chr_console"

# تسمية كل صلاحية للعرض في أي محرّر أدوار/صلاحيات مستقبلي (عربي).
PERMISSION_LABELS: dict[str, str] = {
    CHR_CONSOLE: "وحدة تحكّم CHR المركزية",
}

# وصف موجز لكل صلاحية (تلميح للمحرّر).
PERMISSION_HINTS: dict[str, str] = {
    CHR_CONSOLE: "إدارة كاملة لِراوتر CHR المركزي: مستخدمو الأنفاق وIPsec والجلسات والإجراءات الإدارية.",
}


def permission_label(key: str) -> str:
    return PERMISSION_LABELS.get(str(key or "").strip(), str(key or "—"))
