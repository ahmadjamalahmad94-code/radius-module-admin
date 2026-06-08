#!/usr/bin/env python3
"""يتحقق من أن كل مفتاح os.environ.get في الكود موثَّق في .env.example.

الاستخدام:
    python scripts/check_env_completeness.py

يُعيد:
    0 — جميع المفاتيح موثَّقة
    1 — مفاتيح غير موثَّقة (يطبع القائمة)
"""
from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP_DIR  = ROOT / "app"
ENV_FILE = ROOT / ".env.example"


def _extract_env_keys_from_ast(path: Path) -> set[str]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
    except SyntaxError:
        return set()

    keys: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Attribute):
            obj  = func.value
            attr = func.attr
            is_environ_get = (
                isinstance(obj, ast.Attribute)
                and isinstance(obj.value, ast.Name)
                and obj.value.id == "os"
                and obj.attr == "environ"
                and attr == "get"
            )
            is_getenv = (
                isinstance(obj, ast.Name)
                and obj.id == "os"
                and attr == "getenv"
            )
            if (is_environ_get or is_getenv) and node.args:
                first = node.args[0]
                if isinstance(first, ast.Constant) and isinstance(first.value, str):
                    keys.add(first.value)
    return keys


def _collect_all_env_keys() -> set[str]:
    all_keys: set[str] = set()
    for py_file in APP_DIR.rglob("*.py"):
        all_keys.update(_extract_env_keys_from_ast(py_file))
    return all_keys


def _load_documented_keys(env_example: Path) -> set[str]:
    if not env_example.exists():
        return set()
    documented: set[str] = set()
    for line in env_example.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r"^#?\s*([A-Z][A-Z0-9_]+)\s*=", line)
        if m:
            documented.add(m.group(1))
    return documented


_EXEMPT: frozenset[str] = frozenset({
    "FLASK_ENV",
    "FLASK_DEBUG",
    "WERKZEUG_RUN_MAIN",
    "PYTEST_CURRENT_TEST",
    "TMP",
    "TEMP",
    "TMPDIR",
    "PATH",
    "HOME",
    "USER",
})


def main() -> int:
    if not ENV_FILE.exists():
        print(f"ERROR: {ENV_FILE} not found", file=sys.stderr)
        return 1

    all_keys   = _collect_all_env_keys()
    documented = _load_documented_keys(ENV_FILE)
    relevant   = {k for k in all_keys if k.isupper() and k not in _EXEMPT}

    missing = relevant - documented
    if not missing:
        print(f"✓ All {len(relevant)} env keys are documented in .env.example")
        return 0

    print(f"✗ {len(missing)} env key(s) missing from .env.example:")
    for k in sorted(missing):
        print(f"  - {k}")
    print(f"\nTotal documented: {len(documented)}, Total found in code: {len(relevant)}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
