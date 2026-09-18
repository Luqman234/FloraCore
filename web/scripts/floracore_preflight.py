#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import importlib
import importlib.metadata
import os
import sqlite3
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1] if Path(__file__).resolve().parent.name == "scripts" else Path.cwd().resolve()


def check(name: str, fn):
    try:
        detail = fn()
        print(f"PASS  {name}" + (f" — {detail}" if detail else ""))
        return True
    except Exception as exc:
        print(f"FAIL  {name} — {type(exc).__name__}: {exc}")
        return False


def package(name: str) -> str:
    return importlib.metadata.version(name)


def proxyfix():
    import werkzeug
    from werkzeug.middleware.proxy_fix import ProxyFix  # noqa: F401
    return f"Werkzeug {package('Werkzeug')} @ {werkzeug.__file__}"


def database():
    dbp = ROOT / "users.db"
    db = sqlite3.connect(f"file:{dbp}?mode=ro", uri=True)
    try:
        names = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    finally:
        db.close()
    required = {"users", "device_ownership", "device_messages", "device_telemetry", "device_commands"}
    missing = sorted(required - names)
    if missing:
        raise RuntimeError("missing tables: " + ", ".join(missing))
    return f"{len(names)} tables"


def app_import():
    sys.path.insert(0, str(ROOT))
    appmod = importlib.import_module("app")
    flask_app = getattr(appmod, "app", None)
    if flask_app is None:
        raise RuntimeError("app:app missing")
    routes = {rule.rule for rule in flask_app.url_map.iter_rules()}
    must = {"/", "/login", "/api/device/v1/message", "/health/live", "/health/ready"}
    missing = sorted(must - routes)
    if missing:
        raise RuntimeError("missing routes: " + ", ".join(missing))
    return f"{len(routes)} routes"


def pip_check():
    p = subprocess.run([sys.executable, "-m", "pip", "check"], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30)
    if p.returncode:
        raise RuntimeError(p.stdout.strip() or f"exit {p.returncode}")
    return p.stdout.strip() or "dependencies consistent"


def main() -> int:
    print(f"FloraCore preflight\nProject: {ROOT}\nPython:  {sys.executable}\n")
    checks = [
        check("Flask", lambda: package("Flask")),
        check("Gunicorn", lambda: package("gunicorn")),
        check("Werkzeug ProxyFix", proxyfix),
        check("Dependency consistency", pip_check),
        check("SQLite core schema", database),
        check("Full app import + critical routes", app_import),
    ]
    print()
    if all(checks):
        print("PREFLIGHT: PASS")
        return 0
    print("PREFLIGHT: FAIL")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
