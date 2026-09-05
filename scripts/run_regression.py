#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import importlib
import os
import subprocess
import sys
import unittest


THIS_FILE = Path(__file__).resolve()
ROOT = THIS_FILE.parents[1] if THIS_FILE.parent.name == "scripts" else Path.cwd().resolve()


def _prepare_import_path() -> dict[str, str]:
    """
    unittest discovery runs inside THIS Python process, so setting PYTHONPATH
    only on subprocesses is not enough. Put the FloraCore project root on the
    current interpreter's sys.path as well as in child-process environment.
    """
    root_str = str(ROOT)

    try:
        os.chdir(ROOT)
    except OSError as exc:
        raise SystemExit(f"Cannot enter project root {ROOT}: {exc}") from exc

    if root_str in sys.path:
        sys.path.remove(root_str)
    sys.path.insert(0, root_str)
    importlib.invalidate_caches()

    env = os.environ.copy()
    previous = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = (
        root_str if not previous else root_str + os.pathsep + previous
    )
    return env


def _import_smoke_test() -> bool:
    required_modules = (
        "device_enrollment",
        "floraos_account_security",
        "floraos_automations",
        "floraos_commands",
        "floraos_mfa",
        "floraos_plants",
        "floraos_public_api",
        "floraos_turnstile",
    )

    failed = []
    for module_name in required_modules:
        try:
            importlib.import_module(module_name)
        except ModuleNotFoundError as exc:
            # Only classify this as a project-module path problem when the
            # missing module is the one we explicitly tried to import.
            if exc.name == module_name:
                failed.append(module_name)
            else:
                print(
                    f"Import dependency error while loading {module_name}: "
                    f"missing {exc.name}"
                )
                return False
        except Exception as exc:
            # The regression tests themselves may monkeypatch env/config for
            # module initialization, so don't reject non-import-path runtime
            # errors here. Report them and let the real test suite decide.
            print(
                f"Import smoke warning for {module_name}: "
                f"{type(exc).__name__}: {exc}"
            )

    if failed:
        print(
            "\nProject modules not importable from the FloraCore root:\n  "
            + "\n  ".join(failed)
        )
        print(f"\nsys.path[0]: {sys.path[0] if sys.path else '<empty>'}")
        print(f"Project root: {ROOT}")
        return False

    print("Project import path: PASS")
    return True


def main() -> int:
    env = _prepare_import_path()

    print("FloraCore regression suite")
    print(f"Project: {ROOT}")
    print(f"Python:  {sys.executable}")
    print(f"Import root: {sys.path[0]}")
    print()

    preflight = ROOT / "scripts" / "floracore_preflight.py"
    if preflight.exists():
        result = subprocess.run(
            [sys.executable, str(preflight)],
            cwd=ROOT,
            env=env,
        )
        if result.returncode:
            print("\nRegression stopped: preflight failed.")
            return result.returncode

    if not _import_smoke_test():
        print("\nRegression stopped: project import path is invalid.")
        return 1

    tests_dir = ROOT / "tests"
    if not tests_dir.is_dir():
        print(f"Missing tests directory: {tests_dir}")
        return 1

    suite = unittest.defaultTestLoader.discover(
        start_dir=str(tests_dir),
        pattern="test_*.py",
    )
    count = suite.countTestCases()
    print(f"\nDiscovered {count} test(s).")

    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if not result.wasSuccessful():
        return 1

    print("\nREGRESSION: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
