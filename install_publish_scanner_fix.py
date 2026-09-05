#!/usr/bin/env python3
from pathlib import Path
from datetime import datetime
import shutil
import sys

def main() -> int:
    source = Path(__file__).resolve().with_name("publish_floraos_website_branch_v2.py")
    target = Path("/home/Luqman/website/publish_floraos_website_branch.py")

    if not source.exists():
        print(f"Missing corrected publisher: {source}", file=sys.stderr)
        return 2

    if target.exists():
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        backup = target.with_name(f"{target.name}.before-scanner-fix-{stamp}")
        shutil.copy2(target, backup)
        print(f"Backup: {backup}")

    shutil.copy2(source, target)
    print(f"Installed: {target}")
    print()
    print("Run:")
    print("  cd /home/Luqman/website")
    print("  source .venv/bin/activate")
    print("  python publish_floraos_website_branch.py")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
