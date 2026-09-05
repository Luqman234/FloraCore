#!/usr/bin/env python3
from __future__ import annotations
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from floraos_notifications import dispatch_pending_emails, sweep_offline


def main() -> int:
    db = ROOT / "users.db"
    created = sweep_offline(db)
    mail = dispatch_pending_emails(db)
    print(f"offline notifications created: {created}")
    print(f"emails sent: {mail['sent']}; failed/deferred: {mail['failed']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
