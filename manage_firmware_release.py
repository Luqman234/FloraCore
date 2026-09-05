#!/usr/bin/env python3
from __future__ import annotations

from contextlib import closing
from pathlib import Path
import argparse
import sqlite3

from floraos_ota import init_ota_schema


def main() -> None:
    parser = argparse.ArgumentParser(description="Manage FloraCore OTA release metadata.")
    parser.add_argument(
        "--root",
        default=None,
        help="FloraCore website root. Defaults to this script's directory.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("list")

    for command in ("enable", "disable"):
        p = sub.add_parser(command)
        p.add_argument("channel", choices=("dev", "beta", "stable"))
        p.add_argument("version")

    args = parser.parse_args()
    root = (
        Path(args.root).expanduser().resolve()
        if args.root
        else Path(__file__).resolve().parent
    )
    db_path = root / "users.db"
    if not db_path.exists():
        raise SystemExit(f"Database not found: {db_path}")

    init_ota_schema(db_path)

    with closing(sqlite3.connect(db_path)) as db:
        db.row_factory = sqlite3.Row

        if args.command == "list":
            rows = db.execute(
                """
                SELECT id, product, target, version, channel, byte_size,
                       sha256, released_at, enabled, binary_url
                FROM firmware_releases
                ORDER BY released_at DESC, id DESC
                """
            ).fetchall()
            if not rows:
                print("No firmware releases.")
                return
            for row in rows:
                state = "ENABLED" if row["enabled"] else "DISABLED"
                print(
                    f"[{row['id']}] {row['channel']:6} {row['version']:18} "
                    f"{state:8} {row['byte_size']} bytes"
                )
                print(f"    {row['binary_url']}")
                print(f"    sha256 {row['sha256']}")
            return

        enabled = 1 if args.command == "enable" else 0
        cursor = db.execute(
            """
            UPDATE firmware_releases
            SET enabled = ?
            WHERE product = 'FloraCore'
              AND target = 'esp32s3'
              AND channel = ?
              AND version = ?
            """,
            (enabled, args.channel, args.version),
        )
        db.commit()
        if cursor.rowcount != 1:
            raise SystemExit("Release not found.")

    print(f"{args.channel}/{args.version}: {args.command}d")


if __name__ == "__main__":
    main()
