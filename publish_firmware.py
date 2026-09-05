#!/usr/bin/env python3
from __future__ import annotations

from contextlib import closing
from pathlib import Path
import argparse
import hashlib
import os
import shutil
import sqlite3
import struct
import tempfile
import time

from floraos_ota import PRODUCT, TARGET, PUBLIC_ORIGIN, init_ota_schema, register_release


ESP_IMAGE_MAGIC = 0xE9
ESP_APP_DESC_MAGIC = 0xABCD5432
APP_DESC_OFFSET = 32
APP_DESC_VERSION_OFFSET = APP_DESC_OFFSET + 16
APP_DESC_PROJECT_OFFSET = APP_DESC_VERSION_OFFSET + 32


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _c_string(raw: bytes) -> str:
    return raw.split(b"\0", 1)[0].decode("utf-8", errors="strict").strip()


def inspect_esp_app_image(path: Path) -> dict[str, str | int]:
    """Reject bootloader/partition/OTA-data files and read ESP-IDF app metadata."""
    size = path.stat().st_size
    if size < 64 * 1024:
        raise ValueError(f"image is suspiciously small ({size} bytes)")

    with path.open("rb") as fh:
        head = fh.read(APP_DESC_PROJECT_OFFSET + 32)

    if len(head) < APP_DESC_PROJECT_OFFSET + 32:
        raise ValueError("image is too short to contain an ESP-IDF app descriptor")
    if head[0] != ESP_IMAGE_MAGIC:
        raise ValueError("not an ESP application image: missing ESP image magic 0xE9")

    app_desc_magic = struct.unpack_from("<I", head, APP_DESC_OFFSET)[0]
    if app_desc_magic != ESP_APP_DESC_MAGIC:
        raise ValueError(
            "not a FloraCore application image: ESP-IDF app descriptor is missing. "
            "Do not publish bootloader.bin, partition-table.bin, or ota_data_initial.bin."
        )

    version = _c_string(
        head[APP_DESC_VERSION_OFFSET:APP_DESC_VERSION_OFFSET + 32]
    )
    project_name = _c_string(
        head[APP_DESC_PROJECT_OFFSET:APP_DESC_PROJECT_OFFSET + 32]
    )

    if project_name != PRODUCT:
        raise ValueError(
            f"embedded project name is {project_name!r}; expected {PRODUCT!r}"
        )
    if not version:
        raise ValueError("embedded firmware version is empty")

    return {
        "project": project_name,
        "version": version,
        "size": size,
    }


def atomic_copy(source: Path, destination: Path, *, replace: bool) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists() and not replace:
        raise FileExistsError(f"immutable firmware already exists: {destination}")

    fd, temporary_name = tempfile.mkstemp(
        prefix="." + destination.name + ".",
        suffix=".tmp",
        dir=destination.parent,
    )
    try:
        with os.fdopen(fd, "wb") as out, source.open("rb") as incoming:
            shutil.copyfileobj(incoming, out, length=1024 * 1024)
            out.flush()
            os.fsync(out.fileno())
        os.replace(temporary_name, destination)
    except Exception:
        try:
            os.unlink(temporary_name)
        except OSError:
            pass
        raise


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Publish an approved FloraCore ESP32-S3 OTA application image."
    )
    parser.add_argument("channel", choices=("dev", "beta", "stable"))
    parser.add_argument("firmware", help="Path to build/FloraCore.bin")
    parser.add_argument(
        "--notes",
        default="",
        help="Optional release notes stored with release metadata.",
    )
    parser.add_argument(
        "--disabled",
        action="store_true",
        help="Publish metadata disabled so FloraOS will not offer it yet.",
    )
    parser.add_argument(
        "--root",
        default=None,
        help="FloraCore website root. Defaults to this script's directory.",
    )
    args = parser.parse_args()

    root = (
        Path(args.root).expanduser().resolve()
        if args.root
        else Path(__file__).resolve().parent
    )
    source = Path(args.firmware).expanduser().resolve()
    if not source.is_file():
        raise SystemExit(f"Firmware file not found: {source}")

    try:
        info = inspect_esp_app_image(source)
    except (OSError, UnicodeError, ValueError) as exc:
        raise SystemExit(f"Refusing firmware: {exc}") from exc

    version = str(info["version"])
    size = int(info["size"])
    digest = sha256(source)

    firmware_root = root / "firmware" / "floracore"
    db_path = root / "users.db"
    if not db_path.exists():
        raise SystemExit(f"Database not found: {db_path}")

    # Allow publishing immediately after installing the OTA module, even
    # before Gunicorn has been restarted once.
    init_ota_schema(db_path)

    channel = args.channel

    # Every publication gets an immutable version-addressed artifact.
    if channel == "dev":
        destination = (
            firmware_root / "dev" / "releases" / version / "FloraCore.bin"
        )
        binary_url = (
            f"{PUBLIC_ORIGIN}/firmware/floracore/dev/releases/"
            f"{version}/FloraCore.bin"
        )
    else:
        destination = firmware_root / channel / version / "FloraCore.bin"
        binary_url = (
            f"{PUBLIC_ORIGIN}/firmware/floracore/{channel}/"
            f"{version}/FloraCore.bin"
        )

    if destination.exists():
        raise SystemExit(
            "Refusing to replace an existing versioned firmware artifact:\n"
            f"  {destination}\n"
            "Bump the embedded ESP-IDF application version before publishing "
            "different contents."
        )

    # Check release identity before touching the filesystem.
    with closing(sqlite3.connect(db_path)) as db:
        existing = db.execute(
            """
            SELECT id, sha256, binary_path
            FROM firmware_releases
            WHERE product = ? AND target = ? AND channel = ? AND version = ?
            """,
            (PRODUCT, TARGET, channel, version),
        ).fetchone()
    if existing is not None:
        raise SystemExit(
            f"Release metadata already exists for {PRODUCT}/{TARGET}/{channel}/{version}. "
            "Versioned releases are immutable."
        )

    try:
        atomic_copy(source, destination, replace=False)

        release_id = register_release(
            db_path,
            product=PRODUCT,
            target=TARGET,
            version=version,
            channel=channel,
            binary_path=str(destination.relative_to(root)),
            binary_url=binary_url,
            sha256=digest,
            byte_size=size,
            released_at=int(time.time()),
            enabled=not args.disabled,
            release_notes=args.notes.strip() or None,
        )

        # Preserve the development URL already supported by FloraCore while
        # retaining immutable archives for release metadata/history.
        if channel == "dev":
            pointer = firmware_root / "dev" / "FloraCore.bin"
            atomic_copy(destination, pointer, replace=True)

    except Exception:
        # If the metadata registration fails, do not leave a newly published
        # immutable file pretending to be an approved release.
        try:
            if destination.exists():
                destination.unlink()
        except OSError:
            pass
        raise

    print("Published approved FloraCore OTA release.")
    print(f"Release ID: {release_id}")
    print(f"Product:    {PRODUCT}")
    print(f"Target:     {TARGET}")
    print(f"Version:    {version}")
    print(f"Channel:    {channel}")
    print(f"Enabled:    {not args.disabled}")
    print(f"Size:       {size} bytes")
    print(f"SHA-256:    {digest}")
    print(f"Artifact:   {destination}")
    print(f"URL:        {binary_url}")
    if channel == "dev":
        print(
            "Dev pointer: "
            f"{PUBLIC_ORIGIN}/firmware/floracore/dev/FloraCore.bin"
        )


if __name__ == "__main__":
    main()
