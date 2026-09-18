#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import hashlib
import os
import shutil
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parent
DEST_DIR = ROOT / "firmware" / "floracore" / "dev"
DEST = DEST_DIR / "FloraCore.bin"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit(
            "Usage: python publish_dev_firmware.py /path/to/floracore-firmware.bin"
        )

    source = Path(sys.argv[1]).expanduser().resolve()
    if not source.is_file():
        raise SystemExit(f"Firmware file not found: {source}")
    if source.suffix.lower() != ".bin":
        raise SystemExit("Refusing to publish a non-.bin file.")

    size = source.stat().st_size
    if size < 64 * 1024:
        raise SystemExit(
            f"Firmware is only {size} bytes; refusing to publish a suspiciously small image."
        )

    DEST_DIR.mkdir(parents=True, exist_ok=True)

    if DEST.exists():
        backup = DEST_DIR / f"FloraCore-{time.strftime('%Y%m%d-%H%M%S')}.bin.bak"
        shutil.copy2(DEST, backup)
        print(f"Previous dev image backed up to: {backup}")

    # Copy into the destination directory, fsync, then os.replace(). A request
    # will therefore see either the old complete image or the new complete image,
    # never a half-written firmware file.
    fd, temporary_name = tempfile.mkstemp(
        prefix=".FloraCore-",
        suffix=".bin.tmp",
        dir=DEST_DIR,
    )
    try:
        with os.fdopen(fd, "wb") as out, source.open("rb") as incoming:
            shutil.copyfileobj(incoming, out, length=1024 * 1024)
            out.flush()
            os.fsync(out.fileno())
        os.replace(temporary_name, DEST)
    except Exception:
        try:
            os.unlink(temporary_name)
        except OSError:
            pass
        raise

    digest = sha256(DEST)
    print("Published FloraCore development OTA firmware.")
    print(f"Path:   {DEST}")
    print(f"Size:   {DEST.stat().st_size} bytes")
    print(f"SHA256: {digest}")
    print("URL:    https://floraos.life/firmware/floracore/dev/FloraCore.bin")


if __name__ == "__main__":
    main()
