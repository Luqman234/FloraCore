#!/usr/bin/env python3

"""
Derive FloraOS network keys from the ORIGINAL 32-byte HMAC eFuse
key file and write only the derived network keys to a registry.

Run this on a trusted/offline machine if possible.

The raw HMAC key should NOT be copied to the web server.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
from pathlib import Path


PROTOCOL_LABEL = "floraos-e2ee-v1"


def derive(
    root_key: bytes,
    direction: str,
    device_id: str,
) -> bytes:
    context = (
        f"{PROTOCOL_LABEL}|"
        f"{direction}|"
        f"{device_id}"
    ).encode("utf-8")

    return hmac.new(
        root_key,
        context,
        hashlib.sha256,
    ).digest()


def main() -> None:
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--device-id",
        required=True,
        help="Exact device ID printed by FloraCore, e.g. floracore-aabbccddeeff",
    )

    parser.add_argument(
        "--hmac-key-file",
        required=True,
        type=Path,
        help="Original raw 32-byte key file used when the HMAC_UP eFuse was provisioned.",
    )

    parser.add_argument(
        "--registry",
        required=True,
        type=Path,
        help="Output device_keys.json registry.",
    )

    args = parser.parse_args()

    root_key = args.hmac_key_file.read_bytes()

    if len(root_key) != 32:
        raise SystemExit(
            "HMAC key file must contain exactly 32 raw bytes."
        )

    if args.registry.exists():
        registry = json.loads(
            args.registry.read_text()
        )
    else:
        registry = {}

    registry[
        args.device_id
    ] = {
        "d2s_key": derive(
            root_key,
            "d2s",
            args.device_id,
        ).hex(),

        "s2d_key": derive(
            root_key,
            "s2d",
            args.device_id,
        ).hex(),
    }

    args.registry.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    args.registry.write_text(
        json.dumps(
            registry,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )

    os.chmod(
        args.registry,
        0o600,
    )

    print(
        f"Provisioned {args.device_id}"
    )

    print(
        f"Wrote derived network keys to {args.registry}"
    )

    print(
        "The registry does NOT contain the raw eFuse HMAC key."
    )


if __name__ == "__main__":
    main()
