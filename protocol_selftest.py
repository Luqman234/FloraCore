#!/usr/bin/env python3

import hashlib
import hmac
import json
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


DEVICE_ID = "floracore-aabbccddeeff"
ROOT = bytes(range(32))
PATH = "/api/device/v1/message"
LABEL = "floraos-e2ee-v1"


def derive(direction: str) -> bytes:
    return hmac.new(
        ROOT,
        f"{LABEL}|{direction}|{DEVICE_ID}".encode(),
        hashlib.sha256,
    ).digest()


def aad(direction: str) -> bytes:
    return (
        f"{LABEL}|{DEVICE_ID}|{direction}|{PATH}"
    ).encode()


def main() -> None:
    d2s = derive("d2s")
    s2d = derive("s2d")

    request_plain = json.dumps(
        {
            "message_id": os.urandom(16).hex(),
            "ts": 0,
            "type": "selftest",
            "payload": {"hello": "FloraOS"},
        },
        separators=(",", ":"),
    ).encode()

    nonce = os.urandom(12)

    encrypted = AESGCM(d2s).encrypt(
        nonce,
        request_plain,
        aad("d2s"),
    )

    decrypted = AESGCM(d2s).decrypt(
        nonce,
        encrypted,
        aad("d2s"),
    )

    assert decrypted == request_plain

    response_plain = b'{"ok":true}'
    response_nonce = os.urandom(12)

    response_encrypted = AESGCM(s2d).encrypt(
        response_nonce,
        response_plain,
        aad("s2d"),
    )

    response_decrypted = AESGCM(s2d).decrypt(
        response_nonce,
        response_encrypted,
        aad("s2d"),
    )

    assert response_decrypted == response_plain

    print("FloraOS E2EE protocol self-test: PASS")


if __name__ == "__main__":
    main()
