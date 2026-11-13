#!/usr/bin/env python3
import argparse
import base64
import json
import pathlib
import sys

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey


def fail(msg):
    print(f"attestation verification failed: {msg}", file=sys.stderr)
    sys.exit(1)


def load_json_file(path):
    return json.loads(pathlib.Path(path).read_text())


def load_text(path):
    return pathlib.Path(path).read_text().strip()


def canonical_json(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--attestation", required=True)
    ap.add_argument("--public-key", required=True)
    ap.add_argument("--device-id", required=True)
    ap.add_argument("--projected-config", required=True)
    args = ap.parse_args()

    att = load_json_file(args.attestation)
    local_projected = load_json_file(args.projected_config)
    pubkey_b64 = load_text(args.public_key)

    required = ["device_id", "projected_config", "payload", "signature"]
    for key in required:
        if key not in att:
            fail(f"missing field: {key}")

    if att["device_id"] != args.device_id:
        fail(
            f"device_id mismatch: expected {args.device_id}, got {att['device_id']}"
        )

    try:
        verify_key = VerifyKey(base64.b64decode(pubkey_b64))
    except Exception as e:
        fail(f"invalid public key: {e}")

    payload = att["payload"].encode("utf-8")
    try:
        sig = base64.b64decode(att["signature"])
    except Exception as e:
        fail(f"invalid signature encoding: {e}")

    try:
        verify_key.verify(payload, sig)
    except BadSignatureError:
        fail("bad signature")

    try:
        payload_obj = json.loads(att["payload"])
    except Exception as e:
        fail(f"invalid payload JSON: {e}")

    for key in ["device_id", "projected_config"]:
        if payload_obj.get(key) != att.get(key):
            fail(f"payload/top-level mismatch on {key}")

    if canonical_json(att["projected_config"]) != canonical_json(local_projected):
        print(canonical_json(local_projected))
        print(canonical_json(att["projected_config"]))
        fail(
            "local projected config does not match attested projected config"
        )

    print("attestation verification successful")


if __name__ == "__main__":
    main()
