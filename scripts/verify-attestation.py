#!/usr/bin/env python3
import argparse
import base64
import json
import pathlib
import sys

from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError


def read_text(path):
    return pathlib.Path(path).read_text().strip()


def load_json(path):
    return json.loads(pathlib.Path(path).read_text())


def fail(msg):
    print(f"attestation verify failed: {msg}", file=sys.stderr)
    sys.exit(1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--attestation", required=True)
    ap.add_argument("--public-key", required=True)
    ap.add_argument("--trusted-current-root", required=True)
    ap.add_argument("--candidate-root", required=True)
    ap.add_argument("--projected-config", required=True)
    ap.add_argument("--device-id", required=True)
    args = ap.parse_args()

    att = load_json(args.attestation)
    trusted_current_root = read_text(args.trusted_current_root)
    candidate_root = read_text(args.candidate_root)
    expected_device_id = args.device_id

    for key in ["device_id", "currentRoot", "nextRoot", "payload", "signature"]:
        if key not in att:
            fail(f"missing field {key}")

    if att["device_id"] != expected_device_id:
        fail(f"device_id mismatch: expected {expected_device_id}, got {att['device_id']}")

    if att["currentRoot"] != trusted_current_root:
        fail(
            f"currentRoot mismatch: trusted={trusted_current_root} attestation={att['currentRoot']}"
        )

    if att["nextRoot"] != candidate_root:
        fail(
            f"nextRoot mismatch: candidate={candidate_root} attestation={att['nextRoot']}"
        )

    pubkey_b64 = read_text(args.public_key)
    try:
        verify_key = VerifyKey(base64.b64decode(pubkey_b64))
    except Exception as e:
        fail(f"invalid public key: {e}")

    payload = att["payload"].encode("utf-8")
    try:
        sig = base64.b64decode(att["signature"])
    except Exception as e:
        fail(f"invalid base64 signature: {e}")

    try:
        verify_key.verify(payload, sig)
    except BadSignatureError:
        fail("bad signature")

    try:
        payload_obj = json.loads(att["payload"])
    except Exception as e:
        fail(f"payload is not valid JSON: {e}")

    for key in ["device_id", "currentRoot", "nextRoot"]:
        if payload_obj.get(key) != att.get(key):
            fail(f"payload/top-level mismatch on {key}")

    print("attestation verify ok")


if __name__ == "__main__":
    main()
