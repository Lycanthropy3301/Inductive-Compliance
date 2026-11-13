#!/usr/bin/env python3
import argparse
import base64
import copy
import json
import os
import pathlib
from http.server import BaseHTTPRequestHandler, HTTPServer

from nacl.signing import SigningKey


def canonical_json(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def parse_transition(t):
    if "=" not in t:
        raise ValueError("transition must be of form path=value")
    path, raw_value = t.split("=", 1)
    path_parts = path.split(".")
    try:
        value = json.loads(raw_value)
    except Exception:
        value = raw_value
    return path_parts, value


def set_deep(obj, path_parts, value):
    cur = obj
    for part in path_parts[:-1]:
        if part not in cur or not isinstance(cur[part], dict):
            cur[part] = {}
        cur = cur[part]
    cur[path_parts[-1]] = value


def load_json(path, default):
    p = pathlib.Path(path)
    if not p.exists():
        return copy.deepcopy(default)
    return json.loads(p.read_text())


def save_json(path, obj):
    p = pathlib.Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj, indent=2, sort_keys=True))


class App:
    def __init__(self, state_dir="", signing_key=""):
        self.state_dir = pathlib.Path(state_dir)
        self.signing_key = signing_key

    def device_state_file(self, device_id):
        return self.state_dir / f"{device_id}.json"

    def get_device_state(self, device_id):
        default = {
            "attestation": {
                "enable": True,
                "deviceId": device_id,
                "projectionVersion": 1,
            },
            "services": {
                "openssh": {
                    "enable": False,
                    "passwordAuthentication": True,
                    "permitRootLogin": "yes",
                }
            },
            "networking": {
                "firewall": {
                    "enable": True,
                    "allowedTCPPorts": [],
                }
            },
        }
        return load_json(self.device_state_file(device_id), default)

    def set_device_state(self, device_id, state):
        save_json(self.device_state_file(device_id), state)

    def make_attestation(self, device_id, projected_config):
        payload_obj = {
            "device_id": device_id,
            "projected_config": projected_config,
        }
        payload = canonical_json(payload_obj).encode("utf-8")
        signature = self.signing_key.sign(payload).signature

        return {
            "device_id": device_id,
            "projected_config": projected_config,
            "payload": payload.decode("utf-8"),
            "signature": base64.b64encode(signature).decode("ascii"),
        }


class Handler(BaseHTTPRequestHandler):
    app = App()

    def _json_response(self, status, obj):
        body = json.dumps(obj, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path != "/attestation":
            self._json_response(404, {"error": "not found"})
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length)
            req = json.loads(raw.decode("utf-8"))
        except Exception as e:
            self._json_response(400, {"error": f"bad json: {e}"})
            return

        device_id = req.get("device_id")
        transition = req.get("transition")

        if not device_id or not transition:
            self._json_response(400, {"error": "device_id and transition required"})
            return

        try:
            path_parts, value = parse_transition(transition)
        except Exception as e:
            self._json_response(400, {"error": str(e)})
            return

        current_state = self.app.get_device_state(device_id)
        next_state = copy.deepcopy(current_state)
        set_deep(next_state, path_parts, value)

        print()
        print("=== Attestation Request ===")
        print(f"device_id   : {device_id}")
        print(f"transition  : {transition}")
        print("current val : ", end="")
        cur = current_state
        try:
            for p in path_parts:
                cur = cur[p]
            print(repr(cur))
        except Exception:
            print("<unset>")
        print(f"next val    : {value!r}")
        print("===========================")
        approve = input("Approve? [y/N] ").strip().lower() == "y"

        if not approve:
            self._json_response(403, {"error": "denied"})
            return

        self.app.set_device_state(device_id, next_state)
        attestation = self.app.make_attestation(device_id, next_state)
        self._json_response(200, attestation)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--state-dir", default="./server_state")
    ap.add_argument("--secret-key-file", default="./server_state/server_ed25519.sk")
    args = ap.parse_args()

    sk_path = pathlib.Path(args.secret_key_file)
    sk_path.parent.mkdir(parents=True, exist_ok=True)

    if sk_path.exists():
        signing_key = SigningKey(base64.b64decode(sk_path.read_text().strip()))
    else:
        signing_key = SigningKey.generate()
        sk_path.write_text(base64.b64encode(bytes(signing_key)).decode("ascii"))
        pub_path = sk_path.with_suffix(".pub")
        pub_path.write_text(base64.b64encode(bytes(signing_key.verify_key)).decode("ascii"))
        print(f"Generated keypair:")
        print(f"  secret: {sk_path}")
        print(f"  public: {pub_path}")

    app = App(args.state_dir, signing_key)
    Handler.app = app

    server = HTTPServer((args.host, args.port), Handler)
    print(f"Listening on http://{args.host}:{args.port}")
    server.serve_forever()


if __name__ == "__main__":
    main()
