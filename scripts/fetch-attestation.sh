#!/usr/bin/env bash
set -euo pipefail

device_id="${1:?usage: fetch_attestation.sh DEVICE_ID ENDPOINT HOST TRANSITION}"
endpoint="${2:?usage: fetch_attestation.sh DEVICE_ID ENDPOINT HOST TRANSITION}"
host="${3:?usage: fetch_attestation.sh DEVICE_ID ENDPOINT HOST TRANSITION}"
transition="${4:?usage: fetch_attestation.sh DEVICE_ID ENDPOINT HOST TRANSITION}"

state_dir="/var/lib/attestation"
dest="${state_dir}/attestation.json"

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

mkdir -p "$state_dir"

curl -fsS -X POST \
  -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg device_id "$device_id" --arg transition "$transition" '{device_id:$device_id, transition:$transition}')" \
  "${endpoint}/attestation" \
  -o "$tmp"

install -m 0644 "$tmp" "$dest"

sudo nixos-rebuild switch --impure
