#!/usr/bin/env bash
set -euo pipefail

device_id="${1:?usage: fetch-attestation.sh DEVICE_ID ENDPOINT HOST}"
endpoint="${2:?usage: fetch-attestation.sh DEVICE_ID ENDPOINT HOST}"
host="${3:?usage: fetch-attestation.sh DEVICE_ID ENDPOINT HOST}"

state_dir="/var/lib/attestation"
dest="${state_dir}/attestation.json"

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

mkdir -p "$state_dir"

curl -fsS "${endpoint}/attestation/${device_id}" -o "$tmp"

install -m 0644 "$tmp" "$dest"

sudo nixos-rebuild switch --flake "/etc/nixos#${host}" --impure
