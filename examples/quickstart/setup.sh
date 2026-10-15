#!/bin/sh
# Writes everything the quickstart gate needs into the current directory:
# the root and backup keys, K_mac, the L402 and MPP secrets, a signer key
# file with one offer key and one receipt key (valid for 7 days), and a
# manifest signed for ./gate.toml. Needs caparra-gate on PATH.
#
# In production the root key never touches the gate's host; see
# examples/llm-proxy/README.md. This script is for a local try only.

set -eu

[ -f gate.toml ] || {
	echo "setup.sh: run it in a directory that holds gate.toml" >&2
	exit 2
}

umask 077
caparra-gate key new --out root.key >/dev/null
caparra-gate key new --out backup.key >backup.pub
for k in mac l402 mpp offer receipt; do
	caparra-gate key new --out "$k.key" >/dev/null
done

not_after=$(($(date +%s) + 7 * 86400))
cat >keys.toml <<KEYS
[[key]]
use = "offer"
secret = "$(cat offer.key)"
not_after = $not_after

[[key]]
use = "receipt"
secret = "$(cat receipt.key)"
not_after = $not_after
KEYS
rm offer.key receipt.key

caparra-gate manifest sign --config gate.toml --root-key root.key \
	--backup "$(cat backup.pub)" --seq 1 --keys-from keys.toml --out manifest.json
