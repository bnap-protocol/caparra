#!/bin/sh
# Start the regtest network and make it ready for the e2e tests:
#
#   1. docker compose up, waiting until every service is healthy;
#   2. mine to the payer node until it has spendable coins;
#   3. open a payer -> payee channel, wait until it is active and a 1 sat
#      payment goes through;
#   4. copy the payee's TLS cert and invoice macaroon to .state/ and write
#      .state/env with the paths the bnap-rail-lnd plug needs.
#
# Idempotent: run it again and it only checks that everything is in place.
# Regtest only. POSIX sh; needs docker with the compose plugin.
#
# Usage: devenv/regtest/up.sh            then: . devenv/regtest/.state/env

set -eu

here=$(cd "$(dirname "$0")" && pwd)
state="$here/.state"

dc() { docker compose -f "$here/compose.yml" "$@"; }
btc() { dc exec -T bitcoind bitcoin-cli -regtest -rpcuser=bnap -rpcpassword=bnap "$@"; }
payer() { dc exec -T payer lncli --network=regtest "$@"; }
payee() { dc exec -T payee lncli --network=regtest "$@"; }
say() { printf 'regtest: %s\n' "$*" >&2; }

# The first string or bare value of member $1 in the JSON on stdin (lncli
# prints one member per line).
field() {
	sed -n "s/^ *\"$1\": *\"\{0,1\}\([^\",]*\)\"\{0,1\},\{0,1\} *\$/\1/p" | head -n 1
}

# Retries "$@" every second, up to $tries times.
tries=120
retry() {
	n=0
	until "$@" >/dev/null 2>&1; do
		n=$((n + 1))
		if [ "$n" -ge "$tries" ]; then
			say "gave up waiting for: $*"
			return 1
		fi
		sleep 1
	done
}

synced() { "$1" getinfo | grep -q '"synced_to_chain": *true'; }
mine() { btc generatetoaddress "$1" "$2" >/dev/null; }

# One setup at a time: test processes may run this script in parallel.
lock="$here/.lock"
n=0
until mkdir "$lock" 2>/dev/null; do
	n=$((n + 1))
	if [ "$n" -ge 600 ]; then
		say "another up.sh holds $lock; remove it if no setup is running"
		exit 1
	fi
	sleep 1
done
trap 'rmdir "$lock"' EXIT INT TERM

say "starting the containers"
dc up -d --wait --quiet-pull

retry payer getinfo
retry payee getinfo
payer_addr=$(payer newaddress p2wkh | field address)
payee_key=$(payee getinfo | field identity_pubkey)
[ -n "$payer_addr" ] && [ -n "$payee_key" ] || { say "could not read the nodes' address or key"; exit 1; }

# A fresh chain has only the genesis block, which LND does not count as
# synced: one block wakes both nodes up.
if [ "$(btc getblockcount)" -eq 0 ]; then
	mine 1 "$payer_addr"
fi
retry synced payer
retry synced payee

if ! payer listchannels --active_only | grep -q "\"remote_pubkey\": *\"$payee_key\""; then
	balance=$(payer walletbalance | field confirmed_balance)
	if [ "${balance:-0}" -lt 2000000 ]; then
		say "funding the payer"
		# 101 blocks: the first coinbase matures after 100 more.
		mine 101 "$payer_addr"
		has_funds() { [ "$(payer walletbalance | field confirmed_balance)" -ge 2000000 ]; }
		retry has_funds
	fi
	if ! payer listchannels | grep -q "\"remote_pubkey\": *\"$payee_key\"" &&
		! payer pendingchannels | grep -q "\"remote_node_pub\": *\"$payee_key\""; then
		say "opening a payer -> payee channel"
		payer connect "$payee_key@payee:9735" >/dev/null 2>&1 || true
		open() { payer openchannel --node_key "$payee_key" --local_amt 1000000; }
		retry open
	fi
	mine 6 "$payer_addr"
	active() { payer listchannels --active_only | grep -q "\"remote_pubkey\": *\"$payee_key\""; }
	retry active
fi
retry synced payee

# A channel can be active a moment before the payer's router sees its
# balance ("insufficient_balance"): pay 1 sat until a payment goes through.
pays() {
	inv=$(payee addinvoice --amt 1 --memo bnap-regtest-warmup | field payment_request)
	[ -n "$inv" ] && payer payinvoice --force --json "$inv" | grep -q '"status": *"SUCCEEDED"'
}
tries=60
retry pays

say "exporting the payee's TLS cert and invoice macaroon"
mkdir -p "$state"
dc cp payee:/root/.lnd/tls.cert "$state/payee-tls.cert" >/dev/null 2>&1
dc cp payee:/root/.lnd/data/chain/bitcoin/regtest/invoice.macaroon "$state/payee-invoice.macaroon" >/dev/null 2>&1
cat >"$state/env" <<EOF
BNAP_REGTEST_LND_ADDRESS=https://127.0.0.1:10009
BNAP_REGTEST_LND_CERT=$state/payee-tls.cert
BNAP_REGTEST_LND_MACAROON=$state/payee-invoice.macaroon
export BNAP_REGTEST_LND_ADDRESS BNAP_REGTEST_LND_CERT BNAP_REGTEST_LND_MACAROON
EOF
say "ready; the paths are in $state/env"
cat "$state/env"
