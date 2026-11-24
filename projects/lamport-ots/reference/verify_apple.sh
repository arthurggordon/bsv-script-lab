#!/usr/bin/env bash
# Apple Container, isolated no-peer regtest. Requires Python dependencies on host.
set -euo pipefail
cd "$(dirname "$0")"
image=docker.io/bitcoinsv/bitcoin-sv@sha256:d96fe4786a00e5fc10bc9e0e76a6006376f9472d4eb74d07e4c1e0d019493d33
name="lamport-ots-$$"
data=$(mktemp -d)
port=${LAMPORT_RPC_PORT:-18449}
cleanup() {
  container stop "$name" >/dev/null 2>&1 || true
  container delete "$name" >/dev/null 2>&1 || true
  rm -rf "$data"
}
trap cleanup EXIT
container run --platform linux/amd64 --cpus 2 --memory 1G --detach \
  --name "$name" --publish "127.0.0.1:$port:18443" --volume "$data:/data" \
  --entrypoint /usr/local/bin/bitcoind "$image" \
  -regtest -server -minminingtxfee=0.000005 -rpcport=18443 -rpcbind=0.0.0.0 -rpcallowip=0.0.0.0/0 \
  -datadir=/data -disablewallet -dbcache=64 -listen=0 -connect=0 -dnsseed=0 -discover=0 \
  -genesisactivationheight=1 -chronicleactivationheight=2 -excessiveblocksize=1000000000 \
  -maxstackmemoryusageconsensus=100000000 -maxtxsizepolicy=100000000 \
  -maxstdtxvalidationduration=1000 -maxnonstdtxvalidationduration=2000 -printtoconsole
export REGTEST_COOKIE="$data/regtest/.cookie"
export REGTEST_URL="http://127.0.0.1:$port"
for attempt in {1..60}; do
  if [[ -s "$REGTEST_COOKIE" ]] && container exec "$name" bitcoin-cli -regtest -rpcport=18443 -datadir=/data getblockcount >/dev/null 2>&1; then
    container exec "$name" bitcoind --version | head -1
    python -m unittest -v test_node test_acceptance "$@"
    exit 0
  fi
  sleep 1
done
container logs "$name"
exit 1
