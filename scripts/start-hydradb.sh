#!/usr/bin/env bash
# Start a single-node HydraDB in Docker for local dev / CI.
# Usage: scripts/start-hydradb.sh [data-dir] [container-name]
set -euo pipefail

DATA_DIR="${1:-$PWD/hydradb-data}"
NAME="${2:-hydradb-dev}"
TOKEN="local-development-token-32-bytes"

mkdir -p "$DATA_DIR/store" "$DATA_DIR/cache"
printf '%s\n' "$TOKEN" > "$DATA_DIR/auth-token"

docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" \
  --user "$(id -u):$(id -g)" \
  -p 7687:7687 -p 8443:8443 -p 9090:9090 \
  -v "$DATA_DIR:/data" \
  -e CLOUD_PROVIDER=local \
  -e LOCAL_PATH=/data/store \
  -e GRAPH_NAMESPACE=default \
  -e GRAPH_ID=default \
  -e GRAPH_CELL_ID=cell-0 \
  -e GRAPH_CELLS=cell-0 \
  -e GRAPH_NODE_ID=node-0 \
  -e GRAPH_BOLT_NODE_ADDRESSES=node-0=127.0.0.1:7687 \
  -e GRAPH_ADVERTISED_BOLT_ADDR=127.0.0.1:7687 \
  -e GRAPH_DATA_CACHE_DIR=/data/cache \
  -e GRAPH_AUTH_TOKEN_FILE=/data/auth-token \
  -e GRAPH_ALLOW_PLAINTEXT=true \
  -e RUST_MIN_STACK=33554432 \
  "${HYDRADB_IMAGE:-ghcr.io/hydra-db/hydradb@sha256:db78309a233be54662db29744047e985a39b51c45a270d1a1f47c31a62cdb709}"

# Wait for a real round-tripped write, not just a listening port.
for i in $(seq 1 60); do
  if curl -sS -m 5 http://127.0.0.1:8443/v1/graphs/default/query \
    -H "Authorization: Bearer $TOKEN" \
    -H 'X-Graph-Namespace: default' \
    -H 'Content-Type: application/json' \
    --data '{"cell_id":"cell-0","query":"MATCH (probe:StartupProbe {boot: 1}) RETURN probe.boot"}' \
    | grep -q '"columns"'; then
    echo "HydraDB ready (attempt $i)"
    exit 0
  fi
  sleep 2
done
echo "HydraDB failed to become ready" >&2
docker logs "$NAME" | tail -20 >&2
exit 1
