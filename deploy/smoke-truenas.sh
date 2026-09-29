#!/bin/sh
# Smoke-test a deployed obsidian-mcp-lite from the TrueNAS shell, from inside
# the mcp_backend network (the service has no published ports).
#
#   sh smoke-truenas.sh            # uses the claude identity's token
#   IDENTITY=HERMES WRITE_DIR=AI/Hermes sh smoke-truenas.sh
#
# The token is read from the running container, so nothing is pasted or echoed.
# Step 4 creates one small note in WRITE_DIR (delete it afterwards if you like).
set -eu

IDENTITY="${IDENTITY:-CLAUDE}"
WRITE_DIR="${WRITE_DIR:-AI/Claude}"
DENIED_PATH="${DENIED_PATH:-Private/anything.md}"
URL="http://obsidian-mcp-lite:8000/mcp"
TOKEN="$(docker exec obsidian-mcp-lite printenv "OBSIDIAN_MCP_TOKEN_${IDENTITY}")"

mcp() {
  docker run --rm --network mcp_backend curlimages/curl -sS \
    -H "Authorization: Bearer ${TOKEN}" \
    -H "Accept: application/json, text/event-stream" \
    -H "Content-Type: application/json" \
    -w '\nHTTP %{http_code}\n' \
    -d "$1" "$URL"
}

echo "== 0. healthz and auth (expect 200, then 401 without a token)"
docker run --rm --network mcp_backend curlimages/curl -sS -w '\nHTTP %{http_code}\n' \
  http://obsidian-mcp-lite:8000/healthz
docker run --rm --network mcp_backend curlimages/curl -sS -o /dev/null -w 'HTTP %{http_code}\n' \
  -H "Content-Type: application/json" -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' "$URL"

echo "== 1. initialize"
mcp '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"smoke","version":"0"}}}'

echo "== 2. tools/list (write tools appear only for identities with write rules)"
mcp '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' | grep -o '"name":"[a-z_]*"' | sort -u

echo "== 3. denied read (expect isError true and path_forbidden)"
mcp "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"read_file\",\"arguments\":{\"path\":\"${DENIED_PATH}\"}}}"

NOTE="${WRITE_DIR}/obsidian-mcp-smoke-$(date +%Y%m%d-%H%M%S).md"
echo "== 4. allowed write of ${NOTE} (expect isError false, created true)"
mcp "{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"tools/call\",\"params\":{\"name\":\"write_file\",\"arguments\":{\"path\":\"${NOTE}\",\"content\":\"obsidian-mcp-lite smoke test\\n\",\"create_only\":true}}}"

echo "== 5. last audit entry"
tail -n 1 /mnt/tank3/apps/obsidian-mcp/data/audit.jsonl
