#!/bin/sh
# Smoke-test a deployed obsidian-mcp-lite from the TrueNAS shell, from inside
# the mcp_backend network (the service has no published ports).
#
#   sh smoke-truenas.sh
#
# For each identity (default: CLAUDE_RC and HERMES) it checks initialize,
# tools/list, that Private/ is invisible (read_file Private/README.md is
# refused, list_dir / doesn't show it), and one allowed write into WRITE_DIR.
# Tokens are read from the running container, so nothing is pasted or echoed.
# Each run creates one small note per identity in WRITE_DIR; delete them if you like.
set -eu

IDENTITIES="${IDENTITIES:-CLAUDE_RC HERMES}"
WRITE_DIR="${WRITE_DIR:-LLM_Data}"
BASE="http://obsidian-mcp-lite:8000"
FAILED=0

curl_net() { docker run --rm --network mcp_backend curlimages/curl -sS "$@"; }

mcp() {  # $1 = token, $2 = JSON-RPC body
  curl_net -H "Authorization: Bearer $1" \
    -H "Accept: application/json, text/event-stream" \
    -H "Content-Type: application/json" \
    -d "$2" "$BASE/mcp"
}

check() {  # $1 = label, $2 = output, $3 = grep -E pattern that must match, $4 = pattern that must NOT match
  if printf '%s' "$2" | grep -Eq "$3" && ! printf '%s' "$2" | grep -Eq "${4:-^\$NEVER}"; then
    echo "  PASS  $1"
  else
    echo "  FAIL  $1"; printf '        %s\n' "$2" | cut -c1-400; FAILED=1
  fi
}

echo "== healthz and unauthenticated request"
check "healthz 200" "$(curl_net -w ' HTTP %{http_code}' "$BASE/healthz")" 'HTTP 200'
check "no token -> 401" "$(curl_net -o /dev/null -w 'HTTP %{http_code}' -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' "$BASE/mcp")" 'HTTP 401'

for ID in $IDENTITIES; do
  echo "== identity $ID"
  TOKEN="$(docker exec obsidian-mcp-lite printenv "OBSIDIAN_MCP_TOKEN_${ID}")"

  out="$(mcp "$TOKEN" '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"smoke","version":"0"}}}')"
  check "initialize" "$out" '"serverInfo"'

  out="$(mcp "$TOKEN" '{"jsonrpc":"2.0","id":2,"method":"tools/list"}')"
  check "tools/list has read_file + write_file, no delete_file" "$out" '"read_file".*"write_file"|"write_file".*"read_file"' '"delete_file"'

  out="$(mcp "$TOKEN" '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"Private/README.md"}}}')"
  check "read_file Private/README.md is refused" "$out" '"isError":true.*path_forbidden|path_forbidden.*"isError":true'

  out="$(mcp "$TOKEN" '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"list_dir","arguments":{"path":"/"}}}')"
  check "list_dir / does not show Private" "$out" '"isError":false' 'Private'

  out="$(mcp "$TOKEN" '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"search","arguments":{"query":"Private"}}}')"
  check "search 'Private' reveals nothing under Private/" "$out" '"isError":false' '"path":"Private'

  NOTE="${WRITE_DIR}/obsidian-mcp-smoke-$(echo "$ID" | tr 'A-Z_' 'a-z-')-$(date +%Y%m%d-%H%M%S).md"
  out="$(mcp "$TOKEN" "{\"jsonrpc\":\"2.0\",\"id\":6,\"method\":\"tools/call\",\"params\":{\"name\":\"write_file\",\"arguments\":{\"path\":\"${NOTE}\",\"content\":\"obsidian-mcp-lite smoke test\\n\",\"create_only\":true}}}")"
  check "allowed write $NOTE" "$out" '"isError":false.*"created":true|"created":true.*"isError":false'
done

echo "== last audit entries"
tail -n 2 /mnt/tank3/apps/obsidian-mcp/data/audit.jsonl || true

[ "$FAILED" = 0 ] && echo "ALL PASSED" || { echo "SOME CHECKS FAILED"; exit 1; }
