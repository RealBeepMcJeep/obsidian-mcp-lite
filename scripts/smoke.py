"""Smoke-test a running obsidian-mcp-lite over HTTP (stdlib only).

Expects the server to use deploy/ci-acl.yaml semantics:
  writer: read "/", write "AI/Smoke/", deny "Private/"
  reader: read "Projects/" only

    SMOKE_WRITER_TOKEN=... SMOKE_READER_TOKEN=... python scripts/smoke.py --url http://127.0.0.1:18000
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
import uuid

ACCEPT = "application/json, text/event-stream"


def request(url, *, token=None, host=None, body=None, method="POST"):
    headers = {"Accept": ACCEPT, "Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if host:
        headers["Host"] = host
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode()


def rpc(base, token, method, params=None, rid=1):
    body = {"jsonrpc": "2.0", "id": rid, "method": method}
    if params is not None:
        body["params"] = params
    status, text = request(f"{base}/mcp", token=token, body=body)
    if status != 200:
        raise RuntimeError(f"{method} returned HTTP {status}: {text[:200]}")
    msg = json.loads(text)
    if "error" in msg:
        raise RuntimeError(f"{method} returned JSON-RPC error: {msg['error']}")
    return msg["result"]


def call(base, token, name, **arguments):
    return rpc(base, token, "tools/call", {"name": name, "arguments": arguments})


def smoke(base: str, writer: str, reader: str) -> None:
    for _ in range(45):
        try:
            status, _ = request(f"{base}/healthz", method="GET")
            if status == 200:
                break
        except (urllib.error.URLError, ConnectionError, OSError):
            # docker-proxy accepts and then resets connections until the app listens.
            pass
        time.sleep(1)
    else:
        raise RuntimeError("/healthz did not become ready within 45 seconds")

    list_body = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
    for label, token, host, want in (
        ("no token", None, None, 401),
        ("wrong token", "wrong-" + "x" * 40, None, 401),
        ("bad Host", writer, "evil.example", 403),
    ):
        status, _ = request(f"{base}/mcp", token=token, host=host, body=list_body)
        if status != want:
            raise RuntimeError(f"{label}: expected HTTP {want}, got {status}")

    init = rpc(
        base,
        writer,
        "initialize",
        {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "smoke", "version": "0"},
        },
    )
    tools = {t["name"] for t in rpc(base, writer, "tools/list")["tools"]}
    if not {"read_file", "write_file", "search"} <= tools:
        raise RuntimeError(f"writer tools/list is missing tools: {sorted(tools)}")
    reader_tools = {t["name"] for t in rpc(base, reader, "tools/list")["tools"]}
    if "write_file" in reader_tools:
        raise RuntimeError("reader can see write_file")

    denied = call(base, writer, "read_file", path="Private/secret.md")
    if not denied.get("isError") or "path_forbidden" not in denied["content"][0]["text"]:
        raise RuntimeError(f"denied read was not refused: {denied}")

    name = f"AI/Smoke/smoke-{uuid.uuid4().hex[:8]}.md"
    wrote = call(base, writer, "write_file", path=name, content="smoke ok\n", create_only=True)
    if wrote.get("isError"):
        raise RuntimeError(f"allowed write failed: {wrote}")
    back = call(base, writer, "read_file", path=name)
    if back.get("isError") or "smoke ok" not in back["structuredContent"]["content"]:
        raise RuntimeError(f"read-back failed: {back}")

    print(
        "Smoke passed: healthz, 401 without/with wrong token, 403 on bad Host, "
        f"initialize (protocol {init.get('protocolVersion')}), tools/list per identity "
        f"({len(tools)} writer / {len(reader_tools)} reader tools), denied read, "
        f"allowed write + read-back of {name}."
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--url", default="http://127.0.0.1:18000")
    args = parser.parse_args()
    writer = os.environ.get("SMOKE_WRITER_TOKEN", "")
    reader = os.environ.get("SMOKE_READER_TOKEN", "")
    if len(writer) < 32 or len(reader) < 32:
        parser.error("set SMOKE_WRITER_TOKEN and SMOKE_READER_TOKEN (32+ characters each)")
    try:
        smoke(args.url.rstrip("/"), writer, reader)
    except (RuntimeError, urllib.error.URLError) as exc:
        print(f"Smoke failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
