"""End to end over Streamable HTTP: auth, Host checks and per-identity tools."""

from __future__ import annotations

import pytest
from starlette.testclient import TestClient

from obsidian_mcp_lite.config import Settings
from obsidian_mcp_lite.server import create_http_app, create_server, host_allowed
from obsidian_mcp_lite.vault import Vault

from .conftest import TOKENS

CLAUDE = TOKENS["OBSIDIAN_MCP_TOKEN_CLAUDE"]
READER = TOKENS["OBSIDIAN_MCP_TOKEN_READER"]
ACCEPT = "application/json, text/event-stream"


@pytest.fixture
def make_client(layout, acl_store):
    def make(enable_delete: bool = False) -> TestClient:
        settings = Settings.from_env(
            {
                "OBSIDIAN_MCP_VAULT_DIR": str(layout["vault"]),
                "OBSIDIAN_MCP_DATA_DIR": str(layout["data"]),
                "OBSIDIAN_MCP_ACL_FILE": str(layout["config"] / "acl.yaml"),
            }
        )
        vault = Vault(layout["vault"], layout["data"], enable_delete=enable_delete)
        app = create_http_app(create_server(vault), settings, acl_store)
        return TestClient(app, base_url="http://obsidian-mcp-lite:8000")

    return make


@pytest.fixture
def http(make_client):
    with make_client() as client:
        yield client


def rpc(client, token, method, params=None, *, host=None, rid=1):
    headers = {"accept": ACCEPT}
    if token is not None:
        headers["authorization"] = f"Bearer {token}"
    if host is not None:
        headers["host"] = host
    body = {"jsonrpc": "2.0", "id": rid, "method": method}
    if params is not None:
        body["params"] = params
    return client.post("/mcp", json=body, headers=headers)


def call(client, token, name, **arguments):
    r = rpc(client, token, "tools/call", {"name": name, "arguments": arguments})
    assert r.status_code == 200, r.text
    return r.json()["result"]


def test_healthz(http):
    r = http.get("/healthz")
    assert r.status_code == 200 and r.json()["status"] == "ok"
    assert http.get("/healthz", headers={"host": "evil.example"}).status_code == 403


def test_missing_or_wrong_token_is_401(http):
    assert rpc(http, None, "tools/list").status_code == 401
    assert rpc(http, "x" * 40, "tools/list").status_code == 401
    assert rpc(http, CLAUDE[:-1], "tools/list").status_code == 401
    r = http.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        headers={"accept": ACCEPT, "authorization": f"Basic {CLAUDE}"},
    )
    assert r.status_code == 401
    for method in ("GET", "DELETE"):
        assert http.request(method, "/mcp").status_code == 401
    assert CLAUDE not in r.text


def test_bad_host_is_403_even_with_a_good_token(http):
    for host in ("evil.example", "obsidian-mcp-lite.evil.example", "obsidian-mcp-lite:80x"):
        assert rpc(http, CLAUDE, "tools/list", host=host).status_code == 403
    assert rpc(http, CLAUDE, "tools/list", host="obsidian-mcp-lite:8000").status_code == 200
    assert rpc(http, CLAUDE, "tools/list", host="localhost").status_code == 200


def test_host_allowed_patterns():
    allowed = ("obsidian-mcp-lite", "obsidian-mcp-lite:*", "127.0.0.1:8000")
    assert host_allowed("obsidian-mcp-lite", allowed)
    assert host_allowed("Obsidian-MCP-Lite:8000", allowed)
    assert host_allowed("127.0.0.1:8000", allowed)
    assert not host_allowed("127.0.0.1:9000", allowed)
    assert not host_allowed("obsidian-mcp-lite:", allowed)
    assert not host_allowed("obsidian-mcp-lite:8000@evil", allowed)
    assert not host_allowed("obsidian-mcp-lite:\u00b2", allowed)  # unicode digit


def test_initialize_and_tools_list_per_identity(http):
    init = rpc(
        http,
        CLAUDE,
        "initialize",
        {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "pytest", "version": "0"},
        },
    )
    assert init.status_code == 200
    assert init.json()["result"]["serverInfo"]["name"] == "obsidian-mcp-lite"

    names = {t["name"] for t in rpc(http, CLAUDE, "tools/list").json()["result"]["tools"]}
    assert names == {
        "list_dir",
        "read_file",
        "search",
        "stat",
        "write_file",
        "edit_file",
        "append_file",
        "move_file",
    }
    reader_names = {t["name"] for t in rpc(http, READER, "tools/list").json()["result"]["tools"]}
    assert reader_names == {"list_dir", "read_file", "search", "stat"}


def test_delete_tool_only_when_enabled(make_client):
    with make_client(enable_delete=True) as client:
        names = {t["name"] for t in rpc(client, CLAUDE, "tools/list").json()["result"]["tools"]}
        assert "delete_file" in names
        out = call(client, CLAUDE, "delete_file", path="Inbox/todo.md")
        assert out["isError"] is False


def test_denied_read_and_allowed_write(layout, http):
    denied = call(http, CLAUDE, "read_file", path="Private/secret-diary.md")
    assert denied["isError"] is True
    text = denied["content"][0]["text"]
    assert "path_forbidden" in text and "swordfish" not in text

    ok = call(http, CLAUDE, "write_file", path="AI/Claude/hello.md", content="hi from pytest\n")
    assert ok["isError"] is False
    assert ok["structuredContent"]["created"] is True
    assert (layout["vault"] / "AI/Claude/hello.md").read_text() == "hi from pytest\n"

    listed = call(http, CLAUDE, "list_dir", path="/")
    assert "Private" not in str(listed)


def test_hidden_write_tool_cannot_be_called(layout, http):
    out = call(http, READER, "write_file", path="Projects/x.md", content="x")
    assert out["isError"] is True and "Unknown tool" in out["content"][0]["text"]
    assert not (layout["vault"] / "Projects/x.md").exists()


def test_identity_comes_from_token_not_arguments(layout, http):
    # Hermes may write Daily/, Claude may not; the token decides.
    out = call(http, CLAUDE, "append_file", path="Daily/2026-09-29.md", content="x\n")
    assert out["isError"] is True and "path_forbidden" in out["content"][0]["text"]
    out = call(
        http,
        TOKENS["OBSIDIAN_MCP_TOKEN_HERMES"],
        "append_file",
        path="Daily/2026-09-29.md",
        content="x\n",
    )
    assert out["isError"] is False
