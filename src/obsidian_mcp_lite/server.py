"""MCP tool surface and the authenticated Streamable HTTP app.

Request flow: ``GuardMiddleware`` checks the Host header (403), then the bearer
token (401), and pins the caller's ``Identity`` plus a snapshot of the ACL
onto the ASGI scope. Tools read them back from the request context, so one
request always sees one consistent ACL even if the file is reloaded mid-way.
"""

from __future__ import annotations

import hmac
import os
from typing import Any

from mcp.server.mcpserver import Context, MCPServer
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import CallToolResult, ListToolsResult, TextContent, ToolAnnotations
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from . import __version__
from .acl import Acl, AclStore, Identity
from .config import Settings
from .errors import VaultError
from .search import search as run_search
from .vault import Vault

SCOPE_IDENTITY = "obsidian_mcp.identity"
SCOPE_ACL = "obsidian_mcp.acl"

READ_ONLY = ToolAnnotations(readOnlyHint=True, openWorldHint=False)
ADDITIVE = ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=False)
OVERWRITES = ToolAnnotations(readOnlyHint=False, destructiveHint=True, openWorldHint=False)

WRITE_TOOLS = frozenset({"write_file", "edit_file", "append_file", "move_file", "delete_file"})

INSTRUCTIONS = (
    "Access to an Obsidian vault. Paths are relative to the vault root, use '/' separators, "
    "and must not start with '/' or contain '..'. Your identity decides which folders you "
    "can read and write; folders you cannot read are invisible. To change an existing note: "
    "read_file (or stat) to get its revision, then edit_file for targeted changes or "
    "write_file with expected_revision to replace it. A 'conflict' error means the note "
    "changed since you read it (the owner edits from other devices and a sync client runs "
    "continuously): re-read and retry. Use append_file for logs and daily notes."
)


# ---------------------------------------------------------------------- HTTP guard


def host_allowed(host: str, allowed: tuple[str, ...]) -> bool:
    """Exact match, or ``name:*`` = that name with or without any numeric port."""
    host = host.strip().lower()
    for pattern in (a.lower() for a in allowed):
        if pattern.endswith(":*"):
            base = pattern[:-2]
            if host == base or (host.startswith(base + ":") and host[len(base) + 1 :].isdigit()):
                return True
        elif host == pattern:
            return True
    return False


class GuardMiddleware:
    """Host allowlist (403) and bearer auth (401) in front of the MCP app."""

    def __init__(self, app: Any, *, acl_store: AclStore, allowed_hosts: tuple[str, ...]):
        self.app = app
        self.acl_store = acl_store
        self.allowed_hosts = allowed_hosts

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = [(k.lower(), v) for k, v in scope.get("headers", [])]
        hosts = [v for k, v in headers if k == b"host"]
        if len(hosts) != 1 or not host_allowed(hosts[0].decode("latin-1"), self.allowed_hosts):
            await Response("Forbidden: Host not allowed", status_code=403)(scope, receive, send)
            return
        path = scope.get("path", "")
        if path == "/mcp" or path.startswith("/mcp/"):
            identity, acl = self._authenticate(headers)
            if identity is None:
                await Response(
                    "Unauthorized", status_code=401, headers={"WWW-Authenticate": "Bearer"}
                )(scope, receive, send)
                return
            scope[SCOPE_IDENTITY] = identity
            scope[SCOPE_ACL] = acl
        await self.app(scope, receive, send)

    def _authenticate(self, headers: list[tuple[bytes, bytes]]) -> tuple[Identity | None, Acl]:
        acl = self.acl_store.get()
        auth = [v for k, v in headers if k == b"authorization"]
        if len(auth) != 1:
            return None, acl
        scheme, _, token = auth[0].decode("latin-1").partition(" ")
        if not hmac.compare_digest(scheme.lower().encode(), b"bearer") or not token.strip():
            return None, acl
        return acl.identify(token.strip()), acl


# ---------------------------------------------------------------------- MCP server


class ObsidianServer(MCPServer):
    """MCPServer whose tools/list and tools/call depend on the caller's identity."""

    enable_delete: bool = False

    @staticmethod
    def _caller(ctx: Any) -> Identity | None:
        request = getattr(ctx, "request", None)
        scope = getattr(request, "scope", None) or {}
        return scope.get(SCOPE_IDENTITY)

    def _visible(self, name: str, identity: Identity | None) -> bool:
        if name == "delete_file" and not self.enable_delete:
            return False
        if name in WRITE_TOOLS:
            return identity is not None and identity.can_write_anything
        return True

    async def _handle_list_tools(self, ctx: Any, params: Any) -> ListToolsResult:
        result = await super()._handle_list_tools(ctx, params)
        identity = self._caller(ctx)
        return ListToolsResult(tools=[t for t in result.tools if self._visible(t.name, identity)])

    async def _handle_call_tool(self, ctx: Any, params: Any) -> Any:
        if not self._visible(params.name, self._caller(ctx)):
            return CallToolResult(
                content=[TextContent(type="text", text=f"Unknown tool: {params.name}")],
                is_error=True,
            )
        return await super()._handle_call_tool(ctx, params)


def _who(ctx: Context) -> tuple[Identity, Acl]:
    request = ctx.request_context.request
    scope = getattr(request, "scope", None) or {}
    identity, acl = scope.get(SCOPE_IDENTITY), scope.get(SCOPE_ACL)
    if identity is None or acl is None:
        raise VaultError("unauthorized", "no authenticated identity on this request")
    return identity, acl


def create_server(vault: Vault) -> ObsidianServer:
    server = ObsidianServer(
        name="obsidian-mcp-lite",
        title="Obsidian vault",
        description="Obsidian vault access with per-agent folder permissions.",
        instructions=INSTRUCTIONS,
        version=__version__,
    )
    server.enable_delete = vault.enable_delete

    @server.tool(
        description=(
            "List a folder in the vault: each entry's path, type (file/dir), size and mtime. "
            "path defaults to the vault root. recursive=true walks subfolders. At most "
            "max_entries (default 500, max 5000) are returned; if 'truncated' is set, call "
            "again with offset=next_offset. Hidden (dot) files and folders you can't read are "
            "not shown."
        ),
        annotations=READ_ONLY,
    )
    def list_dir(
        ctx: Context,
        path: str = ".",
        recursive: bool = False,
        max_entries: int = 500,
        offset: int = 0,
    ) -> dict[str, Any]:
        identity, acl = _who(ctx)
        return vault.list_dir(identity, acl, path, recursive, max_entries, offset)

    @server.tool(
        description=(
            "Read a UTF-8 text note. Returns content with line numbers ('   12<TAB>text'; the "
            "number and tab are not part of the file), total_lines, and revision (sha256 of the "
            "whole file; pass it to write_file/edit_file as expected_revision). offset is the "
            "1-based first line, limit the number of lines (default 2000); if 'truncated' is "
            "set, continue from next_offset. Binary and very large files are refused."
        ),
        annotations=READ_ONLY,
    )
    def read_file(
        ctx: Context, path: str, offset: int | None = None, limit: int | None = None
    ) -> dict[str, Any]:
        identity, acl = _who(ctx)
        return vault.read_file(identity, acl, path, offset, limit)

    @server.tool(
        description=(
            "Search the vault, case-insensitively. Matches file names/paths and note contents "
            "(.md .txt .canvas .base .json) and returns filename_matches plus content_matches "
            "with line numbers and a snippet. query is literal text unless regex=true. path "
            "limits the search to a folder. max_results defaults to 50 (max 500)."
        ),
        annotations=READ_ONLY,
    )
    def search(
        ctx: Context,
        query: str,
        path: str | None = None,
        regex: bool = False,
        max_results: int = 50,
    ) -> dict[str, Any]:
        identity, acl = _who(ctx)
        return run_search(vault, identity, acl, query, path, regex, max_results)

    @server.tool(
        description=(
            "Check a path: exists, type, size, mtime and (for files) revision. Returns "
            "exists=false for a path you may read that doesn't exist yet."
        ),
        annotations=READ_ONLY,
    )
    def stat(ctx: Context, path: str) -> dict[str, Any]:
        identity, acl = _who(ctx)
        return vault.stat(identity, acl, path)

    @server.tool(
        description=(
            "Create or replace a text note (.md .txt .canvas .base .json). Missing parent "
            "folders are created. Replacing an existing file REQUIRES expected_revision from "
            "read_file/stat; if the file changed since, you get a 'conflict' error and nothing is "
            "written. create_only=true refuses to touch an existing file. For small changes "
            "prefer edit_file; for adding to the end prefer append_file."
        ),
        annotations=OVERWRITES,
    )
    def write_file(
        ctx: Context,
        path: str,
        content: str,
        expected_revision: str | None = None,
        create_only: bool = False,
    ) -> dict[str, Any]:
        identity, acl = _who(ctx)
        return vault.write_file(identity, acl, path, content, expected_revision, create_only)

    @server.tool(
        description=(
            "Replace an exact string in a note (like a text editor's find/replace, not a diff). "
            "old_string must match the file exactly, including whitespace, and must occur once "
            "unless replace_all=true; otherwise you get 'no_match' or 'ambiguous_match' and "
            "nothing changes. Do not include read_file's line-number prefixes. expected_revision "
            "is optional but recommended."
        ),
        annotations=OVERWRITES,
    )
    def edit_file(
        ctx: Context,
        path: str,
        old_string: str,
        new_string: str,
        replace_all: bool = False,
        expected_revision: str | None = None,
    ) -> dict[str, Any]:
        identity, acl = _who(ctx)
        return vault.edit_file(
            identity, acl, path, old_string, new_string, replace_all, expected_revision
        )

    @server.tool(
        description=(
            "Append text to the end of a note, creating it (and its folders) if missing. For "
            "daily notes and logs; no revision needed. If the file doesn't end with a newline, "
            "one is added before your content. Include your own trailing newline."
        ),
        annotations=ADDITIVE,
    )
    def append_file(ctx: Context, path: str, content: str) -> dict[str, Any]:
        identity, acl = _who(ctx)
        return vault.append_file(identity, acl, path, content)

    @server.tool(
        description=(
            "Move or rename a note. Needs write access to both src and dst; never overwrites an "
            "existing dst. Does NOT rewrite [[wikilinks]] in other notes; links to the old "
            "path will break, so search for and fix them if that matters."
        ),
        annotations=OVERWRITES,
    )
    def move_file(ctx: Context, src: str, dst: str) -> dict[str, Any]:
        identity, acl = _who(ctx)
        return vault.move_file(identity, acl, src, dst)

    if vault.enable_delete:

        @server.tool(
            description=(
                "Delete a note by moving it to the vault's .trash folder (recoverable by the "
                "owner). Needs write access to the path."
            ),
            annotations=OVERWRITES,
        )
        def delete_file(ctx: Context, path: str) -> dict[str, Any]:
            identity, acl = _who(ctx)
            return vault.delete_file(identity, acl, path)

    return server


def create_http_app(server: ObsidianServer, settings: Settings, acl_store: AclStore) -> Any:
    hosts = list(settings.allowed_hosts)
    security = TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=hosts,
        allowed_origins=[f"{scheme}://{host}" for scheme in ("http", "https") for host in hosts],
    )

    async def healthz(_request: Request) -> Response:
        return JSONResponse(
            {
                "status": "ok",
                "service": "obsidian-mcp-lite",
                "version": __version__,
                "build": os.environ.get("OBSIDIAN_MCP_BUILD_COMMIT") or None,
            }
        )

    app = server.streamable_http_app(
        streamable_http_path="/mcp",
        stateless_http=True,
        json_response=True,
        transport_security=security,
        host="0.0.0.0",
    )
    app.add_route("/healthz", healthz, methods=["GET"])
    app.add_middleware(GuardMiddleware, acl_store=acl_store, allowed_hosts=settings.allowed_hosts)
    return app
