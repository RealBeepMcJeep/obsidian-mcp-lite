"""CLI entry point: ``obsidian-mcp-lite serve`` runs the Streamable HTTP server."""

from __future__ import annotations

import argparse
import logging
import os
import signal
from collections.abc import Sequence

from . import __version__
from .acl import AclStore
from .config import Settings
from .server import create_http_app, create_server
from .vault import Vault


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="obsidian-mcp-lite",
        description="MCP server for an Obsidian vault with per-agent folder permissions.",
    )
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command")
    serve = sub.add_parser("serve", help="run the Streamable HTTP MCP server")
    serve.add_argument("--host", default=os.environ.get("OBSIDIAN_MCP_HOST", "127.0.0.1"))
    serve.add_argument("--port", type=int, default=int(os.environ.get("OBSIDIAN_MCP_PORT", "8000")))
    args = parser.parse_args(argv)
    if args.command not in (None, "serve"):  # pragma: no cover - argparse rejects it
        parser.error(f"unknown command: {args.command}")

    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s"
    )
    os.umask(0o022)  # new notes 0644, folders 0755

    settings = Settings.from_env()
    acl_store = AclStore(settings.acl_file)
    vault = Vault(
        settings.vault_dir,
        settings.data_dir,
        max_read_bytes=settings.max_read_bytes,
        max_write_bytes=settings.max_write_bytes,
        enable_delete=settings.enable_delete,
    )
    signal.signal(signal.SIGHUP, lambda *_: acl_store.request_reload())

    import uvicorn

    app = create_http_app(create_server(vault), settings, acl_store)
    host = getattr(args, "host", os.environ.get("OBSIDIAN_MCP_HOST", "127.0.0.1"))
    port = getattr(args, "port", int(os.environ.get("OBSIDIAN_MCP_PORT", "8000")))
    uvicorn.run(app, host=host, port=port, log_level="info")


if __name__ == "__main__":
    main()
