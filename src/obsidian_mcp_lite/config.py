"""Environment-driven configuration.

Bearer tokens are NOT read here: ``acl.yaml`` names the env var that holds
each identity's token, and ``acl.py`` reads it. Nothing logs or returns them.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

TRUTHY = {"1", "true", "yes", "on"}
FALSY = {"", "0", "false", "no", "off"}

# Host allowlist for the HTTP transport (DNS-rebinding protection). Entries
# match exactly, with "<host>:*" meaning any port, so the container name
# appears both bare and with ":*".
DEFAULT_ALLOWED_HOSTS = (
    "obsidian-mcp-lite,obsidian-mcp-lite:*,localhost,localhost:*,127.0.0.1,127.0.0.1:*"
)


def _bool(env: Mapping[str, str], key: str, default: bool = False) -> bool:
    raw = (env.get(key) or "").strip().lower()
    if not raw:
        return default
    if raw in TRUTHY:
        return True
    if raw in FALSY:
        return False
    raise ValueError(f"{key} must be one of: 1/true/yes/on or 0/false/no/off")


def _int(env: Mapping[str, str], key: str, default: int, minimum: int = 1) -> int:
    raw = (env.get(key) or "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"{key} must be an integer") from exc
    if value < minimum:
        raise ValueError(f"{key} must be >= {minimum}")
    return value


@dataclass(frozen=True)
class Settings:
    vault_dir: Path
    acl_file: Path
    data_dir: Path
    allowed_hosts: tuple[str, ...]
    enable_delete: bool
    max_read_bytes: int
    max_write_bytes: int

    @staticmethod
    def from_env(env: Mapping[str, str] | None = None) -> Settings:
        e = os.environ if env is None else env
        hosts_raw = (e.get("OBSIDIAN_MCP_ALLOWED_HOSTS") or DEFAULT_ALLOWED_HOSTS).strip()
        return Settings(
            vault_dir=Path(e.get("OBSIDIAN_MCP_VAULT_DIR") or "/vault"),
            acl_file=Path(e.get("OBSIDIAN_MCP_ACL_FILE") or "/config/acl.yaml"),
            data_dir=Path(e.get("OBSIDIAN_MCP_DATA_DIR") or "/data"),
            allowed_hosts=tuple(h.strip() for h in hosts_raw.split(",") if h.strip()),
            enable_delete=_bool(e, "OBSIDIAN_MCP_ENABLE_DELETE"),
            max_read_bytes=_int(e, "OBSIDIAN_MCP_MAX_READ_BYTES", 5 * 1024 * 1024),
            max_write_bytes=_int(e, "OBSIDIAN_MCP_MAX_WRITE_BYTES", 5 * 1024 * 1024),
        )
