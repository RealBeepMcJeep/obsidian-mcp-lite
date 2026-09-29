from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from obsidian_mcp_lite.acl import Acl, AclStore
from obsidian_mcp_lite.vault import Vault

TOKENS = {
    "OBSIDIAN_MCP_TOKEN_CLAUDE": "c" * 40,
    "OBSIDIAN_MCP_TOKEN_HERMES": "h" * 40,
    "OBSIDIAN_MCP_TOKEN_READER": "r" * 40,
}

ACL_YAML = textwrap.dedent(
    """
    always_deny: [".obsidian/", ".trash/", ".git/"]
    identities:
      claude:
        token_env: OBSIDIAN_MCP_TOKEN_CLAUDE
        read:  ["/"]
        write: ["AI/Claude/", "Inbox/"]
        deny:  ["Private/"]
      hermes:
        token_env: OBSIDIAN_MCP_TOKEN_HERMES
        read:  ["/"]
        write: ["AI/Hermes/", "Daily/"]
        deny:  ["Private/", "Finance/"]
      reader:
        token_env: OBSIDIAN_MCP_TOKEN_READER
        read:  ["Projects/"]
    """
)


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


@pytest.fixture
def layout(tmp_path: Path) -> dict[str, Path]:
    vault = tmp_path / "vault"
    data = tmp_path / "data"
    config = tmp_path / "config"
    outside = tmp_path / "outside"
    for d in (vault, data, config, outside):
        d.mkdir()
    _write(vault / "Welcome.md", "# Welcome\nhello vault\n")
    _write(vault / "Inbox/todo.md", "- [ ] buy milk\n- [ ] call mum\n")
    _write(vault / "AI/Claude/notes.md", "alpha\nbeta\nalpha\n")
    _write(vault / "AI/Hermes/log.md", "hermes log\n")
    _write(vault / "Private/secret-diary.md", "the secret word is swordfish\n")
    _write(vault / "Finance/budget.md", "budget swordfish\n")
    _write(vault / "Projects/plan.md", "project swordfish plan\n")
    _write(vault / "Daily/2026-09-29.md", "daily\n")
    _write(vault / ".obsidian/app.json", '{"swordfish": true}\n')
    _write(vault / ".trash/old.md", "old swordfish\n")
    _write(vault / "Notes/.hidden.md", "hidden swordfish\n")
    (vault / "Attachments").mkdir()
    (vault / "Attachments/image.png").write_bytes(b"\x89PNG\r\n\x1a\n\x00\x00binary")
    _write(outside / "passwd", "root:x:0:0 swordfish\n")
    (config / "acl.yaml").write_text(ACL_YAML, encoding="utf-8")
    return {"vault": vault, "data": data, "config": config, "outside": outside}


@pytest.fixture
def acl(layout) -> Acl:
    return Acl.load(layout["config"] / "acl.yaml", TOKENS)


@pytest.fixture
def acl_store(layout) -> AclStore:
    return AclStore(layout["config"] / "acl.yaml", TOKENS)


@pytest.fixture
def vault(layout) -> Vault:
    return Vault(
        layout["vault"], layout["data"], max_read_bytes=64 * 1024, max_write_bytes=64 * 1024
    )


@pytest.fixture
def claude(acl):
    return acl.identities["claude"]


@pytest.fixture
def hermes(acl):
    return acl.identities["hermes"]


@pytest.fixture
def reader(acl):
    return acl.identities["reader"]
