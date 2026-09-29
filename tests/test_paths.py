"""Traversal and symlink escapes: nothing outside the vault or the caller's scope."""

from __future__ import annotations

import os

import pytest

from obsidian_mcp_lite.errors import VaultError
from obsidian_mcp_lite.vault import normalize_path


@pytest.mark.parametrize(
    "raw",
    [
        "../outside/passwd",
        "Inbox/../../outside/passwd",
        "Inbox/../../../etc/passwd",
        "..",
        "/etc/passwd",
        "/vault/Inbox/todo.md",
        "~/notes.md",
        "C:/Windows/win.ini",
        "C:\\Windows\\win.ini",
        "..\\outside\\passwd",
        "Inbox/todo.md\x00.png",
    ],
)
def test_bad_paths_are_rejected(raw):
    with pytest.raises(VaultError) as err:
        normalize_path(raw)
    assert err.value.code == "invalid_path"


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("", ""),
        (".", ""),
        ("/", ""),
        ("Inbox/todo.md", "Inbox/todo.md"),
        ("./Inbox//todo.md", "Inbox/todo.md"),
        ("Inbox\\todo.md", "Inbox/todo.md"),
        (" Inbox/ ", "Inbox"),
    ],
)
def test_paths_normalise(raw, expected):
    assert normalize_path(raw) == expected


def test_dotdot_rejected_by_every_tool(vault, acl, claude):
    calls = [
        lambda: vault.read_file(claude, acl, "../outside/passwd"),
        lambda: vault.stat(claude, acl, "../outside/passwd"),
        lambda: vault.list_dir(claude, acl, "../outside"),
        lambda: vault.write_file(claude, acl, "Inbox/../../outside/x.md", "x"),
        lambda: vault.edit_file(claude, acl, "../outside/passwd", "root", "toor"),
        lambda: vault.append_file(claude, acl, "Inbox/../../x.md", "x"),
        lambda: vault.move_file(claude, acl, "Inbox/todo.md", "../x.md"),
    ]
    for call in calls:
        with pytest.raises(VaultError) as err:
            call()
        assert err.value.code == "invalid_path"


def test_symlink_to_etc_is_refused(layout, vault, acl, claude):
    os.symlink("/etc", layout["vault"] / "Inbox" / "etc")
    os.symlink("/etc/hostname", layout["vault"] / "Inbox" / "host.md")
    for path in ("Inbox/etc/hostname", "Inbox/host.md"):
        with pytest.raises(VaultError) as err:
            vault.read_file(claude, acl, path)
        assert err.value.code == "path_forbidden"
        assert "outside the vault" in err.value.message
    with pytest.raises(VaultError) as err:
        vault.list_dir(claude, acl, "Inbox/etc")
    assert err.value.code == "path_forbidden"
    names = {e["path"] for e in vault.list_dir(claude, acl, "Inbox")["entries"]}
    assert "Inbox/etc" not in names and "Inbox/host.md" not in names


def test_symlink_to_denied_folder_is_refused(layout, vault, acl, claude):
    v = layout["vault"]
    os.symlink("../Private", v / "Inbox" / "sneaky")
    os.symlink("../Private/secret-diary.md", v / "Inbox" / "diary.md")
    for path in ("Inbox/sneaky/secret-diary.md", "Inbox/diary.md"):
        with pytest.raises(VaultError) as err:
            vault.read_file(claude, acl, path)
        assert err.value.code == "path_forbidden"
        # The message names what was asked for, never where the link points.
        assert "Private" not in str(err.value)
    listing = vault.list_dir(claude, acl, "Inbox", recursive=True)
    assert all("sneaky" not in e["path"] and "diary" not in e["path"] for e in listing["entries"])


def test_symlinked_parent_dir_cannot_escape_on_write(layout, vault, acl, claude):
    v = layout["vault"]
    os.symlink(layout["outside"], v / "Inbox" / "out")
    with pytest.raises(VaultError) as err:
        vault.write_file(claude, acl, "Inbox/out/new.md", "pwned")
    assert err.value.code == "path_forbidden"
    with pytest.raises(VaultError):
        vault.write_file(claude, acl, "Inbox/out/deeper/new.md", "pwned")
    with pytest.raises(VaultError):
        vault.append_file(claude, acl, "Inbox/out/passwd.md", "pwned")
    assert sorted(os.listdir(layout["outside"])) == ["passwd"]


def test_symlinked_parent_into_readonly_folder_cannot_write(layout, vault, acl, claude):
    # Inbox/proj -> ../Projects: claude may read Projects but not write it.
    os.symlink("../Projects", layout["vault"] / "Inbox" / "proj")
    with pytest.raises(VaultError) as err:
        vault.write_file(claude, acl, "Inbox/proj/new.md", "x")
    assert err.value.code == "path_forbidden"
    assert not (layout["vault"] / "Projects" / "new.md").exists()


def test_writes_refuse_symlink_final_component(layout, vault, acl, claude):
    os.symlink("todo.md", layout["vault"] / "Inbox" / "alias.md")
    rev = vault.read_file(claude, acl, "Inbox/alias.md")["revision"]  # reading through is fine
    with pytest.raises(VaultError) as err:
        vault.write_file(claude, acl, "Inbox/alias.md", "x", expected_revision=rev)
    assert err.value.code == "path_forbidden"


def test_forbidden_checked_before_existence(vault, acl, claude):
    # Same answer whether or not the denied file exists.
    for path in ("Private/secret-diary.md", "Private/does-not-exist.md"):
        with pytest.raises(VaultError) as err:
            vault.read_file(claude, acl, path)
        assert err.value.code == "path_forbidden"
        assert "outside your read scope" in err.value.message
