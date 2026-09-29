"""Listings and search results must never reveal denied paths or their names."""

from __future__ import annotations

import json
import os
import shutil

import pytest

from obsidian_mcp_lite.errors import VaultError
from obsidian_mcp_lite.search import search

ENGINES = [False] + ([True] if shutil.which("rg") else [])


def _paths(listing):
    return {e["path"] for e in listing["entries"]}


def test_list_root_hides_denied_and_hidden(vault, acl, claude, hermes):
    top = _paths(vault.list_dir(claude, acl, "."))
    assert {"Welcome.md", "Inbox", "AI", "Projects", "Finance", "Daily", "Notes"} <= top
    assert "Private" not in top
    assert not any(p.startswith(".") for p in top)
    assert "Finance" not in _paths(vault.list_dir(hermes, acl, "/"))


def test_recursive_list_filters_everything(vault, acl, claude):
    everything = _paths(vault.list_dir(claude, acl, "", recursive=True, max_entries=5000))
    assert "Inbox/todo.md" in everything and "Attachments/image.png" in everything
    assert not any("Private" in p or "secret" in p for p in everything)
    assert not any("/." in p or p.startswith(".") for p in everything)


def test_traverse_only_identity_sees_only_its_route(vault, acl, reader):
    assert _paths(vault.list_dir(reader, acl, "/")) == {"Projects"}
    assert _paths(vault.list_dir(reader, acl, "/", recursive=True)) == {
        "Projects",
        "Projects/plan.md",
    }
    with pytest.raises(VaultError) as err:
        vault.list_dir(reader, acl, "Inbox")
    assert err.value.code == "path_forbidden"


def test_list_denied_folder_is_forbidden(vault, acl, claude):
    with pytest.raises(VaultError) as err:
        vault.list_dir(claude, acl, "Private")
    assert err.value.code == "path_forbidden"
    with pytest.raises(VaultError):
        vault.list_dir(claude, acl, ".obsidian")


def test_list_truncates_with_marker(layout, vault, acl, claude):
    for i in range(12):
        (layout["vault"] / "Inbox" / f"n{i:02}.md").write_text("x")
    first = vault.list_dir(claude, acl, "Inbox", max_entries=5)
    assert first["truncated"] is True and first["count"] == 5 and first["next_offset"] == 5
    assert "TRUNCATED" in first["note"]
    rest = vault.list_dir(claude, acl, "Inbox", max_entries=500, offset=first["next_offset"])
    assert "truncated" not in rest
    assert _paths(first) | _paths(rest) == _paths(vault.list_dir(claude, acl, "Inbox"))


def test_list_errors(vault, acl, claude):
    with pytest.raises(VaultError) as err:
        vault.list_dir(claude, acl, "Inbox/todo.md")
    assert err.value.code == "not_a_directory"
    with pytest.raises(VaultError) as err:
        vault.list_dir(claude, acl, "Nope")
    assert err.value.code == "not_found"


@pytest.mark.parametrize("use_rg", ENGINES)
def test_search_never_returns_denied_hits(layout, vault, acl, claude, hermes, reader, use_rg):
    # "swordfish" is in Private/, Finance/, Projects/, .obsidian/, .trash/, a dotfile and outside.
    os.symlink(layout["outside"], layout["vault"] / "Inbox" / "out")
    os.symlink("../Private", layout["vault"] / "Inbox" / "priv")

    def hits(who):
        res = search(vault, who, acl, "swordfish", use_ripgrep=use_rg)
        blob = json.dumps(res)
        return {h["path"] for h in res["content_matches"]}, blob

    got, blob = hits(claude)
    assert got == {"Finance/budget.md", "Projects/plan.md"}
    got, blob = hits(hermes)
    assert got == {"Projects/plan.md"}
    assert "Finance" not in blob and "Private" not in blob and "diary" not in blob
    got, _ = hits(reader)
    assert got == {"Projects/plan.md"}


@pytest.mark.parametrize("use_rg", ENGINES)
def test_search_filenames_and_scope(vault, acl, claude, use_rg):
    res = search(vault, claude, acl, "secret", use_ripgrep=use_rg)
    assert res["filename_matches"] == [] and res["content_matches"] == []
    res = search(vault, claude, acl, "todo", use_ripgrep=use_rg)
    assert {"path": "Inbox/todo.md", "type": "file"} in res["filename_matches"]
    res = search(vault, claude, acl, "ALPHA", path="AI", use_ripgrep=use_rg)
    assert [(h["path"], h["line"]) for h in res["content_matches"]] == [
        ("AI/Claude/notes.md", 1),
        ("AI/Claude/notes.md", 3),
    ]
    assert res["engine"] == ("ripgrep" if use_rg else "python")


@pytest.mark.parametrize("use_rg", ENGINES)
def test_search_regex_and_truncation(layout, vault, acl, claude, use_rg):
    for i in range(10):
        (layout["vault"] / "Inbox" / f"r{i}.md").write_text(f"item-{i} marker\n")
    res = search(
        vault, claude, acl, r"item-\d marker", regex=True, max_results=3, use_ripgrep=use_rg
    )
    assert len(res["content_matches"]) == 3 and res["truncated"] is True
    literal = search(vault, claude, acl, r"item-\d", use_ripgrep=use_rg)
    assert literal["content_matches"] == []


def test_search_rejects_bad_input_and_denied_scope(vault, acl, claude):
    for q in ("", "   ", "x" * 501):
        with pytest.raises(VaultError):
            search(vault, claude, acl, q)
    with pytest.raises(VaultError) as err:
        search(vault, claude, acl, "(", regex=True)
    assert err.value.code == "invalid_argument"
    with pytest.raises(VaultError) as err:
        search(vault, claude, acl, "swordfish", path="Private")
    assert err.value.code == "path_forbidden"
