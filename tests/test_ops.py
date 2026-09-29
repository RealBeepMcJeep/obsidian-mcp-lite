from __future__ import annotations

import json
import multiprocessing
import os
import stat
import threading

import pytest

from obsidian_mcp_lite.errors import VaultError
from obsidian_mcp_lite.vault import Vault, revision_of

# ---------------------------------------------------------------------- read / stat


def test_read_file_numbers_lines_and_returns_revision(layout, vault, acl, claude):
    out = vault.read_file(claude, acl, "Inbox/todo.md")
    raw = (layout["vault"] / "Inbox/todo.md").read_bytes()
    assert out["revision"] == revision_of(raw)
    assert out["total_lines"] == 2
    assert out["content"] == "     1\t- [ ] buy milk\n     2\t- [ ] call mum"
    assert "truncated" not in out


def test_read_file_offset_and_limit(layout, vault, acl, claude):
    (layout["vault"] / "Inbox/long.md").write_text("".join(f"line {i}\n" for i in range(1, 11)))
    out = vault.read_file(claude, acl, "Inbox/long.md", offset=4, limit=3)
    assert out["content"].splitlines() == ["     4\tline 4", "     5\tline 5", "     6\tline 6"]
    assert out["truncated"] is True and out["next_offset"] == 7
    assert out["total_lines"] == 10


def test_read_refuses_binary_large_and_folders(layout, vault, acl, claude):
    with pytest.raises(VaultError) as err:
        vault.read_file(claude, acl, "Attachments/image.png")
    assert err.value.code == "not_text"
    (layout["vault"] / "Inbox/big.md").write_text("x" * (vault.max_read_bytes + 1))
    with pytest.raises(VaultError) as err:
        vault.read_file(claude, acl, "Inbox/big.md")
    assert err.value.code == "too_large"
    with pytest.raises(VaultError) as err:
        vault.read_file(claude, acl, "Inbox")
    assert err.value.code == "not_a_file"
    with pytest.raises(VaultError) as err:
        vault.read_file(claude, acl, "Inbox/nope.md")
    assert err.value.code == "not_found"


def test_stat(vault, acl, claude, reader):
    s = vault.stat(claude, acl, "Inbox/todo.md")
    assert s["exists"] and s["type"] == "file" and len(s["revision"]) == 64
    assert vault.stat(claude, acl, "Inbox/new.md") == {"path": "Inbox/new.md", "exists": False}
    assert vault.stat(claude, acl, "Inbox")["type"] == "dir"
    assert vault.stat(reader, acl, "/")["type"] == "dir"
    for who, path in ((claude, "Private/secret-diary.md"), (reader, "Welcome.md")):
        with pytest.raises(VaultError) as err:
            vault.stat(who, acl, path)
        assert err.value.code == "path_forbidden"


# ---------------------------------------------------------------------- write_file


def test_write_creates_file_and_folders_with_modes(layout, vault, acl, claude):
    out = vault.write_file(claude, acl, "AI/Claude/sub/dir/new.md", "hi\n")
    target = layout["vault"] / "AI/Claude/sub/dir/new.md"
    assert target.read_text() == "hi\n"
    assert out["created"] is True and out["revision"] == revision_of(b"hi\n")
    assert stat.S_IMODE(target.stat().st_mode) == 0o644
    assert stat.S_IMODE((layout["vault"] / "AI/Claude/sub").stat().st_mode) == 0o755
    assert stat.S_IMODE((layout["vault"] / "AI/Claude/sub/dir").stat().st_mode) == 0o755


def test_overwrite_requires_matching_revision(layout, vault, acl, claude):
    target = layout["vault"] / "AI/Claude/notes.md"
    before = target.read_bytes()
    with pytest.raises(VaultError) as err:
        vault.write_file(claude, acl, "AI/Claude/notes.md", "new")
    assert err.value.code == "revision_required"

    stale = revision_of(b"something older")
    with pytest.raises(VaultError) as err:
        vault.write_file(claude, acl, "AI/Claude/notes.md", "new", expected_revision=stale)
    assert err.value.code == "conflict"
    assert target.read_bytes() == before  # unchanged

    rev = vault.read_file(claude, acl, "AI/Claude/notes.md")["revision"]
    out = vault.write_file(claude, acl, "AI/Claude/notes.md", "new", expected_revision=rev)
    assert out["created"] is False and target.read_text() == "new"


def test_stale_revision_after_concurrent_change(layout, vault, acl, claude):
    rev = vault.read_file(claude, acl, "Inbox/todo.md")["revision"]
    (layout["vault"] / "Inbox/todo.md").write_text("edited on the phone\n")  # e.g. sync
    with pytest.raises(VaultError) as err:
        vault.write_file(claude, acl, "Inbox/todo.md", "agent version", expected_revision=rev)
    assert err.value.code == "conflict"
    with pytest.raises(VaultError) as err:
        vault.edit_file(claude, acl, "Inbox/todo.md", "phone", "laptop", expected_revision=rev)
    assert err.value.code == "conflict"
    assert (layout["vault"] / "Inbox/todo.md").read_text() == "edited on the phone\n"


def test_write_preserves_existing_mode(layout, vault, acl, claude):
    target = layout["vault"] / "Inbox/todo.md"
    os.chmod(target, 0o600)
    rev = revision_of(target.read_bytes())
    vault.write_file(claude, acl, "Inbox/todo.md", "x", expected_revision=rev)
    assert stat.S_IMODE(target.stat().st_mode) == 0o600


def test_create_only(vault, acl, claude):
    vault.write_file(claude, acl, "Inbox/once.md", "1", create_only=True)
    with pytest.raises(VaultError) as err:
        vault.write_file(claude, acl, "Inbox/once.md", "2", create_only=True)
    assert err.value.code == "already_exists"


def test_write_scope_and_extension(vault, acl, claude, reader):
    with pytest.raises(VaultError) as err:
        vault.write_file(claude, acl, "Welcome2.md", "x")
    assert err.value.code == "path_forbidden"
    assert "AI/Claude/, Inbox/" in err.value.message
    with pytest.raises(VaultError) as err:
        vault.write_file(reader, acl, "Projects/new.md", "x")
    assert err.value.code == "path_forbidden"
    for bad in ("Inbox/script.sh", "Inbox/image.png", "Inbox/noext", "Inbox/x.MD.exe"):
        with pytest.raises(VaultError) as err:
            vault.write_file(claude, acl, bad, "x")
        assert err.value.code == "unsupported_extension"
    for ok in ("Inbox/a.txt", "Inbox/b.canvas", "Inbox/c.base", "Inbox/d.json", "Inbox/E.MD"):
        vault.write_file(claude, acl, ok, "{}")


def test_write_size_cap(vault, acl, claude):
    with pytest.raises(VaultError) as err:
        vault.write_file(claude, acl, "Inbox/huge.md", "x" * (vault.max_write_bytes + 1))
    assert err.value.code == "too_large"


def test_atomic_write_leaves_no_temp_files(layout, vault, acl, claude):
    for i in range(5):
        vault.append_file(claude, acl, "Inbox/log.md", f"{i}\n")
    leftovers = [n for n in os.listdir(layout["vault"] / "Inbox") if n.startswith(".obsidian-mcp-")]
    assert leftovers == []


def test_failed_write_leaves_original(layout, vault, acl, claude, monkeypatch):
    target = layout["vault"] / "Inbox/todo.md"
    before = target.read_bytes()

    def boom(*_a, **_k):
        raise OSError("disk full")

    monkeypatch.setattr(os, "replace", boom)
    with pytest.raises(OSError):
        vault.write_file(claude, acl, "Inbox/todo.md", "x", expected_revision=revision_of(before))
    assert target.read_bytes() == before
    assert not [n for n in os.listdir(target.parent) if n.startswith(".obsidian-mcp-")]


# ---------------------------------------------------------------------- edit_file


def test_edit_missing_old_string(layout, vault, acl, claude):
    before = (layout["vault"] / "Inbox/todo.md").read_text()
    with pytest.raises(VaultError) as err:
        vault.edit_file(claude, acl, "Inbox/todo.md", "buy bread", "buy eggs")
    assert err.value.code == "no_match"
    assert (layout["vault"] / "Inbox/todo.md").read_text() == before


def test_edit_duplicate_old_string(layout, vault, acl, claude):
    with pytest.raises(VaultError) as err:
        vault.edit_file(claude, acl, "AI/Claude/notes.md", "alpha", "gamma")
    assert err.value.code == "ambiguous_match"
    assert "2 times" in err.value.message
    assert (layout["vault"] / "AI/Claude/notes.md").read_text() == "alpha\nbeta\nalpha\n"
    out = vault.edit_file(claude, acl, "AI/Claude/notes.md", "alpha", "gamma", replace_all=True)
    assert out["replacements"] == 2
    assert (layout["vault"] / "AI/Claude/notes.md").read_text() == "gamma\nbeta\ngamma\n"


def test_edit_unique(layout, vault, acl, claude):
    rev = vault.read_file(claude, acl, "Inbox/todo.md")["revision"]
    out = vault.edit_file(
        claude, acl, "Inbox/todo.md", "- [ ] buy milk", "- [x] buy milk", expected_revision=rev
    )
    assert out["replacements"] == 1
    assert (layout["vault"] / "Inbox/todo.md").read_text() == "- [x] buy milk\n- [ ] call mum\n"


def test_edit_argument_checks(vault, acl, claude):
    for old, new, code in (("", "x", "invalid_argument"), ("a", "a", "invalid_argument")):
        with pytest.raises(VaultError) as err:
            vault.edit_file(claude, acl, "Inbox/todo.md", old, new)
        assert err.value.code == code
    with pytest.raises(VaultError) as err:
        vault.edit_file(claude, acl, "Inbox/missing.md", "a", "b")
    assert err.value.code == "not_found"


# ---------------------------------------------------------------------- append_file


def test_append_creates_and_separates_lines(layout, vault, acl, hermes):
    out = vault.append_file(hermes, acl, "Daily/2026-09-30.md", "first")
    assert out["created"] is True
    vault.append_file(hermes, acl, "Daily/2026-09-30.md", "second\n")
    assert (layout["vault"] / "Daily/2026-09-30.md").read_text() == "first\nsecond\n"


def test_concurrent_appends_lose_no_lines_threads(layout, vault, acl, claude):
    n_threads, per_thread = 8, 25

    def worker(t: int) -> None:
        for i in range(per_thread):
            vault.append_file(claude, acl, "Inbox/log.md", f"t{t}-{i}\n")

    threads = [threading.Thread(target=worker, args=(t,)) for t in range(n_threads)]
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    lines = (layout["vault"] / "Inbox/log.md").read_text().splitlines()
    assert sorted(lines) == sorted(f"t{t}-{i}" for t in range(n_threads) for i in range(per_thread))


def _proc_append(
    vault_dir: str, data_dir: str, acl_file: str, tokens: dict, t: int, n: int
) -> None:
    from obsidian_mcp_lite.acl import Acl

    acl = Acl.load(__import__("pathlib").Path(acl_file), tokens)
    v = Vault(vault_dir, data_dir)
    for i in range(n):
        v.append_file(acl.identities["claude"], acl, "Inbox/plog.md", f"p{t}-{i}\n")


def test_concurrent_appends_lose_no_lines_processes(layout):
    from .conftest import TOKENS

    ctx = multiprocessing.get_context("spawn")
    args = (str(layout["vault"]), str(layout["data"]), str(layout["config"] / "acl.yaml"), TOKENS)
    procs = [ctx.Process(target=_proc_append, args=(*args, t, 20)) for t in range(4)]
    for p in procs:
        p.start()
    for p in procs:
        p.join(60)
        assert p.exitcode == 0
    lines = (layout["vault"] / "Inbox/plog.md").read_text().splitlines()
    assert sorted(lines) == sorted(f"p{t}-{i}" for t in range(4) for i in range(20))


# ---------------------------------------------------------------------- move / delete


def test_move_needs_write_on_both_and_never_overwrites(layout, vault, acl, claude):
    v = layout["vault"]
    out = vault.move_file(claude, acl, "Inbox/todo.md", "AI/Claude/archive/todo.md")
    assert not (v / "Inbox/todo.md").exists()
    assert (v / "AI/Claude/archive/todo.md").read_text().startswith("- [ ] buy milk")
    assert "wikilinks" in out["note"]

    with pytest.raises(VaultError) as err:
        vault.move_file(claude, acl, "AI/Claude/archive/todo.md", "AI/Claude/notes.md")
    assert err.value.code == "already_exists"
    assert (v / "AI/Claude/notes.md").read_text() == "alpha\nbeta\nalpha\n"

    for src, dst in (
        ("AI/Claude/notes.md", "Projects/notes.md"),  # dst read-only
        ("Projects/plan.md", "Inbox/plan.md"),  # src read-only
        ("AI/Claude/notes.md", "Private/notes.md"),  # dst denied
    ):
        with pytest.raises(VaultError) as err:
            vault.move_file(claude, acl, src, dst)
        assert err.value.code == "path_forbidden"
    assert (v / "Projects/plan.md").exists()


def test_delete_disabled_by_default(vault, acl, claude):
    with pytest.raises(VaultError) as err:
        vault.delete_file(claude, acl, "Inbox/todo.md")
    assert err.value.code == "delete_disabled"


def test_delete_moves_to_trash(layout, acl, claude):
    v = Vault(layout["vault"], layout["data"], enable_delete=True)
    out = v.delete_file(claude, acl, "Inbox/todo.md")
    assert out["trashed_to"] == ".trash/Inbox/todo.md"
    assert (layout["vault"] / ".trash/Inbox/todo.md").exists()
    assert not (layout["vault"] / "Inbox/todo.md").exists()
    (layout["vault"] / "Inbox/todo.md").write_text("again\n")
    out2 = v.delete_file(claude, acl, "Inbox/todo.md")
    assert out2["trashed_to"] != out["trashed_to"]
    assert (layout["vault"] / out2["trashed_to"]).read_text() == "again\n"
    with pytest.raises(VaultError) as err:
        v.delete_file(claude, acl, "Projects/plan.md")
    assert err.value.code == "path_forbidden"


# ---------------------------------------------------------------------- audit


def test_every_mutation_is_audited(layout, acl, claude):
    v = Vault(layout["vault"], layout["data"], enable_delete=True)
    w = v.write_file(claude, acl, "Inbox/a.md", "1\n")
    e = v.edit_file(claude, acl, "Inbox/a.md", "1", "2")
    a = v.append_file(claude, acl, "Inbox/a.md", "3\n")
    v.move_file(claude, acl, "Inbox/a.md", "Inbox/b.md")
    v.delete_file(claude, acl, "Inbox/b.md")
    with pytest.raises(VaultError):
        v.write_file(claude, acl, "Private/x.md", "no")  # refused: not audited
    lines = [json.loads(x) for x in (layout["data"] / "audit.jsonl").read_text().splitlines()]
    assert [x["tool"] for x in lines] == [
        "write_file",
        "edit_file",
        "append_file",
        "move_file",
        "delete_file",
    ]
    assert all(x["identity"] == "claude" and x["ts"].endswith("Z") for x in lines)
    assert lines[0]["old_rev"] is None and lines[0]["new_rev"] == w["revision"]
    assert lines[1]["old_rev"] == w["revision"] and lines[1]["new_rev"] == e["revision"]
    assert lines[2]["new_rev"] == a["revision"]
    assert lines[3]["path"] == "Inbox/a.md" and lines[3]["dst"] == "Inbox/b.md"
    assert lines[4]["new_rev"] is None and lines[4]["trashed_to"] == ".trash/Inbox/b.md"
    assert not any("Private" in json.dumps(x) for x in lines)


def test_data_dir_inside_vault_is_rejected(layout):
    with pytest.raises(ValueError, match="must not be inside the vault"):
        Vault(layout["vault"], layout["vault"] / "state")
