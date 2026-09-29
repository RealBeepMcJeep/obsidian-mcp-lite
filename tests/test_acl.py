from __future__ import annotations

import os
import textwrap

import pytest

from obsidian_mcp_lite.acl import Acl, AclError, AclStore

from .conftest import ACL_YAML, TOKENS


def test_precedence_always_deny_over_deny_over_write_over_read(acl, claude, hermes):
    # read "/" but deny Private/
    assert acl.can_read(claude, "Welcome.md")
    assert not acl.can_read(claude, "Private/secret-diary.md")
    assert not acl.can_read(claude, "Private")
    # write implies read; write limited to its folders
    assert acl.can_write(claude, "AI/Claude/notes.md")
    assert acl.can_write(claude, "Inbox/new/deep.md")
    assert not acl.can_write(claude, "AI/Hermes/log.md")
    assert not acl.can_write(claude, "Welcome.md")
    # always_deny beats a read of "/"
    assert not acl.can_read(claude, ".obsidian/app.json")
    assert not acl.can_read(claude, ".trash/old.md")
    # per-identity deny
    assert acl.can_read(claude, "Finance/budget.md")
    assert not acl.can_read(hermes, "Finance/budget.md")


def test_deny_beats_write():
    acl = Acl.from_mapping(
        {
            "identities": {
                "a": {"token_env": "T", "write": ["Notes/"], "deny": ["Notes/Locked/"]},
            }
        },
        {"T": "t" * 40},
    )
    a = acl.identities["a"]
    assert acl.can_write(a, "Notes/x.md")
    assert acl.can_read(a, "Notes/x.md")  # write implies read
    assert not acl.can_write(a, "Notes/Locked/x.md")
    assert not acl.can_read(a, "Notes/Locked/x.md")


def test_always_deny_beats_explicit_write():
    acl = Acl.from_mapping(
        {"always_deny": ["Vault-Admin/"], "identities": {"a": {"token_env": "T", "write": ["/"]}}},
        {"T": "t" * 40},
    )
    a = acl.identities["a"]
    assert not acl.can_write(a, "Vault-Admin/x.md")
    assert not acl.can_write(a, ".obsidian/plugins.json")  # built-in even if omitted


def test_dotfiles_denied_at_any_depth(acl, claude):
    assert not acl.can_read(claude, "Notes/.hidden.md")
    assert not acl.can_read(claude, "Inbox/.git/config")
    assert not acl.can_write(claude, "Inbox/.env.md")


def test_folder_rule_does_not_match_name_prefix(acl, claude):
    # "Private/" must not deny "PrivateNotes", and "Inbox/" must not grant "Inbox2".
    assert acl.can_read(claude, "PrivateNotes/x.md")
    assert not acl.can_write(claude, "Inbox2/x.md")


def test_exact_file_rule():
    acl = Acl.from_mapping(
        {"identities": {"a": {"token_env": "T", "read": ["Home.md"], "write": ["Log.md"]}}},
        {"T": "t" * 40},
    )
    a = acl.identities["a"]
    assert acl.can_read(a, "Home.md")
    assert not acl.can_read(a, "Home.md/x")
    assert not acl.can_read(a, "Home.mdx")
    assert acl.can_write(a, "Log.md")
    assert acl.can_traverse(a, "")  # the root leads to Home.md
    assert not acl.can_traverse(a, "Other")


def test_deny_is_case_and_unicode_insensitive(acl, claude):
    assert not acl.can_read(claude, "private/secret-diary.md")
    assert not acl.can_read(claude, "PRIVATE/x.md")
    acl2 = Acl.from_mapping(
        {"identities": {"a": {"token_env": "T", "read": ["/"], "deny": ["Café/"]}}},
        {"T": "t" * 40},
    )
    a = acl2.identities["a"]
    assert not acl2.can_read(a, "Café/menu.md")  # decomposed é
    assert not acl2.can_read(a, "CAFÉ/menu.md")


def test_traverse_only_reveals_route_to_readable_rules(acl, reader):
    assert acl.can_traverse(reader, "")
    assert acl.can_traverse(reader, "Projects")
    assert not acl.can_traverse(reader, "Inbox")
    assert not acl.can_read(reader, "Welcome.md")
    assert not acl.can_traverse(reader, "Private")


def test_identify_by_token(acl):
    assert acl.identify("c" * 40).name == "claude"
    assert acl.identify("h" * 40).name == "hermes"
    assert acl.identify("x" * 40) is None
    assert acl.identify("") is None


def test_token_rules():
    spec = {"identities": {"a": {"token_env": "TA"}, "b": {"token_env": "TB"}}}
    with pytest.raises(AclError, match="at least 32"):
        Acl.from_mapping(spec, {"TA": "short", "TB": "b" * 40})
    with pytest.raises(AclError, match="share the same token"):
        Acl.from_mapping(spec, {"TA": "x" * 40, "TB": "x" * 40})
    with pytest.raises(AclError, match="nobody could connect"):
        Acl.from_mapping(spec, {})
    only_b = Acl.from_mapping(spec, {"TB": "b" * 40})
    assert set(only_b.identities) == {"b"}  # identity without a token is disabled


@pytest.mark.parametrize(
    "bad",
    [
        None,
        [],
        {"identities": {}},
        {"identities": {"a": {"token_env": "T", "read": "Notes/"}}},
        {"identities": {"a": {"token_env": "T", "read": ["../x/"]}}},
        {"identities": {"a": {"token_env": "T", "raed": ["/"]}}},
        {"identities": {"a": {"read": ["/"]}}},
        {"identitys": {}},
    ],
)
def test_malformed_acl_is_rejected(bad):
    with pytest.raises(AclError):
        Acl.from_mapping(bad, {"T": "t" * 40})


def test_tokens_are_not_in_repr(acl):
    assert "c" * 40 not in repr(acl)


def test_store_reloads_on_change_and_keeps_old_acl_on_error(layout):
    path = layout["config"] / "acl.yaml"
    store = AclStore(path, TOKENS)
    assert store.get(now=0).can_write(store.get(now=0).identities["claude"], "Inbox/x.md")

    path.write_text(
        textwrap.dedent(
            """
            identities:
              claude:
                token_env: OBSIDIAN_MCP_TOKEN_CLAUDE
                read: ["/"]
            """
        )
    )
    os.utime(path, ns=(1, 1))  # force a different mtime even on coarse clocks
    acl = store.get(now=10)
    assert set(acl.identities) == {"claude"}
    assert not acl.can_write(acl.identities["claude"], "Inbox/x.md")

    path.write_text("identities: [broken")
    os.utime(path, ns=(2, 2))
    kept = store.get(now=20)
    assert kept is acl

    path.write_text(ACL_YAML)
    assert store.get(now=20.5) is acl  # inside the 1 s check interval: not re-read yet
    store.request_reload()  # SIGHUP path: reload now, even inside the check interval
    assert set(store.get(now=20.6).identities) == {"claude", "hermes", "reader"}


def test_shipped_example_acls_load():
    root = __import__("pathlib").Path(__file__).resolve().parent.parent / "deploy"
    example = Acl.load(
        root / "acl.example.yaml",
        {"OBSIDIAN_MCP_TOKEN_CLAUDE_RC": "c" * 40, "OBSIDIAN_MCP_TOKEN_HERMES": "h" * 40},
    )
    assert set(example.identities) == {"claude-rc", "hermes"}
    for ident in example.identities.values():
        assert example.can_write(ident, "LLM_Data/notes/x.md")
        assert example.can_read(ident, "Notion/page.md") and example.can_read(ident, "Home.md")
        assert not example.can_write(ident, "prompts/p.md")
        assert not example.can_read(ident, "Private/README.md")
        assert not example.can_traverse(ident, "Private")
    # Private/ is in always_deny, so an identity added later is covered without its own deny.
    later = Acl.from_mapping(
        {
            "always_deny": [r.path + "/" for r in example.always_deny],
            "identities": {"deepseek": {"token_env": "T", "read": ["/"], "write": ["/"]}},
        },
        {"T": "d" * 40},
    )
    ds = later.identities["deepseek"]
    assert not later.can_read(ds, "Private/README.md") and not later.can_write(ds, "private/x.md")
    ci = Acl.load(
        root / "ci-acl.yaml", {"SMOKE_WRITER_TOKEN": "w" * 40, "SMOKE_READER_TOKEN": "r" * 40}
    )
    assert not ci.identities["reader"].can_write_anything


def test_deny_without_trailing_slash_covers_subtree():
    acl = Acl.from_mapping(
        {"identities": {"a": {"token_env": "T", "read": ["/"], "deny": ["Secrets", "Diary.md"]}}},
        {"T": "t" * 40},
    )
    a = acl.identities["a"]
    assert not acl.can_read(a, "Secrets")
    assert not acl.can_read(a, "Secrets/key.md")
    assert not acl.can_read(a, "secrets/deep/key.md")
    assert not acl.can_read(a, "Diary.md")
    assert acl.can_read(a, "SecretsOfTheSea.md")


@pytest.mark.parametrize(
    "spelling",
    ["Prıvate", "PRİVATE", "prİvate", "Prívate", "Ｐｒｉｖａｔｅ", "PRIVATE"],
)
def test_deny_resists_lookalike_spellings(acl, claude, spelling):
    # On a case-insensitive dataset these may all open the real Private/ folder.
    assert not acl.can_read(claude, f"{spelling}/secret-diary.md")
