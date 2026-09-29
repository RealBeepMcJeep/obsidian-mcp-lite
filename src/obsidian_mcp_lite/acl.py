"""Per-identity folder permissions, loaded from ``acl.yaml``.

Rule syntax (paths are relative to the vault root):

* ``"/"`` matches the whole vault.
* ``"AI/Claude/"`` (trailing slash) matches that folder and everything under it.
* ``"Inbox.md"`` (no trailing slash) matches exactly that one path.

Deny rules (``always_deny``, ``deny``) always cover the path *and everything
under it*, with or without the trailing slash: ``deny: ["Secrets"]`` must not
leave ``Secrets/key.md`` readable.

Precedence: ``always_deny`` > ``deny`` > ``write`` > ``read``; write implies
read. Any path segment starting with ``.`` is always denied.

Allow rules match case-sensitively (after NFC). Deny rules match on a
"skeleton" (see ``_skeleton``): case-folded, accents and compatibility forms
stripped, Turkish dotted/dotless i folded to ``i``. That over-matches on
purpose, so a case-insensitive dataset (common on TrueNAS SMB shares) or a
look-alike spelling can't be used to slip past a deny rule.
"""

from __future__ import annotations

import hmac
import logging
import os
import threading
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

log = logging.getLogger(__name__)

MIN_TOKEN_LENGTH = 32


class AclError(ValueError):
    """The ACL file is missing, malformed, or unsafe to load."""


def _nfc(text: str) -> str:
    return unicodedata.normalize("NFC", text)


def _skeleton(text: str) -> str:
    """Aggressive fold for deny matching: 'PRİVATE', 'Prıvate', 'Pri\u0301vate' -> 'private'."""
    t = unicodedata.normalize("NFKD", text.replace("\u0131", "i").casefold())
    t = "".join(c for c in t if not unicodedata.combining(c))
    return unicodedata.normalize("NFKC", t).casefold()


@dataclass(frozen=True)
class Rule:
    """One normalised rule. ``path == ""`` with ``folder`` set is the vault root."""

    path: str
    folder: bool

    @staticmethod
    def parse(raw: Any, *, deny: bool) -> Rule:
        if not isinstance(raw, str) or not raw.strip():
            raise AclError(f"rule must be a non-empty string, got {raw!r}")
        text = _nfc(raw.strip().replace("\\", "/"))
        folder = text.endswith("/")
        parts = [p for p in text.split("/") if p not in ("", ".")]
        if any(p == ".." for p in parts):
            raise AclError(f"rule {raw!r} must not contain '..'")
        path = "/".join(parts)
        if deny:
            # Deny rules always cover the subtree and match on the skeleton.
            return Rule(path=_skeleton(path), folder=True)
        # "/" (and "") is the root, which is always a folder rule.
        return Rule(path=path, folder=folder or path == "")

    def matches(self, path: str) -> bool:
        if self.folder:
            return self.path == "" or path == self.path or path.startswith(self.path + "/")
        return path == self.path

    def is_below(self, path: str) -> bool:
        """True if this rule names something strictly inside folder ``path``."""
        return path == "" or self.path.startswith(path + "/")

    def __str__(self) -> str:
        if self.path == "":
            return "/"
        return self.path + ("/" if self.folder else "")


@dataclass(frozen=True)
class Identity:
    name: str
    token: str = field(repr=False)
    read: tuple[Rule, ...]
    write: tuple[Rule, ...]
    deny: tuple[Rule, ...]

    @property
    def can_write_anything(self) -> bool:
        return bool(self.write)


@dataclass(frozen=True)
class Acl:
    always_deny: tuple[Rule, ...]
    identities: Mapping[str, Identity]

    # ------------------------------------------------------------------ checks

    def denied(self, identity: Identity, path: str) -> bool:
        """Whether ``path`` (normalised, vault-relative) is off limits entirely."""
        if any(seg.startswith(".") for seg in path.split("/") if seg):
            return True
        folded = _skeleton(path)
        return any(r.matches(folded) for r in self.always_deny) or any(
            r.matches(folded) for r in identity.deny
        )

    def can_read(self, identity: Identity, path: str) -> bool:
        if self.denied(identity, path):
            return False
        p = _nfc(path)
        return any(r.matches(p) for r in identity.read) or any(r.matches(p) for r in identity.write)

    def can_write(self, identity: Identity, path: str) -> bool:
        if self.denied(identity, path):
            return False
        p = _nfc(path)
        return any(r.matches(p) for r in identity.write)

    def can_traverse(self, identity: Identity, path: str) -> bool:
        """A folder may be listed if readable, or if it leads to a readable rule.

        With ``read: ["Projects/"]`` only, the root must still be listable so
        the agent can find ``Projects`` - but it will only see ``Projects``.
        """
        if self.can_read(identity, path):
            return True
        if self.denied(identity, path):
            return False
        p = _nfc(path)
        return any(r.is_below(p) for r in (*identity.read, *identity.write))

    def identify(self, token: str) -> Identity | None:
        """Constant-time lookup of the identity that owns ``token``."""
        supplied = token.encode("utf-8")
        found: Identity | None = None
        for ident in self.identities.values():
            if hmac.compare_digest(supplied, ident.token.encode("utf-8")):
                found = ident
        return found

    # ------------------------------------------------------------------ loading

    @staticmethod
    def from_mapping(data: Any, env: Mapping[str, str]) -> Acl:
        if not isinstance(data, dict):
            raise AclError("acl.yaml must be a mapping with 'identities'")
        unknown = set(data) - {"always_deny", "identities"}
        if unknown:
            raise AclError(f"unknown top-level keys: {sorted(unknown)}")
        always_deny = tuple(
            Rule.parse(r, deny=True) for r in _rule_list(data.get("always_deny"), "always_deny")
        )
        # The built-in denials hold even if the file forgets them.
        for builtin in (".obsidian/", ".trash/", ".git/"):
            rule = Rule.parse(builtin, deny=True)
            if rule not in always_deny:
                always_deny += (rule,)

        raw_ids = data.get("identities")
        if not isinstance(raw_ids, dict) or not raw_ids:
            raise AclError("'identities' must be a non-empty mapping")

        identities: dict[str, Identity] = {}
        seen_tokens: dict[str, str] = {}
        for name, spec in raw_ids.items():
            if not isinstance(name, str) or not name:
                raise AclError(f"identity name must be a non-empty string, got {name!r}")
            if not isinstance(spec, dict):
                raise AclError(f"identity {name!r} must be a mapping")
            unknown = set(spec) - {"token_env", "read", "write", "deny"}
            if unknown:
                raise AclError(f"identity {name!r}: unknown keys {sorted(unknown)}")
            token_env = spec.get("token_env")
            if not isinstance(token_env, str) or not token_env:
                raise AclError(f"identity {name!r}: token_env is required")
            token = (env.get(token_env) or "").strip()
            if not token:
                # Lets admin list an agent (e.g. "maybe Pi") before issuing a token.
                log.warning("identity %r disabled: %s is not set", name, token_env)
                continue
            if len(token) < MIN_TOKEN_LENGTH:
                raise AclError(
                    f"identity {name!r}: {token_env} must be at least {MIN_TOKEN_LENGTH} characters"
                )
            if token in seen_tokens:
                raise AclError(
                    f"identities {seen_tokens[token]!r} and {name!r} share the same token"
                )
            seen_tokens[token] = name
            identities[name] = Identity(
                name=name,
                token=token,
                read=tuple(
                    Rule.parse(r, deny=False) for r in _rule_list(spec.get("read"), f"{name}.read")
                ),
                write=tuple(
                    Rule.parse(r, deny=False)
                    for r in _rule_list(spec.get("write"), f"{name}.write")
                ),
                deny=tuple(
                    Rule.parse(r, deny=True) for r in _rule_list(spec.get("deny"), f"{name}.deny")
                ),
            )
        if not identities:
            raise AclError("no identity has its token env var set; nobody could connect")
        return Acl(always_deny=always_deny, identities=identities)

    @staticmethod
    def load(path: Path, env: Mapping[str, str] | None = None) -> Acl:
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise AclError(f"cannot read ACL file {path}: {exc.strerror}") from exc
        try:
            data = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise AclError(f"ACL file {path} is not valid YAML: {exc}") from exc
        return Acl.from_mapping(data, os.environ if env is None else env)


def _rule_list(value: Any, where: str) -> list[Any]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise AclError(f"{where} must be a list of rules")
    return value


class AclStore:
    """Holds the live ACL and reloads it when the file changes or on SIGHUP.

    A reload that fails keeps the previous ACL and logs why, so a typo in the
    file never locks every agent out (or, worse, opens things up).
    """

    CHECK_INTERVAL = 1.0

    def __init__(self, path: Path, env: Mapping[str, str] | None = None):
        self.path = path
        self._env = env
        self._lock = threading.Lock()
        self._acl = Acl.load(path, env)
        self._stamp = self._file_stamp()
        self._next_check = 0.0
        self._force = False

    def _file_stamp(self) -> tuple[int, int, int] | None:
        try:
            st = self.path.stat()
        except OSError:
            return None
        return (st.st_mtime_ns, st.st_size, st.st_ino)

    def request_reload(self) -> None:
        """Called from the SIGHUP handler; the next request reloads."""
        self._force = True

    def get(self, now: float | None = None) -> Acl:
        import time

        now = time.monotonic() if now is None else now
        if not self._force and now < self._next_check:
            return self._acl
        with self._lock:
            self._next_check = now + self.CHECK_INTERVAL
            stamp = self._file_stamp()
            if self._force or (stamp is not None and stamp != self._stamp):
                self._force = False
                try:
                    self._acl = Acl.load(self.path, self._env)
                    self._stamp = stamp
                    log.info(
                        "ACL reloaded from %s (%d identities)", self.path, len(self._acl.identities)
                    )
                except AclError as exc:
                    self._stamp = stamp  # don't retry the same broken file every second
                    log.error("ACL reload failed, keeping the previous ACL: %s", exc)
            return self._acl
