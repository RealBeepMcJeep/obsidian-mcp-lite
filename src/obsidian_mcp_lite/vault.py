"""Vault access: path resolution, ACL enforcement and safe file operations.

Nothing in here knows about MCP. Every public method takes the calling
``Identity`` plus the current ``Acl`` and raises ``VaultError`` with an
actionable code.

Path safety, in order, for every call:

1. The requested path is normalised (``normalize_path``): absolute paths,
   ``..`` segments, NUL bytes and drive letters are rejected.
2. The ACL is checked on the requested path *before* the filesystem is
   touched, so a denied path's existence is never revealed.
3. The path is resolved with ``realpath`` (for a new file: the deepest
   existing ancestor). It must stay inside the vault, and the resolved path
   must pass the same ACL check, so a symlink can't reach a denied folder.
4. File operations then use the resolved path; the final open uses
   ``O_NOFOLLOW``. Mutations refuse a symlink as the final component.
"""

from __future__ import annotations

import errno
import fcntl
import hashlib
import json
import logging
import os
import stat as stat_mod
import tempfile
import threading
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .acl import Acl, Identity
from .errors import VaultError

log = logging.getLogger(__name__)

TEXT_EXTENSIONS = frozenset({".md", ".txt", ".canvas", ".base", ".json"})
FILE_MODE = 0o644
DIR_MODE = 0o755
DEFAULT_READ_LIMIT = 2000
MAX_LIST_ENTRIES = 5000
WIKILINK_NOTE = "Links are not rewritten: [[wikilinks]] that point at the old path now dangle."


def normalize_path(raw: Any) -> str:
    """Return a vault-relative POSIX path ("" = vault root) or raise invalid_path."""
    if not isinstance(raw, str):
        raise VaultError("invalid_path", "path must be a string")
    if "\x00" in raw:
        raise VaultError("invalid_path", "path must not contain NUL bytes")
    text = raw.strip().replace("\\", "/")
    if text in ("", ".", "/"):
        return ""
    if text.startswith(("/", "~")):
        raise VaultError(
            "invalid_path",
            f"{raw!r} is absolute; use a path relative to the vault root, e.g. 'Inbox/note.md'",
        )
    if len(text) >= 2 and text[1] == ":":
        raise VaultError(
            "invalid_path", f"{raw!r} looks like a drive path; use a vault-relative path"
        )
    parts = [p for p in text.split("/") if p not in ("", ".")]
    if any(p == ".." for p in parts):
        raise VaultError("invalid_path", f"{raw!r} contains '..'; paths must stay inside the vault")
    return "/".join(parts)


def revision_of(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _ext_ok(rel: str) -> bool:
    return os.path.splitext(rel)[1].lower() in TEXT_EXTENSIONS


@dataclass(frozen=True)
class Resolved:
    rel: str  # what the caller asked for, normalised
    real: str  # absolute realpath on disk (may not exist yet)
    real_rel: str  # realpath relative to the vault root


class Vault:
    def __init__(
        self,
        root: Path | str,
        data_dir: Path | str,
        *,
        max_read_bytes: int = 5 * 1024 * 1024,
        max_write_bytes: int = 5 * 1024 * 1024,
        enable_delete: bool = False,
    ):
        self.root = os.path.realpath(root)
        if not os.path.isdir(self.root):
            raise ValueError(f"vault root {root} is not a directory")
        self.max_read_bytes = max_read_bytes
        self.max_write_bytes = max_write_bytes
        self.enable_delete = enable_delete
        self.data_dir = Path(data_dir)
        self.lock_dir = self.data_dir / "locks"
        self.lock_dir.mkdir(parents=True, exist_ok=True)
        real_data = os.path.realpath(self.data_dir)
        if real_data == self.root or real_data.startswith(self.root + os.sep):
            raise ValueError("the data directory must not be inside the vault")
        self.audit = AuditLog(self.data_dir / "audit.jsonl")

    # ------------------------------------------------------------------ resolution

    def _inside(self, real: str) -> bool:
        return real == self.root or real.startswith(self.root + os.sep)

    def _realpath(self, rel: str) -> str:
        full = os.path.join(self.root, rel) if rel else self.root
        if os.path.lexists(full):
            return os.path.realpath(full)
        # New path: resolve the deepest existing ancestor, then re-append the rest.
        head, tail = full, []
        while not os.path.lexists(head):
            head, name = os.path.split(head)
            tail.append(name)
        return os.path.join(os.path.realpath(head), *reversed(tail))

    def resolve(self, identity: Identity, acl: Acl, raw: Any, mode: str) -> Resolved:
        """mode: 'read', 'write' or 'traverse' (list a folder)."""
        rel = normalize_path(raw)
        check = {
            "read": acl.can_read,
            "write": acl.can_write,
            "traverse": acl.can_traverse,
        }[mode]
        if not check(identity, rel):
            raise self._forbidden(identity, rel or "/", mode)
        real = self._realpath(rel)
        if not self._inside(real):
            raise VaultError(
                "path_forbidden", f"'{rel}' resolves outside the vault (symlink); refusing"
            )
        real_rel = os.path.relpath(real, self.root)
        real_rel = "" if real_rel == "." else real_rel.replace(os.sep, "/")
        if real_rel != rel and not check(identity, real_rel):
            # Say nothing about where the symlink points.
            raise self._forbidden(identity, rel, mode)
        return Resolved(rel=rel, real=real, real_rel=real_rel)

    @staticmethod
    def _forbidden(identity: Identity, rel: str, mode: str) -> VaultError:
        if mode == "write":
            scope = ", ".join(str(r) for r in identity.write) or "none"
            return VaultError(
                "path_forbidden",
                f"'{rel}' is outside your write scope (you may write under: {scope})",
            )
        return VaultError("path_forbidden", f"'{rel}' is outside your read scope")

    # ------------------------------------------------------------------ helpers

    def _read_bytes(
        self, real: str, rel: str, *, limit: int | None = None
    ) -> tuple[bytes, os.stat_result]:
        try:
            fd = os.open(real, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except FileNotFoundError:
            raise VaultError("not_found", f"'{rel}' does not exist") from None
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                raise VaultError(
                    "path_forbidden", f"'{rel}' changed into a symlink; refusing"
                ) from None
            if exc.errno == errno.EISDIR:
                raise VaultError("not_a_file", f"'{rel}' is a folder; use list_dir") from None
            raise
        try:
            st = os.fstat(fd)
            if stat_mod.S_ISDIR(st.st_mode):
                raise VaultError("not_a_file", f"'{rel}' is a folder; use list_dir")
            if not stat_mod.S_ISREG(st.st_mode):
                raise VaultError("not_a_file", f"'{rel}' is not a regular file")
            cap = self.max_read_bytes if limit is None else limit
            if st.st_size > cap:
                raise VaultError(
                    "too_large",
                    f"'{rel}' is {st.st_size} bytes; the limit is {cap} bytes",
                )
            chunks, total = [], 0
            while chunk := os.read(fd, 1 << 20):
                chunks.append(chunk)
                total += len(chunk)
                if total > cap:  # grew while we were reading
                    raise VaultError("too_large", f"'{rel}' is larger than {cap} bytes")
            return b"".join(chunks), st
        finally:
            os.close(fd)

    @staticmethod
    def _decode(data: bytes, rel: str) -> str:
        if b"\x00" in data:
            raise VaultError("not_text", f"'{rel}' looks binary; only text files can be read")
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            raise VaultError("not_text", f"'{rel}' is not valid UTF-8 text") from None

    def _check_write_target(self, r: Resolved) -> None:
        for p in {r.rel, r.real_rel}:
            if not _ext_ok(p):
                allowed = ", ".join(sorted(TEXT_EXTENSIONS))
                raise VaultError(
                    "unsupported_extension",
                    f"'{r.rel}' is not a writable text file type (allowed: {allowed})",
                )
        full = os.path.join(self.root, r.rel)
        if os.path.islink(full):
            raise VaultError("path_forbidden", f"'{r.rel}' is a symlink; refusing to modify it")

    def _check_size(self, data: bytes, rel: str) -> None:
        if len(data) > self.max_write_bytes:
            raise VaultError(
                "too_large",
                f"the result for '{rel}' would be {len(data)} bytes; the limit is "
                f"{self.max_write_bytes} bytes",
            )

    def _ensure_parent(self, real: str) -> None:
        parent = os.path.dirname(real)
        missing = []
        p = parent
        while not os.path.isdir(p):
            if os.path.lexists(p):
                raise VaultError(
                    "not_a_directory",
                    f"'{os.path.relpath(p, self.root)}' exists and is not a folder",
                )
            missing.append(p)
            p = os.path.dirname(p)
        for d in reversed(missing):
            if not self._inside(os.path.realpath(os.path.dirname(d))):
                raise VaultError("path_forbidden", "parent folder resolves outside the vault")
            try:
                os.mkdir(d, DIR_MODE)
                os.chmod(d, DIR_MODE)
            except FileExistsError:
                pass

    def _atomic_write(self, real: str, data: bytes, mode: int) -> None:
        directory = os.path.dirname(real)
        # Dot-prefixed so Obsidian, its sync client and our own listings ignore it.
        fd, tmp = tempfile.mkstemp(prefix=".obsidian-mcp-", suffix=".tmp", dir=directory)
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
                fh.flush()
                os.fchmod(fh.fileno(), mode)
                os.fsync(fh.fileno())
            os.replace(tmp, real)
        except BaseException:
            try:
                os.unlink(tmp)
            except FileNotFoundError:
                pass
            raise
        try:
            dfd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        except OSError:
            return
        try:
            os.fsync(dfd)
        except OSError:
            pass
        finally:
            os.close(dfd)

    @contextmanager
    def _locked(self, *resolved: Resolved) -> Iterator[None]:
        # Sorted, de-duplicated keys: two movers can never deadlock each other.
        keys = sorted({hashlib.sha256(r.real_rel.encode()).hexdigest() for r in resolved})
        with ExitStack() as stack:
            for key in keys:
                fh = stack.enter_context(open(self.lock_dir / f"{key}.lock", "a+b"))
                fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
            yield

    def _current(self, r: Resolved) -> tuple[bytes | None, int]:
        """(bytes, mode) of an existing file, or (None, FILE_MODE) if absent."""
        if not os.path.lexists(r.real):
            return None, FILE_MODE
        data, st = self._read_bytes(r.real, r.rel, limit=self.max_write_bytes)
        return data, stat_mod.S_IMODE(st.st_mode)

    def _replace_checked(self, r: Resolved, expected: bytes | None, data: bytes, mode: int) -> None:
        """Atomic write, after re-checking nobody (e.g. the sync client) changed the file."""
        now, _ = self._current(r)
        if now != expected:
            raise VaultError(
                "conflict",
                f"'{r.rel}' changed on disk while this edit was being made (probably a sync). "
                "Re-read it and retry.",
            )
        self._ensure_parent(r.real)
        self._atomic_write(r.real, data, mode)

    # ------------------------------------------------------------------ reads

    def read_file(
        self,
        identity: Identity,
        acl: Acl,
        path: str,
        offset: int | None = None,
        limit: int | None = None,
    ) -> dict[str, Any]:
        r = self.resolve(identity, acl, path, "read")
        data, st = self._read_bytes(r.real, r.rel)
        text = self._decode(data, r.rel)
        lines = text.split("\n")
        if lines and lines[-1] == "":
            lines.pop()
        total = len(lines)
        start = max(1, int(offset or 1))
        count = max(1, min(int(limit or DEFAULT_READ_LIMIT), 20000))
        chunk = lines[start - 1 : start - 1 + count]
        body = "\n".join(f"{start + i:>6}\t{line}" for i, line in enumerate(chunk))
        result: dict[str, Any] = {
            "path": r.rel,
            "revision": revision_of(data),
            "size": st.st_size,
            "mtime": _iso(st.st_mtime),
            "total_lines": total,
            "offset": start,
            "lines_returned": len(chunk),
            "content": body,
        }
        end = start - 1 + len(chunk)
        if end < total:
            result["truncated"] = True
            result["next_offset"] = end + 1
        return result

    def stat(self, identity: Identity, acl: Acl, path: str) -> dict[str, Any]:
        r = self.resolve(identity, acl, path, "traverse")
        full = os.path.join(self.root, r.rel) if r.rel else self.root
        if not os.path.lexists(full) or not os.path.exists(r.real):
            return {"path": r.rel or "/", "exists": False}
        st = os.stat(r.real)
        if stat_mod.S_ISDIR(st.st_mode):
            return {"path": r.rel or "/", "exists": True, "type": "dir", "mtime": _iso(st.st_mtime)}
        # Files need real read access, not just traversal.
        r = self.resolve(identity, acl, path, "read")
        out: dict[str, Any] = {
            "path": r.rel,
            "exists": True,
            "type": "file",
            "size": st.st_size,
            "mtime": _iso(st.st_mtime),
        }
        if stat_mod.S_ISREG(st.st_mode):
            h = hashlib.sha256()
            with open(r.real, "rb") as fh:
                for block in iter(lambda: fh.read(1 << 20), b""):
                    h.update(block)
            out["revision"] = h.hexdigest()
        return out

    def iter_entries(
        self, identity: Identity, acl: Acl, rel_dir: str, real_dir: str, recursive: bool
    ) -> Iterator[dict[str, Any]]:
        """Yield permitted entries below a folder. Never follows symlinked folders."""
        stack = [(rel_dir, real_dir)]
        while stack:
            cur_rel, cur_real = stack.pop()
            try:
                with os.scandir(cur_real) as it:
                    items = sorted(it, key=lambda e: e.name)
            except OSError:
                continue
            for entry in items:
                name = entry.name
                if name.startswith("."):
                    continue
                child = f"{cur_rel}/{name}" if cur_rel else name
                try:
                    is_link = entry.is_symlink()
                    if is_link:
                        target = os.path.realpath(entry.path)
                        if not self._inside(target) or not os.path.exists(target):
                            continue
                        target_rel = os.path.relpath(target, self.root).replace(os.sep, "/")
                        st = os.stat(target)
                    else:
                        target_rel = child
                        st = entry.stat(follow_symlinks=False)
                except OSError:
                    continue
                if stat_mod.S_ISDIR(st.st_mode):
                    if not (
                        acl.can_traverse(identity, child) and acl.can_traverse(identity, target_rel)
                    ):
                        continue
                    yield {"path": child, "type": "dir", "mtime": _iso(st.st_mtime)}
                    if recursive and not is_link:
                        stack.append((child, entry.path))
                elif stat_mod.S_ISREG(st.st_mode):
                    if not (acl.can_read(identity, child) and acl.can_read(identity, target_rel)):
                        continue
                    yield {
                        "path": child,
                        "type": "file",
                        "size": st.st_size,
                        "mtime": _iso(st.st_mtime),
                        "_real": target if is_link else entry.path,
                    }

    def list_dir(
        self,
        identity: Identity,
        acl: Acl,
        path: str = ".",
        recursive: bool = False,
        max_entries: int = 500,
        offset: int = 0,
    ) -> dict[str, Any]:
        r = self.resolve(identity, acl, path, "traverse")
        if not os.path.exists(r.real):
            raise VaultError("not_found", f"'{r.rel or '/'}' does not exist")
        if not os.path.isdir(r.real):
            raise VaultError("not_a_directory", f"'{r.rel}' is a file; use read_file or stat")
        limit = max(1, min(int(max_entries), MAX_LIST_ENTRIES))
        start = max(0, int(offset))
        entries = sorted(
            self.iter_entries(identity, acl, r.rel, r.real, recursive), key=lambda e: e["path"]
        )
        page = [
            {k: v for k, v in e.items() if not k.startswith("_")}
            for e in entries[start : start + limit]
        ]
        result: dict[str, Any] = {
            "path": r.rel or "/",
            "recursive": bool(recursive),
            "total": len(entries),
            "offset": start,
            "count": len(page),
            "entries": page,
        }
        if start + len(page) < len(entries):
            remaining = len(entries) - start - len(page)
            result["truncated"] = True
            result["next_offset"] = start + len(page)
            result["note"] = (
                f"TRUNCATED: {remaining} more entries. Call again with "
                f"offset={start + len(page)}, or list a narrower path."
            )
        return result

    # ------------------------------------------------------------------ writes

    def write_file(
        self,
        identity: Identity,
        acl: Acl,
        path: str,
        content: str,
        expected_revision: str | None = None,
        create_only: bool = False,
    ) -> dict[str, Any]:
        r = self.resolve(identity, acl, path, "write")
        self._check_write_target(r)
        data = content.encode("utf-8")
        self._check_size(data, r.rel)
        with self._locked(r):
            current, mode = self._current(r)
            old_rev = None
            if current is not None:
                old_rev = revision_of(current)
                if create_only:
                    raise VaultError(
                        "already_exists",
                        f"'{r.rel}' already exists; read it and pass expected_revision to "
                        "overwrite, or use edit_file",
                    )
                if not expected_revision:
                    raise VaultError(
                        "revision_required",
                        f"'{r.rel}' already exists; overwriting needs expected_revision "
                        "(from read_file or stat)",
                    )
                if expected_revision != old_rev:
                    raise VaultError(
                        "conflict",
                        f"'{r.rel}' has changed since you read it (expected revision "
                        f"{expected_revision[:12]}, current {old_rev[:12]}); nothing was "
                        "written. Re-read it and retry.",
                    )
            elif expected_revision:
                raise VaultError(
                    "conflict",
                    f"'{r.rel}' no longer exists (expected revision {expected_revision[:12]}); "
                    "nothing was written",
                )
            self._replace_checked(r, current, data, mode)
            new_rev = revision_of(data)
        self.audit.record(identity.name, "write_file", r.rel, old_rev, new_rev)
        return {"path": r.rel, "created": current is None, "revision": new_rev, "size": len(data)}

    def edit_file(
        self,
        identity: Identity,
        acl: Acl,
        path: str,
        old_string: str,
        new_string: str,
        replace_all: bool = False,
        expected_revision: str | None = None,
    ) -> dict[str, Any]:
        r = self.resolve(identity, acl, path, "write")
        self._check_write_target(r)
        if not old_string:
            raise VaultError("invalid_argument", "old_string must not be empty")
        if old_string == new_string:
            raise VaultError("invalid_argument", "old_string and new_string are identical")
        with self._locked(r):
            current, mode = self._current(r)
            if current is None:
                raise VaultError(
                    "not_found", f"'{r.rel}' does not exist; use write_file to create it"
                )
            old_rev = revision_of(current)
            if expected_revision and expected_revision != old_rev:
                raise VaultError(
                    "conflict",
                    f"'{r.rel}' has changed since you read it (expected revision "
                    f"{expected_revision[:12]}, current {old_rev[:12]}); nothing was changed. "
                    "Re-read it and retry.",
                )
            text = self._decode(current, r.rel)
            count = text.count(old_string)
            if count == 0:
                raise VaultError(
                    "no_match",
                    f"old_string was not found in '{r.rel}'; nothing was changed. Re-read the "
                    "file: whitespace, indentation and line endings must match exactly.",
                )
            if count > 1 and not replace_all:
                raise VaultError(
                    "ambiguous_match",
                    f"old_string appears {count} times in '{r.rel}'; nothing was changed. Add "
                    "surrounding context to make it unique, or pass replace_all=true.",
                )
            updated = (
                text.replace(old_string, new_string)
                if replace_all
                else text.replace(old_string, new_string, 1)
            )
            data = updated.encode("utf-8")
            self._check_size(data, r.rel)
            self._replace_checked(r, current, data, mode)
            new_rev = revision_of(data)
        self.audit.record(identity.name, "edit_file", r.rel, old_rev, new_rev)
        return {
            "path": r.rel,
            "replacements": count if replace_all else 1,
            "revision": new_rev,
            "size": len(data),
        }

    def append_file(self, identity: Identity, acl: Acl, path: str, content: str) -> dict[str, Any]:
        r = self.resolve(identity, acl, path, "write")
        self._check_write_target(r)
        if content == "":
            raise VaultError("invalid_argument", "content must not be empty")
        with self._locked(r):
            current, mode = self._current(r)
            old_rev = None
            text = ""
            if current is not None:
                old_rev = revision_of(current)
                text = self._decode(current, r.rel)
            sep = "\n" if text and not text.endswith("\n") else ""
            data = (text + sep + content).encode("utf-8")
            self._check_size(data, r.rel)
            self._replace_checked(r, current, data, mode)
            new_rev = revision_of(data)
        self.audit.record(identity.name, "append_file", r.rel, old_rev, new_rev)
        return {"path": r.rel, "created": current is None, "revision": new_rev, "size": len(data)}

    def move_file(self, identity: Identity, acl: Acl, src: str, dst: str) -> dict[str, Any]:
        rs = self.resolve(identity, acl, src, "write")
        rd = self.resolve(identity, acl, dst, "write")
        self._check_write_target(rs)
        self._check_write_target(rd)
        if rs.real == rd.real:
            raise VaultError("invalid_argument", "src and dst are the same file")
        with self._locked(rs, rd):
            if not os.path.lexists(rs.real):
                raise VaultError("not_found", f"'{rs.rel}' does not exist")
            if not os.path.isfile(rs.real):
                raise VaultError("not_a_file", f"'{rs.rel}' is not a file; only files can be moved")
            if os.path.lexists(rd.real):
                raise VaultError(
                    "already_exists", f"'{rd.rel}' already exists; move never overwrites"
                )
            data, _ = self._read_bytes(rs.real, rs.rel, limit=self.max_write_bytes)
            rev = revision_of(data)
            self._ensure_parent(rd.real)
            try:
                # link() fails if dst exists, so there is no check-then-rename race.
                os.link(rs.real, rd.real, follow_symlinks=False)
                os.unlink(rs.real)
            except FileExistsError:
                raise VaultError(
                    "already_exists", f"'{rd.rel}' already exists; move never overwrites"
                ) from None
            except OSError as exc:
                if exc.errno not in (errno.EPERM, errno.EXDEV, errno.ENOTSUP, errno.EMLINK):
                    raise
                if os.path.lexists(rd.real):
                    raise VaultError(
                        "already_exists", f"'{rd.rel}' already exists; move never overwrites"
                    ) from None
                os.rename(rs.real, rd.real)
        self.audit.record(identity.name, "move_file", rs.rel, rev, rev, dst=rd.rel)
        return {"src": rs.rel, "dst": rd.rel, "revision": rev, "note": WIKILINK_NOTE}

    def delete_file(self, identity: Identity, acl: Acl, path: str) -> dict[str, Any]:
        if not self.enable_delete:
            raise VaultError("delete_disabled", "deleting is disabled on this server")
        r = self.resolve(identity, acl, path, "write")
        self._check_write_target(r)
        with self._locked(r):
            if not os.path.lexists(r.real):
                raise VaultError("not_found", f"'{r.rel}' does not exist")
            if not os.path.isfile(r.real):
                raise VaultError("not_a_file", f"'{r.rel}' is not a file")
            data, _ = self._read_bytes(r.real, r.rel, limit=self.max_write_bytes)
            rev = revision_of(data)
            trash_rel = f".trash/{r.real_rel}"
            trash = os.path.join(self.root, ".trash", r.real_rel)
            if os.path.lexists(trash):
                base, ext = os.path.splitext(trash)
                stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
                trash = f"{base} {stamp}{ext}"
                n = 1
                while os.path.lexists(trash):
                    trash = f"{base} {stamp}-{n}{ext}"
                    n += 1
                trash_rel = os.path.relpath(trash, self.root).replace(os.sep, "/")
            os.makedirs(os.path.dirname(trash), mode=DIR_MODE, exist_ok=True)
            os.rename(r.real, trash)
        self.audit.record(identity.name, "delete_file", r.rel, rev, None, trashed_to=trash_rel)
        return {
            "path": r.rel,
            "trashed_to": trash_rel,
            "note": "Moved to the vault's .trash folder.",
        }


class AuditLog:
    """Append-only JSONL, one line per mutation, safe across threads and processes."""

    def __init__(self, path: Path):
        self.path = path
        self._lock = threading.Lock()
        # Fail at startup, not on the first write, if /data isn't writable.
        with open(self.path, "a", encoding="utf-8"):
            pass

    def record(
        self,
        identity: str,
        tool: str,
        path: str,
        old_rev: str | None,
        new_rev: str | None,
        **extra: Any,
    ) -> None:
        entry = {
            "ts": datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "identity": identity,
            "tool": tool,
            "path": path,
            "old_rev": old_rev,
            "new_rev": new_rev,
            **extra,
        }
        line = (json.dumps(entry, ensure_ascii=False) + "\n").encode("utf-8")
        try:
            with self._lock:
                fd = os.open(
                    self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_CLOEXEC, 0o640
                )
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX)
                    os.write(fd, line)
                    os.fsync(fd)
                finally:
                    os.close(fd)
        except OSError:
            # The change already happened; losing the audit line must not hide that.
            log.exception("failed to write audit entry: %s", entry)
