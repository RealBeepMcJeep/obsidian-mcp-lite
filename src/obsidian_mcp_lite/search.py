"""Filename and content search, filtered through the ACL.

Content search uses ripgrep when it is on PATH (it is in the Docker image) and
falls back to a pure-Python scan otherwise. Either way every hit is checked
with ``Acl.can_read`` before it is returned, so a denied note's name or text
never appears in results. Hidden files and folders are never searched.

User regexes never run on Python's ``re``: a catastrophic pattern would hold
the GIL and freeze every other request. Filename and fallback content
matching use the ``regex`` module with a deadline and ``concurrent=True``
(releases the GIL); ripgrep's engine is linear-time and runs under the same
deadline.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import threading
import time
from typing import Any

import regex as regex_lib

from .acl import Acl, Identity
from .errors import VaultError
from .vault import TEXT_EXTENSIONS, Vault

MAX_QUERY_LENGTH = 500
MAX_RESULTS_CAP = 500
PER_FILE_HITS = 5
SNIPPET_CHARS = 240
TIMEOUT_SECONDS = 30.0


def _snippet(line: str) -> str:
    line = line.rstrip("\r\n")
    if len(line) > SNIPPET_CHARS:
        return line[:SNIPPET_CHARS] + " …"
    return line


def search(
    vault: Vault,
    identity: Identity,
    acl: Acl,
    query: str,
    path: str | None = None,
    regex: bool = False,
    max_results: int = 50,
    *,
    use_ripgrep: bool | None = None,
) -> dict[str, Any]:
    if not isinstance(query, str) or not query.strip():
        raise VaultError("invalid_argument", "query must be a non-empty string")
    if len(query) > MAX_QUERY_LENGTH:
        raise VaultError("invalid_argument", f"query is longer than {MAX_QUERY_LENGTH} characters")
    limit = max(1, min(int(max_results), MAX_RESULTS_CAP))
    try:
        pattern = regex_lib.compile(
            query if regex else regex_lib.escape(query), regex_lib.IGNORECASE
        )
    except regex_lib.error as exc:
        raise VaultError("invalid_argument", f"invalid regex: {exc}") from None
    deadline = time.monotonic() + TIMEOUT_SECONDS

    r = vault.resolve(identity, acl, path or "", "traverse")
    if not os.path.isdir(r.real):
        raise VaultError("not_a_directory", f"'{r.rel}' is not a folder; search needs a folder")

    # Filename matches first: cheap, and often what the agent actually wants.
    files = list(vault.iter_entries(identity, acl, r.rel, r.real, recursive=True))
    filename_matches = []
    timed_out = False
    for entry in files:
        try:
            if _match(pattern, entry["path"], deadline):
                filename_matches.append({"path": entry["path"], "type": entry["type"]})
        except TimeoutError:
            timed_out = True
            break
    truncated = len(filename_matches) > limit
    filename_matches = filename_matches[:limit]
    budget = limit - len(filename_matches)

    rg = shutil.which("rg") if use_ripgrep is not False else None
    if use_ripgrep and rg is None:
        raise RuntimeError("ripgrep requested but not installed")
    content_matches: list[dict[str, Any]] = []
    if budget > 0 and not timed_out:
        if rg:
            content_matches, more, timed_out = _search_rg(
                rg, vault, identity, acl, r.real, query, regex, budget, deadline
            )
            engine = "ripgrep"
        else:
            content_matches, more, timed_out = _search_python(
                vault, files, pattern, budget, deadline
            )
            engine = "python"
        truncated = truncated or more
    else:
        engine = "ripgrep" if rg else "python"

    result: dict[str, Any] = {
        "query": query,
        "path": r.rel or "/",
        "regex": bool(regex),
        "engine": engine,
        "filename_matches": filename_matches,
        "content_matches": content_matches,
    }
    if timed_out:
        result["truncated"] = True
        result["note"] = (
            f"TIMED OUT after {TIMEOUT_SECONDS:.0f}s; results are partial. Use a simpler "
            "query (avoid nested repetition like '(a+)+') or a narrower path."
        )
    elif truncated:
        result["truncated"] = True
        result["note"] = f"TRUNCATED at max_results={limit}. Narrow the query or path to see more."
    return result


def _match(pattern: regex_lib.Pattern[str], text: str, deadline: float) -> bool:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError
    return pattern.search(text, timeout=remaining, concurrent=True) is not None


def _search_python(
    vault: Vault,
    files: list[dict[str, Any]],
    pattern: regex_lib.Pattern[str],
    budget: int,
    deadline: float,
) -> tuple[list[dict[str, Any]], bool, bool]:
    hits: list[dict[str, Any]] = []
    for entry in files:
        if entry["type"] != "file":
            continue
        if os.path.splitext(entry["path"])[1].lower() not in TEXT_EXTENSIONS:
            continue
        if entry["size"] > vault.max_read_bytes:
            continue
        try:
            fd = os.open(entry["_real"], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(fd, "rb") as fh:
                data = fh.read(vault.max_read_bytes + 1)
            text = data.decode("utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        per_file = 0
        for number, line in enumerate(text.split("\n"), start=1):
            try:
                found = _match(pattern, line, deadline)
            except TimeoutError:
                return hits, True, True
            if found:
                if len(hits) >= budget:
                    return hits, True, False
                hits.append({"path": entry["path"], "line": number, "text": _snippet(line)})
                per_file += 1
                if per_file >= PER_FILE_HITS:
                    break
    return hits, False, False


def _search_rg(
    rg: str,
    vault: Vault,
    identity: Identity,
    acl: Acl,
    real_dir: str,
    query: str,
    regex: bool,
    budget: int,
    deadline: float,
) -> tuple[list[dict[str, Any]], bool, bool]:
    cmd = [
        rg,
        "--json",
        "--no-config",
        "--no-ignore",  # a .gitignore in the vault must not hide notes
        "--no-messages",
        "--ignore-case",
        "--sort",
        "path",  # deterministic results when max_results truncates
        "--max-count",
        str(PER_FILE_HITS),
        "--max-filesize",
        str(vault.max_read_bytes),
        "--max-columns",
        str(SNIPPET_CHARS * 4),
        "--max-columns-preview",
    ]
    for ext in sorted(TEXT_EXTENSIONS):
        cmd += ["--glob", f"*{ext}"]
    cmd += ["--fixed-strings"] if not regex else []
    cmd += ["--regexp", query, "--", real_dir]

    hits: list[dict[str, Any]] = []
    more = False
    proc = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL
    )
    # Kill rg at the deadline even if it is scanning silently and never yields a line.
    watchdog = threading.Timer(max(0.0, deadline - time.monotonic()), proc.kill)
    watchdog.start()
    try:
        assert proc.stdout is not None
        for raw in proc.stdout:
            try:
                msg = json.loads(raw)
            except ValueError:
                continue
            if msg.get("type") != "match":
                continue
            data = msg["data"]
            abs_path = data.get("path", {}).get("text")
            text = data.get("lines", {}).get("text")
            if abs_path is None or text is None:
                continue  # non-UTF-8 path or line
            real = os.path.realpath(abs_path)
            if not (real == vault.root or real.startswith(vault.root + os.sep)):
                continue
            rel = os.path.relpath(abs_path, vault.root).replace(os.sep, "/")
            real_rel = os.path.relpath(real, vault.root).replace(os.sep, "/")
            if not (acl.can_read(identity, rel) and acl.can_read(identity, real_rel)):
                continue
            if len(hits) >= budget:
                more = True
                break
            hits.append({"path": rel, "line": data.get("line_number"), "text": _snippet(text)})
    finally:
        watchdog.cancel()
        if proc.poll() is None:
            proc.kill()
        proc.wait()
    timed_out = not more and time.monotonic() >= deadline
    return hits, more or timed_out, timed_out
