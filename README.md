# obsidian-mcp-lite

A small [MCP](https://modelcontextprotocol.io) server that gives several AI agents access to one
Obsidian vault, with **per-agent folder permissions enforced by the server**. Each agent gets its
own bearer token; the token decides what it can see and change.

- Streamable HTTP at `/mcp` (stateless, JSON responses); `/healthz` for health checks.
- Nine tools: `list_dir`, `read_file`, `search`, `stat`, and the write tools `write_file`,
  `edit_file`, `append_file`, `move_file`, plus `delete_file` if enabled (off by default).
- Folders an agent can't read are invisible: listings and search results never show them.
- Built for a vault that the Obsidian sync client and the owner edit at the same time:
  revision checks, atomic writes, per-file locks, and an audit log.

## How it works

```
agent ──► MCPHub ──(Bearer <agent token>)──► obsidian-mcp-lite ──► /vault
                                               │  Host allowlist → 403
                                               │  token → identity → 401
                                               │  ACL (acl.yaml) per request
                                               └► /data/audit.jsonl, /data/locks/
```

Each agent is a separate MCPHub upstream pointing at `http://obsidian-mcp-lite:8000/mcp` with its
own `Authorization: Bearer …` header.

## Tools

| Tool | What it does |
|---|---|
| `list_dir(path=".", recursive=false, max_entries=500, offset=0)` | Name, type, size and mtime per entry. Returns `truncated` + `next_offset` when there's more. |
| `read_file(path, offset?, limit?)` | UTF-8 text only. Line-numbered content, `total_lines`, `revision` (sha256 of the whole file). Refuses binary and oversized files. |
| `search(query, path?, regex=false, max_results=50)` | Case-insensitive search of file names and note contents, with line snippets. Uses ripgrep when installed (it is in the image). |
| `stat(path)` | `exists`, type, size, mtime, revision. |
| `write_file(path, content, expected_revision?, create_only=false)` | Creates a file, or replaces one. Replacing needs `expected_revision`; a mismatch returns `conflict` and changes nothing. |
| `edit_file(path, old_string, new_string, replace_all=false, expected_revision?)` | Exact string replacement. Fails with `no_match` or `ambiguous_match` (unless `replace_all`). |
| `append_file(path, content)` | Appends text, creating the file if needed. Adds a newline first if the file doesn't end with one. |
| `move_file(src, dst)` | Needs write access to both. Never overwrites. **Does not rewrite `[[wikilinks]]`.** |
| `delete_file(path)` | Only when `OBSIDIAN_MCP_ENABLE_DELETE=1`. Moves the note to the vault's `.trash/`, the same place Obsidian's own trash uses. |

`tools/list` shows the write tools only to identities that have at least one `write` rule, and
calling a hidden tool fails with `Unknown tool`.

Errors are prefixed with a stable code an LLM can act on, for example
`path_forbidden: 'Private/x.md' is outside your read scope`, `conflict: …`, `no_match: …`,
`unsupported_extension: …`, `too_large: …`, `revision_required: …`.

## Permissions (`acl.yaml`)

```yaml
# /config/acl.yaml: the deployed ACL (decided by admin, 2026-09-29)
always_deny: [".obsidian/", ".trash/", ".git/", "Private/"]   # every identity, incl. future ones
identities:
  claude-rc:
    token_env: OBSIDIAN_MCP_TOKEN_CLAUDE_RC
    read:  ["/"]                  # "/" = whole vault
    write: ["LLM_Data/"]          # trailing slash = folder + everything under it
    deny:  ["Private/"]
  hermes:
    token_env: OBSIDIAN_MCP_TOKEN_HERMES
    read:  ["/"]
    write: ["LLM_Data/"]
    deny:  ["Private/"]
```

See [`deploy/acl.example.yaml`](deploy/acl.example.yaml) for a commented version.

- **Vault-wide denials go in `always_deny`.** It applies to every identity, including any you
  add later (say, a new DeepSeek worker), so nobody has to remember a per-identity `deny` for
  `Private/`.
- **Allow rules** (`read`, `write`): `"/"` means the whole vault. `"Folder/"` means that folder
  and everything under it. `"Note.md"` (no trailing slash) means exactly that path. `"LLM_Data/"`
  does *not* match `LLM_Data_old/`.
- **Deny rules** (`always_deny`, `deny`) always cover the path *and everything under it*, with
  or without a trailing slash.
- **Precedence**: `always_deny` > `deny` > `write` > `read`. Write implies read.
- Any path segment starting with `.` is always denied. `.obsidian/`, `.trash/` and `.git/` are
  denied even if the file leaves them out.
- **Deny rules match on a folded "skeleton"**: case, accents, full-width letters and the Turkish
  dotted/dotless i are all folded away. `Private/` also blocks `PRIVATE/`, `Prıvate/` and
  `Ｐｒｉｖａｔｅ/`, which matters on a case-insensitive dataset. Allow rules are case-sensitive.
- An agent with read access only below some folder can still list the folders that lead there,
  and sees nothing else in them.
- **Tokens never go in this file.** `token_env` names the environment variable that holds the
  token. Tokens must be at least 32 characters and unique. An identity whose variable is empty is
  disabled and logged at startup. When you add an identity, add its variable to the compose
  `environment:` block too.
- **Reload**: file changes are picked up within about a second, or immediately after `SIGHUP`
  (`docker kill -s HUP obsidian-mcp-lite`). If the new file is invalid, the error is logged and
  the last good ACL stays in force.

## Safety model

- **Paths**: everything is relative to `/vault`. The server rejects absolute paths, `..`
  segments, NUL bytes and drive letters. The ACL is checked on the path the agent asked for
  *before* touching the disk, so a denied file's existence is never revealed.
- **Symlinks**: every path is resolved with `realpath` (for a new file, via its parent). The
  result must stay inside the vault *and* pass the same ACL check, so a symlink can't reach
  `/etc` or a denied folder. Listings never follow symlinked folders. Write tools refuse a
  symlink as the file itself.
- **Atomic writes**: the new content goes to a hidden temp file in the same folder, is fsynced,
  and then renamed over the target. Existing file modes are kept. New files are `0644` and new
  folders `0755`.
- **Concurrency**: `edit_file`, `append_file` and the other write tools hold a per-file lock
  for the whole read-modify-write. Locks live in `/data/locks/` as a fixed set of 256 bucket
  files, so they can't pile up. They also re-check the file just before the
  rename, so a sync client that writes in the meantime causes a `conflict`, not a lost edit.
- **Search**: user regexes never run on Python's `re`. Filenames and the fallback content
  search use the `regex` module, which has a timeout and releases the interpreter lock, and
  ripgrep's engine runs in linear time. Every search has a 30-second budget, so a pathological
  pattern returns partial results marked `TIMED OUT` instead of freezing the server.
- **Limits**: only `.md .txt .canvas .base .json` files can be written. Reads and writes are
  capped at 5 MiB by default.
- **Audit**: every successful change appends one JSON line to `/data/audit.jsonl`
  (`ts, identity, tool, path, old_rev, new_rev`, plus `dst`/`trashed_to` for moves and deletes).
- **HTTP**: the Host header is checked against `OBSIDIAN_MCP_ALLOWED_HOSTS` (403 otherwise).
  `/mcp` requires `Authorization: Bearer <token>` (401 otherwise), compared in constant time.
  `/healthz` needs no token.

App state lives in `/data`, which must not be inside the vault; the server refuses to start if
it is.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `OBSIDIAN_MCP_TOKEN_*` | — | One per identity; names come from `token_env` in `acl.yaml` (deployed: `OBSIDIAN_MCP_TOKEN_CLAUDE_RC`, `OBSIDIAN_MCP_TOKEN_HERMES`). 32+ characters. |
| `OBSIDIAN_MCP_ALLOWED_HOSTS` | `obsidian-mcp-lite,obsidian-mcp-lite:*,localhost,localhost:*,127.0.0.1,127.0.0.1:*` | Comma-separated Host header allowlist; `name:*` = any port. Keep `127.0.0.1:*` for the image's HEALTHCHECK. |
| `OBSIDIAN_MCP_ENABLE_DELETE` | unset (off) | `1` registers `delete_file` (moves notes to `.trash/`). Off in the deployment. |
| `OBSIDIAN_MCP_VAULT_DIR` | `/vault` | Vault root. |
| `OBSIDIAN_MCP_ACL_FILE` | `/config/acl.yaml` | ACL file. |
| `OBSIDIAN_MCP_DATA_DIR` | `/data` | Audit log and lock files. Must not be inside the vault. |
| `OBSIDIAN_MCP_MAX_READ_BYTES` | `5242880` | Largest file `read_file`/`search` will read. |
| `OBSIDIAN_MCP_MAX_WRITE_BYTES` | `5242880` | Largest resulting file a write tool will produce. |
| `OBSIDIAN_MCP_HOST` / `OBSIDIAN_MCP_PORT` | `0.0.0.0` / `8000` in the image | Listen address. |

## Deploy (TrueNAS, `mcp-servers` stack)

- Image: `ghcr.io/realbeepmcjeep/obsidian-mcp-lite:latest`, or `:sha-<commit>` to pin a version.
- Service block: [`deploy/compose.yaml`](deploy/compose.yaml). It uses the `mcp_backend` network
  only, publishes no ports, and runs as `user: 568:568` with a read-only root filesystem and
  `no-new-privileges`. Mounts:
  `/mnt/tank3/apps/obsidian/vault:/vault`, `…/obsidian-mcp/config:/config:ro` and
  `…/obsidian-mcp/data:/data`.
- Stack `.env`: [`deploy/.env.example`](deploy/.env.example).
- Smoke test from the TrueNAS shell: `sh deploy/smoke-truenas.sh`
  ([source](deploy/smoke-truenas.sh)). It uses `curlimages/curl` inside `mcp_backend` and reads
  the tokens from the running container. For each identity it runs `initialize` and
  `tools/list`, checks that `read_file Private/README.md` is refused and that `list_dir /` and
  `search` don't reveal `Private`, then makes one allowed write into `LLM_Data/`. It prints
  PASS/FAIL per check and exits non-zero on any failure.

## Development

```sh
uv sync
uv run pytest                 # 90+ tests: traversal, symlinks, ACL, revisions, locking, HTTP auth
uv run ruff check src tests scripts
# Run locally against a scratch vault:
OBSIDIAN_MCP_VAULT_DIR=/tmp/vault OBSIDIAN_MCP_DATA_DIR=/tmp/data \
OBSIDIAN_MCP_ACL_FILE=deploy/ci-acl.yaml SMOKE_WRITER_TOKEN=$(openssl rand -hex 32) \
SMOKE_READER_TOKEN=$(openssl rand -hex 32) uv run obsidian-mcp-lite serve --port 18000
```

CI (`.github/workflows/ci.yml`) runs lint and tests, then builds the image and smoke-tests it
over HTTP as a non-default uid. `publish.yml` pushes to GHCR only after CI passes on `main`, then
checks that the image can be pulled anonymously.

## Limitations

- `move_file` doesn't update links in other notes.
- `append_file` isn't revision-checked by design. If the sync client writes the same file at
  the same moment, the append returns `conflict` and can simply be retried.
- A symlink swapped in by something *other* than this server, between the check and the open,
  is not fully covered: the final open uses `O_NOFOLLOW`, but parent folders aren't re-checked.
  No tool can create symlinks.
- Content search covers text files only (the extensions above), not PDFs or images.

## License

MIT
