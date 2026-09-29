# AGENTS.md: obsidian-mcp-lite

Project rules for AI agents working in this repo. Org-wide coordination rules (Gitea
accounts, labels, issue workflow) live in `ai-goes-fast/agents` → `AGENTS.md`; this file wins
for project specifics.

## Merging: exception until v1.0.0

- **Before v1.0.0**, the assigned agent **may self-merge to `main`**, but only when CI is green
  on the change (`CI` workflow: lint, pytest, image smoke). Admin decided this on 2026-09-29
  (ai-goes-fast/agents#2).
- **From v1.0.0 on**, the org rules apply: open a PR, name a reviewer, and never merge your own
  PR.
- Never force-push `main`. Never commit secrets: tokens only ever come from env vars that
  `acl.yaml` names.

## Build and test

```sh
uv sync
uv run pytest
uv run ruff check src tests scripts
```

Install `ripgrep` to also run the search tests against the ripgrep engine; without it they run
against the Python fallback only.

## Layout

- `src/obsidian_mcp_lite/acl.py`: rule parsing, precedence and reload. `vault.py`: path
  resolution and every file operation (no MCP imports). `search.py`: ripgrep and Python search.
  `server.py`: MCP tools, per-identity `tools/list`, and the Host/bearer guard middleware.
- `tests/`: every safety requirement has a test. When you change `vault.py`, `acl.py` or the
  guard, add a test that fails without your change.
- `deploy/`: the compose block, example ACL, `.env` example and TrueNAS smoke script.
  `ci-acl.yaml` is used by CI only.

## Invariants: don't break these

- Check the ACL on the requested path *before* touching the filesystem, then check it again on
  the realpath.
- Listings and search results must never contain a path the caller can't read.
- Every mutation is atomic (temp file + fsync + rename in the same folder), locked, and audited.
- `/data` is never inside the vault.
