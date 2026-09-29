"""One error type for everything a caller can get wrong.

Messages start with a stable code (``path_forbidden: ...``) so an LLM can act
on them. They may echo the path the caller asked for, but never reveal a path
the caller did not name.
"""

from __future__ import annotations

from mcp.server.mcpserver.exceptions import ToolError


class VaultError(ToolError):
    def __init__(self, code: str, message: str):
        self.code = code
        self.message = message
        super().__init__(f"{code}: {message}")
