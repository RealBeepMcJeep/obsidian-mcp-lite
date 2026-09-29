# syntax=docker/dockerfile:1

# --- Builder: dependencies exactly at uv.lock's frozen resolution -----------
FROM python:3.12-slim AS builder
COPY --from=ghcr.io/astral-sh/uv:0.11.6 /uv /usr/local/bin/uv
ENV UV_PROJECT_ENVIRONMENT=/opt/venv \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never
WORKDIR /app
COPY pyproject.toml uv.lock README.md LICENSE ./
COPY src ./src
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-editable

# --- Runtime ----------------------------------------------------------------
FROM python:3.12-slim AS runtime

# ripgrep powers the search tool (the server falls back to Python without it).
# Default user matches the TrueNAS apps user (568:568); compose sets it too.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ripgrep \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 568 apps \
    && useradd --system --uid 568 --gid apps --no-create-home --home-dir /nonexistent apps \
    && install -d --owner=568 --group=568 --mode=0755 /vault /config /data

ENV PATH="/opt/venv/bin:${PATH}" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    OBSIDIAN_MCP_HOST=0.0.0.0 \
    OBSIDIAN_MCP_PORT=8000 \
    OBSIDIAN_MCP_VAULT_DIR=/vault \
    OBSIDIAN_MCP_ACL_FILE=/config/acl.yaml \
    OBSIDIAN_MCP_DATA_DIR=/data

COPY --from=builder /opt/venv /opt/venv

ARG BUILD_COMMIT=unknown
ARG BUILD_TIME=unknown
ARG BUILD_TAG=unknown
LABEL org.opencontainers.image.source="https://github.com/RealBeepMcJeep/obsidian-mcp-lite" \
      org.opencontainers.image.description="MCP server for an Obsidian vault with per-agent folder permissions" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.revision="${BUILD_COMMIT}" \
      org.opencontainers.image.created="${BUILD_TIME}" \
      org.opencontainers.image.version="${BUILD_TAG}"
ENV OBSIDIAN_MCP_BUILD_COMMIT=${BUILD_COMMIT} \
    OBSIDIAN_MCP_BUILD_TIME=${BUILD_TIME} \
    OBSIDIAN_MCP_BUILD_TAG=${BUILD_TAG}

USER 568:568
WORKDIR /data
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=4).read()"]

CMD ["obsidian-mcp-lite", "serve", "--host", "0.0.0.0", "--port", "8000"]
