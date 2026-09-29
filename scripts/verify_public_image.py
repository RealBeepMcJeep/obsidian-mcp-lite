"""Verify a GHCR image tag can be pulled without any GitHub credentials."""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.error
import urllib.request

IMAGE = "realbeepmcjeep/obsidian-mcp-lite"
TOKEN_URL = f"https://ghcr.io/token?service=ghcr.io&scope=repository:{IMAGE}:pull"
MANIFEST_ACCEPT = (
    "application/vnd.oci.image.index.v1+json, "
    "application/vnd.oci.image.manifest.v1+json, "
    "application/vnd.docker.distribution.manifest.list.v2+json, "
    "application/vnd.docker.distribution.manifest.v2+json"
)


def verify(tag: str) -> None:
    """Anonymous registry token (never a Docker/GitHub login), then HEAD the manifest."""
    if tag != "latest" and not re.fullmatch(r"sha-[0-9a-f]{7,40}", tag):
        raise ValueError("expected 'latest' or 'sha-<hex commit>'")
    with urllib.request.urlopen(TOKEN_URL, timeout=15) as response:
        token = json.load(response).get("token")
    if not token:
        raise RuntimeError("GHCR did not issue an anonymous pull token")
    request = urllib.request.Request(
        f"https://ghcr.io/v2/{IMAGE}/manifests/{tag}",
        method="HEAD",
        headers={"Authorization": f"Bearer {token}", "Accept": MANIFEST_ACCEPT},
    )
    with urllib.request.urlopen(request, timeout=15) as response:
        if response.status != 200:
            raise RuntimeError(f"anonymous manifest check returned HTTP {response.status}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tag", help="latest or sha-<commit>")
    args = parser.parse_args()
    try:
        verify(args.tag)
    except urllib.error.HTTPError as exc:
        print(
            f"Anonymous pull of ghcr.io/{IMAGE}:{args.tag} failed (HTTP {exc.code}). New GHCR "
            "packages are private: make the package public in GitHub package settings.",
            file=sys.stderr,
        )
        return 1
    print(f"Anonymous GHCR pull verified for ghcr.io/{IMAGE}:{args.tag}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
