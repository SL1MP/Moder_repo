#!/usr/bin/env python3
"""Shared helpers for Git repository moderation.

The scripts are intentionally configured only through environment variables.
No deployment URL or token is embedded in the repository.
"""

from __future__ import annotations

import json
import os
import sys
from urllib.parse import urlparse

import gitlab


def required(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise RuntimeError(f"{name} is not configured")
    return value


def as_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "y"}


def normalize_source(value: str) -> tuple[str, str]:
    raw = value.strip().rstrip("/")
    if not raw:
        raise RuntimeError("Git repository URL is empty")
    parsed = urlparse(raw)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise RuntimeError("Git repository must be a full http(s) URL")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise RuntimeError("Git repository URL must not contain credentials, query or fragment")
    path = parsed.path.strip("/")
    if path.endswith(".git"):
        path = path[:-4]
    if len(path.split("/")) < 2:
        raise RuntimeError("Git repository URL must contain owner and repository")
    canonical = f"{parsed.scheme}://{parsed.netloc}/{path}"
    target_path = f"{parsed.hostname.lower()}/{path}".strip("/")
    return canonical, target_path


def client(token_env: str = "GIT_MIRROR_API_TOKEN") -> gitlab.Gitlab:
    return gitlab.Gitlab(
        required("GIT_MIRROR_GITLAB_URL").rstrip("/"),
        private_token=required(token_env),
        timeout=int(os.getenv("GIT_MIRROR_HTTP_TIMEOUT_SECONDS", "60")),
    )


def emit(payload: dict) -> None:
    print("MODERATION_RESULT=" + json.dumps(payload, ensure_ascii=False, separators=(",", ":")))


def fail(exc: Exception) -> None:
    print(f"ERROR: {exc}", file=sys.stderr)
    raise SystemExit(1)
