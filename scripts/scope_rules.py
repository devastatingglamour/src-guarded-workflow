"""Scope loading and URL matching for the guarded SRC workflow."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import posixpath
from typing import Any
from urllib.parse import unquote, urlsplit

import yaml


class ScopeError(ValueError):
    """Raised when a scope file or URL is invalid."""


@dataclass(frozen=True)
class ScopeDecision:
    allowed: bool
    reason: str
    url: str
    scheme: str | None = None
    host: str | None = None
    path: str | None = None
    port: int | None = None
    method: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "reason": self.reason,
            "url": self.url,
            "scheme": self.scheme,
            "host": self.host,
            "path": self.path,
            "port": self.port,
            "method": self.method,
        }


def load_scope(path: str | Path) -> dict[str, Any]:
    scope_path = Path(path)
    if not scope_path.is_file():
        raise ScopeError(f"Scope file not found: {scope_path}")
    try:
        data = yaml.safe_load(scope_path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001 - surface YAML errors clearly
        raise ScopeError(f"Unable to parse scope YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise ScopeError("Scope file must contain a YAML mapping")

    required = ["program", "authorization_confirmed", "scope", "rate_limit", "data", "ai", "approval"]
    missing = [key for key in required if key not in data]
    if missing:
        raise ScopeError(f"Scope file is missing required keys: {', '.join(missing)}")

    section = data["scope"]
    if not isinstance(section, dict):
        raise ScopeError("scope must be a mapping")
    for key in ["allowed_hosts", "allowed_ports", "allowed_paths", "allowed_methods"]:
        if key not in section:
            raise ScopeError(f"scope.{key} is required")
    if not isinstance(section["allowed_hosts"], list) or not section["allowed_hosts"]:
        raise ScopeError("scope.allowed_hosts must be a non-empty list")
    if not isinstance(section["allowed_ports"], list) or not section["allowed_ports"]:
        raise ScopeError("scope.allowed_ports must be a non-empty list")
    if not isinstance(section["allowed_paths"], list) or not section["allowed_paths"]:
        raise ScopeError("scope.allowed_paths must be a non-empty list")
    if not isinstance(section["allowed_methods"], list) or not section["allowed_methods"]:
        raise ScopeError("scope.allowed_methods must be a non-empty list")
    if data.get("ai", {}).get("autonomous_execution_allowed") is not False:
        raise ScopeError("ai.autonomous_execution_allowed must be false for this workflow")

    return data


def normalize_host(value: str) -> str:
    value = value.strip().lower().rstrip(".")
    if not value:
        raise ScopeError("Host pattern cannot be empty")
    if "://" in value or "/" in value or "@" in value:
        raise ScopeError(f"Host pattern must be a hostname only: {value}")
    try:
        return value.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ScopeError(f"Invalid host pattern: {value}") from exc


def host_matches(host: str, pattern: str) -> bool:
    host = normalize_host(host)
    pattern = normalize_host(pattern)
    if pattern.startswith("*."):
        suffix = pattern[1:]
        return host.endswith(suffix) and host != pattern[2:]
    return host == pattern


def normalize_path(path: str) -> str:
    if not path:
        return "/"
    current = path
    # Decode twice to make obvious double-encoded traversal visible to the check.
    for _ in range(2):
        decoded = unquote(current)
        if decoded == current:
            break
        current = decoded
    if "\x00" in current or "\\" in current:
        raise ScopeError("Path contains a null byte or backslash")
    if not current.startswith("/"):
        current = "/" + current
    normalized = posixpath.normpath(current)
    if normalized == ".":
        return "/"
    if normalized.startswith("//"):
        normalized = "/" + normalized.lstrip("/")
    return normalized


def path_matches(path: str, prefix: str) -> bool:
    path_n = normalize_path(path)
    prefix_n = normalize_path(prefix)
    if prefix_n == "/":
        return True
    return path_n == prefix_n or path_n.startswith(prefix_n.rstrip("/") + "/")


def evaluate_url(
    scope: dict[str, Any],
    url: str,
    method: str = "GET",
    *,
    require_authorization: bool = True,
) -> ScopeDecision:
    method = method.upper().strip()
    try:
        parts = urlsplit(url)
    except ValueError as exc:
        return ScopeDecision(False, f"Invalid URL: {exc}", url, method=method)

    scheme = (parts.scheme or "").lower()
    if scheme not in {"http", "https"}:
        return ScopeDecision(False, "Only http and https URLs are allowed", url, scheme=scheme, method=method)
    if parts.username is not None or parts.password is not None:
        return ScopeDecision(False, "URL userinfo is not allowed", url, scheme=scheme, method=method)
    try:
        host = normalize_host(parts.hostname or "")
    except ScopeError as exc:
        return ScopeDecision(False, str(exc), url, scheme=scheme, method=method)
    if not host:
        return ScopeDecision(False, "URL has no hostname", url, scheme=scheme, method=method)

    try:
        path = normalize_path(parts.path or "/")
    except ScopeError as exc:
        return ScopeDecision(False, str(exc), url, scheme=scheme, host=host, method=method)

    try:
        explicit_port = parts.port
    except ValueError:
        return ScopeDecision(False, "URL has an invalid port", url, scheme=scheme, host=host, path=path, method=method)
    port = explicit_port or (443 if scheme == "https" else 80)

    section = scope["scope"]
    if require_authorization and scope.get("authorization_confirmed") is not True:
        return ScopeDecision(False, "authorization_confirmed is not true", url, scheme, host, path, port, method)

    allowed_methods = {str(item).upper() for item in section.get("allowed_methods", [])}
    if method not in allowed_methods:
        return ScopeDecision(False, f"Method {method} is not allowed by scope", url, scheme, host, path, port, method)

    for denied in section.get("denied_hosts", []):
        if host_matches(host, str(denied)):
            return ScopeDecision(False, f"Host matches denied pattern: {denied}", url, scheme, host, path, port, method)

    if not any(host_matches(host, str(pattern)) for pattern in section.get("allowed_hosts", [])):
        return ScopeDecision(False, f"Host is not in allowed_hosts: {host}", url, scheme, host, path, port, method)

    allowed_ports = {int(port_value) for port_value in section.get("allowed_ports", [])}
    if port not in allowed_ports:
        return ScopeDecision(False, f"Port {port} is not allowed by scope", url, scheme, host, path, port, method)

    for denied_path in section.get("denied_paths", []):
        if path_matches(path, str(denied_path)):
            return ScopeDecision(False, f"Path matches denied path: {denied_path}", url, scheme, host, path, port, method)

    if not any(path_matches(path, str(prefix)) for prefix in section.get("allowed_paths", [])):
        return ScopeDecision(False, f"Path is not in allowed_paths: {path}", url, scheme, host, path, port, method)

    return ScopeDecision(True, "URL is in scope", url, scheme, host, path, port, method)


def assert_in_scope(scope: dict[str, Any], url: str, method: str = "GET") -> ScopeDecision:
    decision = evaluate_url(scope, url, method)
    if not decision.allowed:
        raise ScopeError(decision.reason)
    return decision
