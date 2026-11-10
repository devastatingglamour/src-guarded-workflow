#!/usr/bin/env python3
"""Send one scoped HTTP request with allowlisting, rate limits, and approval gates."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import sys
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin
from urllib.request import HTTPRedirectHandler, Request, build_opener

sys.path.insert(0, str(Path(__file__).resolve().parent))

from scope_rules import ScopeError, ScopeDecision, evaluate_url, load_scope  # noqa: E402


WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
APPROVAL_RISKS = {
    "auth_flow",
    "ssrf",
    "file_upload",
    "redirect_chain",
    "deserialization",
    "cross_tenant",
    "credential_use",
    "exploit_chain",
    "js_inventory",
    "path_scan",
    "port_scan",
    "surface_crawl",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def redact_headers(headers: dict[str, str], redact_names: list[str]) -> dict[str, str]:
    sensitive = {name.lower() for name in redact_names}
    sensitive.update({"cookie", "set-cookie", "authorization", "proxy-authorization"})
    return {key: ("[REDACTED]" if key.lower() in sensitive else value) for key, value in headers.items()}


def parse_headers(items: list[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for item in items:
        if ":" not in item:
            raise ValueError(f"Header must use Name: value form: {item!r}")
        name, value = item.split(":", 1)
        name = name.strip()
        if not name:
            raise ValueError("Header name cannot be empty")
        result[name] = value.strip()
    return result


def load_state(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"request_count": 0, "last_request_epoch": 0.0}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"request_count": 0, "last_request_epoch": 0.0}
    if not isinstance(data, dict):
        return {"request_count": 0, "last_request_epoch": 0.0}
    data.setdefault("request_count", 0)
    data.setdefault("last_request_epoch", 0.0)
    return data


def save_state(path: Path, state: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(".tmp")
    temp.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")
    temp.replace(path)


def append_jsonl(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, ensure_ascii=False) + "\n")


def require_approval(scope: dict[str, Any], method: str, risk: str, token: str | None, note: str | None) -> bool:
    if method not in WRITE_METHODS and risk not in APPROVAL_RISKS:
        return True
    token_env = str(scope.get("approval", {}).get("token_env", "SRC_APPROVAL_TOKEN"))
    expected = os.environ.get(token_env)
    if not expected or not token or not hmac.compare_digest(expected, token):
        return False
    return bool(note and len(note.strip()) >= 8)


class GuardedRedirectHandler(HTTPRedirectHandler):
    def __init__(self, scope: dict[str, Any], max_redirects: int):
        super().__init__()
        self.scope = scope
        self.max_redirects = max_redirects
        self.redirect_count = 0

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        target = urljoin(req.full_url, newurl)
        decision = evaluate_url(self.scope, target, "GET")
        if not decision.allowed:
            raise ScopeError(f"Redirect blocked: {decision.reason} ({target})")
        self.redirect_count += 1
        if self.redirect_count > self.max_redirects:
            raise ScopeError(f"Redirect limit exceeded: {self.max_redirects}")
        return super().redirect_request(req, fp, code, msg, headers, target)


def request_budget(scope: dict[str, Any], state: dict[str, Any]) -> tuple[bool, str]:
    limit = int(scope["rate_limit"]["max_requests_per_run"])
    count = int(state.get("request_count", 0))
    if count >= limit:
        return False, f"Run request limit reached: {count}/{limit}"
    rate = float(scope["rate_limit"]["requests_per_second"])
    last = float(state.get("last_request_epoch", 0.0))
    wait = max(0.0, (1.0 / rate) - (time.time() - last))
    if wait:
        time.sleep(wait)
    return True, "within request budget"


def read_response_body(response, max_body: int) -> tuple[bytes, bool]:
    body = response.read(max_body + 1)
    truncated = len(body) > max_body
    return body[:max_body], truncated

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scope", required=True, help="Active scope YAML")
    parser.add_argument("--url", required=True, help="Target URL")
    parser.add_argument("--method", default="GET", help="HTTP method")
    parser.add_argument("--header", action="append", default=[], help="Header in Name: value form; repeatable")
    parser.add_argument("--data-file", help="Request body file; never echoed to stdout or logs")
    parser.add_argument("--json", dest="json_body", help="JSON request body; prefer --data-file for secrets")
    parser.add_argument("--risk", default="standard", choices=["standard", *sorted(APPROVAL_RISKS)])
    parser.add_argument("--run-dir", help="Run directory created by scripts/new_run.py")
    parser.add_argument("--execute", action="store_true", help="Actually send the request; default is dry-run")
    parser.add_argument("--save-body", action="store_true", help="Save response bytes as evidence")
    parser.add_argument("--approval-token", help="Human-provided approval token; never commit or log it")
    parser.add_argument("--approval-note", help="Why this approved operation is necessary")
    parser.add_argument("--max-body", type=int, default=1_000_000, help="Maximum response bytes to retain")
    parser.add_argument("--json-output", action="store_true", help="Print a machine-readable result")
    args = parser.parse_args()

    try:
        scope = load_scope(args.scope)
        decision: ScopeDecision = evaluate_url(scope, args.url, args.method)
        headers = parse_headers(args.header)
    except (ScopeError, ValueError) as exc:
        print(f"BLOCKED: {exc}", file=sys.stderr)
        return 2

    requires_approval = args.method.upper() in WRITE_METHODS or args.risk in APPROVAL_RISKS
    if not decision.allowed:
        print(f"BLOCKED: {decision.reason}", file=sys.stderr)
        return 2

    if not args.execute:
        result = {
            "mode": "dry-run",
            "allowed": True,
            "reason": decision.reason,
            "method": args.method.upper(),
            "url": args.url,
            "risk": args.risk,
            "approval_required": requires_approval,
            "message": "No request sent. Add --execute to send after reviewing the plan.",
        }
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0

    if not args.run_dir:
        print("BLOCKED: --run-dir is required with --execute", file=sys.stderr)
        return 2
    run_dir = Path(args.run_dir).resolve()
    if not (run_dir / "run.json").is_file():
        print(f"BLOCKED: run.json not found in {run_dir}; run scripts/new_run.py first", file=sys.stderr)
        return 2
    if requires_approval and not require_approval(scope, args.method.upper(), args.risk, args.approval_token, args.approval_note):
        print("BLOCKED: this operation requires a human approval token and approval note", file=sys.stderr)
        return 2

    state_path = run_dir / "logs" / "http_state.json"
    state = load_state(state_path)
    allowed_budget, budget_reason = request_budget(scope, state)
    if not allowed_budget:
        print(f"BLOCKED: {budget_reason}", file=sys.stderr)
        return 2

    request_id = f"req-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{os.getpid()}-{int(time.time_ns() % 1_000_000):06d}"
    request_headers = {"User-Agent": "SRC-Guarded-Workflow/1.0", **headers}
    body_bytes: bytes | None = None
    if args.data_file:
        body_bytes = Path(args.data_file).read_bytes()
    elif args.json_body is not None:
        body_bytes = args.json_body.encode("utf-8")
        request_headers.setdefault("Content-Type", "application/json")

    request = Request(args.url, data=body_bytes, headers=request_headers, method=args.method.upper())
    opener = build_opener(GuardedRedirectHandler(scope, int(scope["rate_limit"]["max_redirects"])))
    timeout = float(scope["rate_limit"]["timeout_seconds"])
    started = time.time()
    status = None
    response_headers: dict[str, str] = {}
    response_body = b""
    truncated = False
    error_text = None

    try:
        with opener.open(request, timeout=timeout) as response:
            status = response.status
            response_headers = dict(response.headers.items())
            response_body, truncated = read_response_body(response, args.max_body)
    except HTTPError as exc:
        status = exc.code
        response_headers = dict(exc.headers.items()) if exc.headers else {}
        response_body, truncated = read_response_body(exc, args.max_body)
    except ScopeError as exc:
        print(f"BLOCKED: {exc}", file=sys.stderr)
        return 2
    except URLError as exc:
        error_text = str(exc.reason)
    except Exception as exc:  # noqa: BLE001 - record unexpected transport failures
        error_text = str(exc)

    elapsed_ms = round((time.time() - started) * 1000, 2)
    body_hash = hashlib.sha256(response_body).hexdigest() if response_body else None
    evidence_dir = run_dir / "evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    body_path = None
    should_save_body = args.save_body or bool(scope.get("data", {}).get("save_response_body_default", False))
    if should_save_body and response_body:
        body_file = evidence_dir / f"{request_id}.body"
        body_file.write_bytes(response_body)
        body_path = str(body_file.relative_to(run_dir))

    evidence_record: dict[str, Any] = {
        "request_id": request_id,
        "timestamp": utc_now(),
        "scope_file": str(Path(args.scope).resolve()),
        "method": args.method.upper(),
        "url": args.url,
        "risk": args.risk,
        "approval_required": requires_approval,
        "request_headers": redact_headers(request_headers, list(scope["data"].get("redact_headers", []))),
        "request_body_sha256": hashlib.sha256(body_bytes).hexdigest() if body_bytes else None,
        "request_body_size": len(body_bytes) if body_bytes else 0,
        "status": status,
        "elapsed_ms": elapsed_ms,
        "response_headers": redact_headers(response_headers, list(scope["data"].get("redact_headers", []))),
        "response_body_sha256": body_hash,
        "response_body_size": len(response_body),
        "response_body_truncated": truncated,
        "response_body_path": body_path,
        "error": error_text,
    }
    evidence_file = evidence_dir / f"{request_id}.json"
    evidence_file.write_text(json.dumps(evidence_record, ensure_ascii=False, indent=2), encoding="utf-8")
    append_jsonl(run_dir / "logs" / "requests.jsonl", evidence_record)

    state["request_count"] = int(state.get("request_count", 0)) + 1
    state["last_request_epoch"] = time.time()
    save_state(state_path, state)

    if requires_approval:
        append_jsonl(run_dir / "logs" / "approvals.jsonl", {
            "timestamp": utc_now(),
            "request_id": request_id,
            "method": args.method.upper(),
            "url": args.url,
            "risk": args.risk,
            "note": args.approval_note,
            "token_env": scope["approval"]["token_env"],
        })

    result = {
        "mode": "execute",
        "request_id": request_id,
        "status": status,
        "elapsed_ms": elapsed_ms,
        "evidence": str(evidence_file.relative_to(run_dir)),
        "response_body": body_path,
        "error": error_text,
    }
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if error_text is None else 4


if __name__ == "__main__":
    raise SystemExit(main())

