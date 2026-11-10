#!/usr/bin/env python3
"""Local stdio MCP server for the SRC guarded workflow."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import subprocess
import sys
import time
from typing import Any, Callable
from urllib.parse import quote, urljoin, urlsplit
from urllib.request import Request, urlopen

import yaml
from jsonschema import Draft202012Validator

BASE_DIR = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = BASE_DIR / "scripts"
SCHEMA_DIR = BASE_DIR / "schemas"
RUNS_ROOT = Path(os.environ.get("SRC_GUARDED_RUNS_ROOT", str(BASE_DIR / "runs"))).resolve()
SCOPE_ROOT = RUNS_ROOT / "_scopes"
MCP_CALL_LOG = RUNS_ROOT / "_mcp-tool-calls.jsonl"
SERVER_VERSION = "0.7.2"
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

CLUEBOARD_SECTIONS = {
    "hypotheses": "Hypotheses",
    "hosts": "Host map",
    "paths": "Path and method map",
    "auth": "Authentication and crypto notes",
    "negative": "Negative evidence",
    "credentials": "Redacted credentials and sensitive strings",
    "todo": "Todo",
    "coverage": "Coverage",
}
CLUEBOARD_STATUSES = {"assumption", "rejected", "confirmed", "pending"}
CLUEBOARD_GRAPH_STATUSES = {"pending", "in_progress", "done", "rejected"}

SKILL_AUDIT_TEXT_EXTENSIONS = {
    ".md", ".txt", ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg",
    ".py", ".js", ".mjs", ".cjs", ".ts", ".ps1", ".sh", ".bash", ".zsh",
}
SKILL_AUDIT_SKIP_DIRS = {".git", "node_modules", "__pycache__", ".pytest_cache", "dist", "runs"}
SKILL_AUDIT_RULES = [
    ("private_key", "critical", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), "Private key material is present.", True),
    ("shell_pipe", "critical", re.compile(r"(?i)\b(?:curl|wget)\b[^\n]{0,300}\|\s*(?:ba)?sh\b|\b(?:curl|wget)\b[^\n]{0,300}\|\s*(?:powershell|pwsh)\b"), "Remote content is piped directly into a shell.", False),
    ("encoded_exec", "high", re.compile(r"(?i)(?:base64\s+(?:-d|--decode)|frombase64string|powershell[^\n]{0,80}-(?:enc|encodedcommand)|eval\s*\(\s*atob\s*\()"), "Encoded or obfuscated code execution pattern.", False),
    ("dynamic_exec", "high", re.compile(r"(?i)\b(?:eval|exec|invoke-expression|iex)\s*\(|\bnew\s+Function\s*\(|\bchild_process\.(?:exec|execSync|spawn)\b|\bos\.system\s*\(|\bsubprocess\.(?:run|Popen|call)\s*\([^\n]{0,200}shell\s*=\s*True"), "Dynamic code execution or shell invocation.", False),
    ("approval_bypass", "high", re.compile(r"(?i)dangerouslyDisableSandbox|dangerously-bypass-approvals-and-sandbox|--no-sandbox"), "Sandbox or approval bypass is mentioned in executable guidance.", False),
    ("destructive_command", "high", re.compile(r"(?i)\brm\s+-rf\b|\bRemove-Item\b[^\n]{0,200}-Recurse[^\n]{0,200}-Force|\bformat\s+[A-Za-z]:|\bDROP\s+(?:DATABASE|TABLE)\b|\bTRUNCATE\s+TABLE\b"), "Destructive filesystem or database command pattern.", False),
    ("secret_assignment", "medium", re.compile(r"(?i)\b(?:api[_-]?key|app[_-]?secret|client[_-]?secret|password|passwd|access[_-]?token|refresh[_-]?token)\b\s*[:=]\s*['\"][^'\"]{8,}['\"]"), "Potential hard-coded secret assignment.", True),
    ("credential_path", "medium", re.compile(r"(?i)(?:\.ssh[\\/]|id_rsa|\.aws[\\/]|credentials\b|keychain|dpapi)"), "Credential or sensitive profile path reference.", False),
    ("exfiltration_language", "high", re.compile(r"(?i)(?:send|post|upload|exfiltrat|transmit)[^\n]{0,100}(?:token|secret|credential|environment|env\b|\.ssh|profile)"), "Content may direct sensitive data to an external destination.", False),
    ("prompt_override", "medium", re.compile(r"(?i)ignore\s+(?:all\s+)?(?:previous|prior)\s+instructions|reveal\s+(?:the\s+)?system\s+prompt|bypass\s+(?:the\s+)?system|override\s+(?:the\s+)?developer"), "Prompt-injection or instruction-override language.", False),
    ("mcp_tool_abuse", "high", re.compile(r"(?i)(?:call|invoke)[^\n]{0,80}(?:mcp|tool)[^\n]{0,80}(?:without|skip|ignore)[^\n]{0,50}(?:approval|confirm|scope)"), "Possible instruction to bypass MCP/tool approval boundaries.", False),
    ("zero_width_control", "medium", re.compile(r"[\u200B-\u200F\u202A-\u202E\u2060\uFEFF]"), "Zero-width or bidirectional control characters detected.", True),
    ("html_comment_instruction", "low", re.compile(r"(?is)<!--.{0,500}(?:ignore|system prompt|instruction|execute|secret).{0,500}-->"), "HTML comment contains instruction-like text.", False),
    ("remote_install", "info", re.compile(r"(?i)\b(?:pip|pipx|npm|pnpm|yarn|go)\s+install\b|\bgit\s+clone\b"), "Remote installation command is documented or executed.", False),
]

sys.path.insert(0, str(SCRIPTS_DIR))
from scope_rules import ScopeError, evaluate_url, load_scope  # noqa: E402
from surface_tools import import_har, js_inventory, path_probe, port_probe  # noqa: E402
from intel_tools import asset_intel, provider_status as intel_provider_status  # noqa: E402


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def slug(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", value.strip()).strip("-")
    return cleaned or "run"


def compact(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2)


def run_script(name: str, args: list[str], *, timeout: int = 120, env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(SCRIPTS_DIR / name), *args],
        cwd=str(BASE_DIR),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        env=env,
    )


def parse_last_json(text: str) -> Any:
    text = text.strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return text


def load_run(run_id: str) -> tuple[Path, dict[str, Any]]:
    matches = []
    for run_json in RUNS_ROOT.glob("**/run.json"):
        try:
            data = json.loads(run_json.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if data.get("run_id") == run_id:
            matches.append((run_json.parent, data))
    if not matches:
        raise ValueError(f"Unknown run_id: {run_id}")
    if len(matches) > 1:
        raise ValueError(f"Multiple runs match run_id: {run_id}")
    return matches[0]


def load_scope_for_run(run_dir: Path, run_meta: dict[str, Any]) -> dict[str, Any]:
    scope_path = Path(str(run_meta.get("scope_file", "")))
    if not scope_path.is_absolute():
        scope_path = (run_dir / scope_path).resolve()
    return load_scope(scope_path)


def update_run_meta(run_dir: Path, updates: dict[str, Any]) -> dict[str, Any]:
    path = run_dir / "run.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data.update(updates)
    data["updated_at"] = utc_now()
    path.write_text(compact(data), encoding="utf-8")
    return data

def prepare_run(args: dict[str, Any]) -> dict[str, Any]:
    asset = str(args.get("asset", "")).strip()
    program = str(args.get("program", "")).strip()
    policy_url = str(args.get("policy_url", "")).strip()
    authorization_confirmed = bool(args.get("authorization_confirmed", False))
    if not asset or not program or not policy_url:
        return {"ok": False, "status": "needs_program_context", "message": "asset, program, and policy_url are required"}
    if not authorization_confirmed:
        return {"ok": False, "status": "needs_authorization", "message": "Confirm that this exact asset is authorized by the SRC program before active testing."}

    parts = urlsplit(asset)
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        return {"ok": False, "status": "invalid_asset", "message": "asset must be an absolute http(s) URL"}
    host = parts.hostname.lower()
    port = parts.port or (443 if parts.scheme == "https" else 80)
    path = parts.path or "/"
    override = args.get("scope") or {}
    if not isinstance(override, dict):
        return {"ok": False, "status": "invalid_scope", "message": "scope must be an object"}

    scope_data = {
        "version": 1,
        "program": {
            "name": program,
            "platform": str(args.get("platform", "chat-src")),
            "policy_url": policy_url,
            "contact": str(args.get("contact", "program-approved-channel")),
            "authorization_source": "user-confirmed-in-chat",
            "test_window": str(args.get("test_window", "current-run")),
        },
        "authorization_confirmed": True,
        "scope": {
            "allowed_hosts": override.get("allowed_hosts") or [host],
            "denied_hosts": override.get("denied_hosts") or [],
            "allowed_ports": override.get("allowed_ports") or [port],
            "allowed_paths": override.get("allowed_paths") or [path],
            "denied_paths": override.get("denied_paths") or [],
            "allowed_methods": [str(value).upper() for value in (override.get("allowed_methods") or ["GET", "HEAD", "OPTIONS"])],
        },
        "rate_limit": {
            "requests_per_second": float(override.get("requests_per_second", 0.5)),
            "max_requests_per_run": int(override.get("max_requests_per_run", 200)),
            "timeout_seconds": float(override.get("timeout_seconds", 15)),
            "max_redirects": int(override.get("max_redirects", 3)),
        },
        "accounts": args.get("accounts") or [],
        "data": {
            "save_response_body_default": False,
            "redact_headers": ["cookie", "set-cookie", "authorization", "proxy-authorization", "x-api-key", "x-auth-token", "csrf-token"],
            "allow_real_user_data": False,
            "retain_evidence_days": 7,
        },
        "ai": {"autonomous_execution_allowed": False, "human_verification_required": True},
        "approval": {
            "token_env": "SRC_APPROVAL_TOKEN",
            "required_operations": ["POST", "PUT", "PATCH", "DELETE", *sorted(APPROVAL_RISKS), "report_submission"],
        },
    }
    SCOPE_ROOT.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    scope_path = SCOPE_ROOT / f"{slug(program)}-{stamp}.yaml"
    scope_path.write_text(yaml.safe_dump(scope_data, sort_keys=False, allow_unicode=True), encoding="utf-8")
    try:
        scope = load_scope(scope_path)
        decision = evaluate_url(scope, asset, "GET")
    except ScopeError as exc:
        return {"ok": False, "status": "invalid_scope", "message": str(exc)}
    if not decision.allowed:
        return {"ok": False, "status": "asset_not_in_scope", "message": decision.reason}

    result = run_script("new_run.py", [
        "--scope", str(scope_path),
        "--program", program,
        "--operator", str(args.get("operator", "codex")),
        "--output-root", str(RUNS_ROOT),
    ])
    if result.returncode != 0:
        return {"ok": False, "status": "run_creation_failed", "message": result.stderr.strip() or result.stdout.strip()}
    run_dir = Path(result.stdout.strip()).resolve()
    run_meta = update_run_meta(run_dir, {
        "asset": asset,
        "scope_override": override,
        "started_by": "src_guarded_workflow_mcp",
    })
    return {
        "ok": True,
        "status": "prepared",
        "run_id": run_meta["run_id"],
        "run_dir": str(run_dir),
        "scope_path": str(scope_path),
        "scope": scope_data["scope"],
        "asset": asset,
    }


def approval_dir(run_dir: Path) -> Path:
    path = run_dir / "logs" / "approval_requests"
    path.mkdir(parents=True, exist_ok=True)
    return path


def request_approval(args: dict[str, Any]) -> dict[str, Any]:
    run_dir, _ = load_run(str(args.get("run_id", "")))
    method = str(args.get("method", "")).upper()
    risk = str(args.get("risk", "standard"))
    url = str(args.get("url", ""))
    reason = str(args.get("reason", "")).strip()
    max_uses = max(1, min(int(args.get("max_uses", 1)), 100))
    if not method or not url or not reason:
        return {"ok": False, "status": "invalid_approval_request", "message": "method, url, and reason are required"}
    code = "SRC-" + secrets.token_hex(3).upper()
    record = {
        "code": code,
        "status": "pending",
        "requested_at": utc_now(),
        "method": method,
        "risk": risk,
        "url": url,
        "reason": reason,
        "max_uses": max_uses,
        "uses": 0,
        "human_confirmation_required": f"APPROVE {code}",
    }
    path = approval_dir(run_dir) / f"{code}.json"
    path.write_text(compact(record), encoding="utf-8")
    return {
        "ok": True,
        "status": "approval_pending",
        "approval_code": code,
        "message": "Ask the user to reply with exactly: " + record["human_confirmation_required"],
        "record": record,
    }


def confirm_approval(args: dict[str, Any]) -> dict[str, Any]:
    run_dir, _ = load_run(str(args.get("run_id", "")))
    code = str(args.get("approval_code", "")).strip().upper()
    text = str(args.get("user_confirmation", "")).strip()
    expected = f"APPROVE {code}"
    path = approval_dir(run_dir) / f"{code}.json"
    if not path.is_file():
        return {"ok": False, "status": "approval_not_found", "message": "Unknown approval code"}
    record = json.loads(path.read_text(encoding="utf-8"))
    if record.get("status") != "pending":
        return {"ok": False, "status": "approval_not_pending", "message": f"Approval is {record.get('status')}"}
    if text != expected:
        return {"ok": False, "status": "approval_not_confirmed", "message": f"Expected exact reply: {expected}"}
    record["status"] = "approved"
    record["approved_at"] = utc_now()
    path.write_text(compact(record), encoding="utf-8")
    return {"ok": True, "status": "approved", "approval_code": code, "record": record}


def consume_approval(run_dir: Path, code: str, method: str, url: str, risk: str) -> tuple[bool, str]:
    path = approval_dir(run_dir) / f"{code.strip().upper()}.json"
    if not path.is_file():
        return False, "Approval code not found"
    record = json.loads(path.read_text(encoding="utf-8"))
    if record.get("status") != "approved":
        return False, f"Approval is {record.get('status')}"
    url_matches = record.get("url") == url
    if not url_matches and risk in {"js_inventory", "path_scan", "surface_crawl"}:
        try:
            url_matches = urlsplit(str(record.get("url", ""))).hostname == urlsplit(url).hostname
        except ValueError:
            url_matches = False
    if record.get("method") != method.upper() or not url_matches or record.get("risk") != risk:
        return False, "Approval does not match method, URL, and risk"
    record["uses"] = int(record.get("uses", 0)) + 1
    record["last_used_at"] = utc_now()
    if record["uses"] >= int(record.get("max_uses", 1)):
        record["status"] = "consumed"
        record["consumed_at"] = utc_now()
    else:
        record["status"] = "approved"
    path.write_text(compact(record), encoding="utf-8")
    return True, "Approval consumed"

def passive_recon(args: dict[str, Any]) -> dict[str, Any]:
    run_dir, run_meta = load_run(str(args.get("run_id", "")))
    scope = load_scope_for_run(run_dir, run_meta)
    asset = str(run_meta.get("asset", ""))
    decision = evaluate_url(scope, asset, "GET")
    if not decision.allowed:
        return {"ok": False, "status": "asset_not_in_scope", "message": decision.reason}
    include_dns = bool(args.get("include_dns", True))
    include_ct = bool(args.get("include_ct", True))
    host = urlsplit(asset).hostname or ""
    observations: dict[str, Any] = {"host": host, "asset": asset, "timestamp": utc_now(), "warnings": []}
    if include_dns:
        try:
            infos = socket.getaddrinfo(host, None)
            observations["ips"] = sorted({str(info[4][0]) for info in infos})
        except OSError as exc:
            observations["ips"] = []
            observations["warnings"].append(f"DNS lookup failed: {exc}")
    else:
        observations["ips"] = []
    ct_names: list[str] = []
    if include_ct:
        try:
            url = f"https://crt.sh/?q=%25.{quote(host)}&output=json"
            request = Request(url, headers={"User-Agent": "SRC-Guarded-Workflow/0.2"})
            with urlopen(request, timeout=10) as response:
                raw = response.read(2_000_000)
            entries = json.loads(raw)
            for entry in entries if isinstance(entries, list) else []:
                for name in str(entry.get("name_value", "")).splitlines():
                    name = name.strip().lower()
                    if name and name not in ct_names:
                        ct_names.append(name)
            observations["ct_names"] = ct_names[:500]
            observations["ct_truncated"] = len(ct_names) > 500
        except Exception as exc:  # noqa: BLE001 - CT is optional reconnaissance
            observations["ct_names"] = []
            observations["warnings"].append(f"Certificate transparency lookup failed: {exc}")
    else:
        observations["ct_names"] = []
    evidence_path = run_dir / "evidence" / "passive-recon.json"
    evidence_path.write_text(compact(observations), encoding="utf-8")
    attack_surface = run_dir / "attack-surface.md"
    with attack_surface.open("a", encoding="utf-8") as handle:
        handle.write(f"\n## Passive recon {observations['timestamp']}\n\n")
        handle.write(f"- Asset: `{asset}`\n")
        handle.write(f"- DNS IPs: {', '.join(observations['ips']) or 'none observed'}\n")
        handle.write(f"- CT names observed: {len(observations['ct_names'])}\n")
        for warning in observations["warnings"]:
            handle.write(f"- Warning: {warning}\n")
    return {"ok": True, "status": "recon_complete", "run_id": run_meta["run_id"], "observations": observations, "evidence": str(evidence_path)}


def guarded_http(args: dict[str, Any]) -> dict[str, Any]:
    run_dir, run_meta = load_run(str(args.get("run_id", "")))
    scope = load_scope_for_run(run_dir, run_meta)
    url = str(args.get("url", "")).strip()
    method = str(args.get("method", "GET")).upper()
    risk = str(args.get("risk", "standard"))
    execute = bool(args.get("execute", False))
    save_body = bool(args.get("save_body", False))
    decision = evaluate_url(scope, url, method)
    if not decision.allowed:
        return {"ok": False, "status": "blocked", "message": decision.reason}
    requires_approval = method in WRITE_METHODS or risk in APPROVAL_RISKS
    approval_note = str(args.get("approval_note", "approved through MCP chat gate"))
    internal_env = os.environ.copy()
    command = [
        "--scope", str(Path(run_meta["scope_file"])),
        "--url", url,
        "--method", method,
        "--risk", risk,
        "--run-dir", str(run_dir),
    ]
    if save_body:
        command.append("--save-body")
    if args.get("max_body"):
        command.extend(["--max-body", str(int(args["max_body"]))])
    if execute:
        command.append("--execute")
    if requires_approval and execute:
        approval_code = str(args.get("approval_code", "")).strip()
        if not approval_code:
            return {
                "ok": True,
                "status": "approval_required",
                "message": "Call src_request_approval, show the code to the user, wait for APPROVE <code>, then call src_confirm_approval.",
            }
        ok, message = consume_approval(run_dir, approval_code, method, url, risk)
        if not ok:
            return {"ok": False, "status": "approval_rejected", "message": message}
        internal_token = secrets.token_urlsafe(32)
        internal_env["SRC_APPROVAL_TOKEN"] = internal_token
        command.extend([f"--approval-token={internal_token}", f"--approval-note={approval_note}"])
    for name, value in (args.get("headers") or {}).items():
        command.extend(["--header", f"{name}: {value}"])
    result = run_script("guarded_http.py", command, env=internal_env, timeout=int(args.get("timeout", 120)))
    parsed = parse_last_json(result.stdout)
    return {
        "ok": result.returncode == 0,
        "status": "request_complete" if result.returncode == 0 else "request_failed",
        "run_id": run_meta["run_id"],
        "result": parsed,
        "stderr": result.stderr.strip(),
    }


def start_workflow(args: dict[str, Any]) -> dict[str, Any]:
    prepared = prepare_run(args)
    if not prepared.get("ok"):
        return prepared
    run_id = prepared["run_id"]
    recon = None
    if bool(args.get("include_recon", True)):
        recon = passive_recon({"run_id": run_id, "include_dns": True, "include_ct": True})
    baseline = None
    if bool(args.get("baseline", True)):
        baseline = guarded_http({
            "run_id": run_id,
            "url": prepared["asset"],
            "method": "GET",
            "risk": "standard",
            "execute": True,
            "save_body": bool(args.get("save_baseline_body", False)),
        })
    return {
        "ok": True,
        "status": "started",
        "run_id": run_id,
        "run_dir": prepared["run_dir"],
        "scope_path": prepared["scope_path"],
        "asset": prepared["asset"],
        "clueboard": str(clueboard_path_for_run(Path(prepared["run_dir"]))),
        "recon": recon,
        "baseline": baseline,
        "next_steps": [
            "Read CLUEBOARD.md with src_clueboard and set the current focus before active testing.",
            "Review attack-surface.md and baseline evidence.",
            "Call src_hunt_route for the next feature or observed signal.",
            "Call src_vuln_playbook before validating a vulnerability class.",
            "Use src_request_approval before any write or high-risk validation.",
            "Write hypotheses and negative evidence back to the clueboard in the same turn.",
            "Record leads with src_save_finding; do not claim a vulnerability without actual evidence.",
        ],
    }


def workflow_status(args: dict[str, Any]) -> dict[str, Any]:
    run_dir, run_meta = load_run(str(args.get("run_id", "")))
    request_count = 0
    request_log = run_dir / "logs" / "requests.jsonl"
    if request_log.is_file():
        request_count = sum(1 for line in request_log.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip())
    findings = []
    for path in sorted((run_dir / "candidates").glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        findings.append({"finding_id": data.get("finding_id"), "status": data.get("status"), "title": data.get("title")})
    approvals = []
    for path in sorted((run_dir / "logs" / "approval_requests").glob("*.json")) if (run_dir / "logs" / "approval_requests").is_dir() else []:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        approvals.append({"code": data.get("code"), "status": data.get("status"), "method": data.get("method"), "url": data.get("url")})
    return {
        "ok": True,
        "status": "ok",
        "run": run_meta,
        "request_count": request_count,
        "findings": findings,
        "approvals": approvals,
        "run_dir": str(run_dir),
        "clueboard": str(clueboard_path_for_run(run_dir)),
    }

def save_finding(args: dict[str, Any]) -> dict[str, Any]:
    run_dir, run_meta = load_run(str(args.get("run_id", "")))
    finding = args.get("finding")
    if not isinstance(finding, dict):
        return {"ok": False, "status": "invalid_finding", "message": "finding must be an object"}
    schema = json.loads((SCHEMA_DIR / "finding.schema.json").read_text(encoding="utf-8"))
    try:
        Draft202012Validator(schema).validate(finding)
    except Exception as exc:
        return {"ok": False, "status": "invalid_finding", "message": str(exc)}
    finding_id = str(finding["finding_id"])
    path = run_dir / "candidates" / f"{finding_id}.json"
    path.write_text(compact(finding), encoding="utf-8")
    return {"ok": True, "status": "finding_saved", "finding_id": finding_id, "path": str(path)}


def validate_finding_tool(args: dict[str, Any]) -> dict[str, Any]:
    run_dir, _ = load_run(str(args.get("run_id", "")))
    finding_id = str(args.get("finding_id", "")).strip()
    if not finding_id:
        return {"ok": False, "status": "invalid_finding_id", "message": "finding_id is required"}
    finding_path = run_dir / "candidates" / f"{finding_id}.json"
    if not finding_path.is_file():
        return {"ok": False, "status": "finding_not_found", "message": str(finding_path)}
    result = run_script("validate_finding.py", ["--finding", str(finding_path), "--run-dir", str(run_dir), "--json"])
    parsed = parse_last_json(result.stdout)
    return {"ok": result.returncode == 0, "status": "validated" if result.returncode == 0 else "validation_failed", "validation": parsed, "stderr": result.stderr.strip()}


def render_report_tool(args: dict[str, Any]) -> dict[str, Any]:
    run_dir, _ = load_run(str(args.get("run_id", "")))
    finding_id = str(args.get("finding_id", "")).strip()
    if not finding_id:
        return {"ok": False, "status": "invalid_finding_id", "message": "finding_id is required"}
    finding_path = run_dir / "candidates" / f"{finding_id}.json"
    output = args.get("output") or str(run_dir / "reports" / f"{finding_id}.md")
    result = run_script("render_report.py", ["--finding", str(finding_path), "--run-dir", str(run_dir), "--output", str(output)])
    return {"ok": result.returncode == 0, "status": "report_rendered" if result.returncode == 0 else "report_blocked", "output": str(output), "message": result.stdout.strip(), "stderr": result.stderr.strip()}


def load_playbook_classes() -> list[dict[str, Any]]:
    classes = []
    class_dir = BASE_DIR / "knowledge" / "classes"
    for path in sorted(class_dir.glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(data, dict) and data.get("id"):
            classes.append(data)
    return classes


def vuln_playbook(args: dict[str, Any]) -> dict[str, Any]:
    classes = load_playbook_classes()
    query = str(args.get("query", "")).strip().lower()
    class_id = str(args.get("class_id", "")).strip().lower()
    priority = str(args.get("priority", "")).strip().lower()
    matches = []
    for item in classes:
        haystack = " ".join([
            str(item.get("id", "")),
            str(item.get("name", "")),
            " ".join(str(alias) for alias in item.get("aliases", [])),
        ]).lower()
        if class_id and str(item.get("id", "")).lower() != class_id:
            continue
        if query and query not in haystack:
            continue
        if priority and str(item.get("priority", "")).lower() != priority:
            continue
        matches.append(item)
    if not query and not class_id and not priority:
        matches = classes
    if not matches:
        return {
            "ok": False,
            "status": "no_match",
            "message": "No playbook matched. Try a class ID such as idor_bola, ssrf, xss, sql_injection, or business_logic.",
            "available_ids": sorted(str(item.get("id")) for item in classes),
        }
    if len(matches) > 8:
        summary = [{key: item.get(key) for key in ["id", "name", "priority", "approval", "aliases"]} for item in matches]
        return {"ok": True, "status": "class_index", "count": len(matches), "classes": summary, "message": "Call again with class_id or a narrower query for full detection guidance."}
    return {"ok": True, "status": "playbook", "count": len(matches), "classes": matches}


def load_expert_routes() -> tuple[dict[str, Any], list[dict[str, Any]]]:
    path = BASE_DIR / "knowledge" / "expert-routes.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Unable to load expert routes: {exc}") from exc
    routes = data.get("routes") if isinstance(data, dict) else None
    if not isinstance(routes, list):
        raise ValueError("knowledge/expert-routes.json must contain a routes array")
    source = data.get("source") if isinstance(data.get("source"), dict) else {}
    return source, [route for route in routes if isinstance(route, dict) and route.get("id")]


def hunt_route(args: dict[str, Any]) -> dict[str, Any]:
    source, routes = load_expert_routes()
    route_id = str(args.get("route_id", "")).strip().lower()
    query = str(args.get("query", "")).strip().lower()
    max_routes = max(1, min(int(args.get("max_routes", 1)), 3))
    if route_id:
        matches = [route for route in routes if str(route.get("id", "")).lower() == route_id]
    elif query:
        scored: list[tuple[int, dict[str, Any]]] = []
        for route in routes:
            terms = [
                str(route.get("id", "")),
                str(route.get("name", "")),
                *[str(value) for value in route.get("triggers", [])],
                *[str(value) for value in route.get("playbook_classes", [])],
            ]
            normalized = [term.lower().strip() for term in terms if term.strip()]
            score = 0
            for term in normalized:
                if term == query:
                    score += 4
                elif term in query or query in term:
                    score += 1
            if score:
                scored.append((score, route))
        scored.sort(key=lambda item: (-item[0], str(item[1].get("id", ""))))
        matches = [route for _, route in scored[:max_routes]]
    else:
        index = [
            {
                "id": route.get("id"),
                "name": route.get("name"),
                "phase": route.get("phase"),
                "playbook_classes": route.get("playbook_classes", []),
            }
            for route in routes
        ]
        return {
            "ok": True,
            "status": "ok",
            "result_type": "route_index",
            "count": len(index),
            "routes": index,
            "source": source,
        }

    if not matches:
        return {
            "ok": False,
            "status": "no_match",
            "message": "No expert route matched. Use src_vuln_playbook for a known class or provide a more specific feature description.",
            "available_route_ids": sorted(str(route.get("id")) for route in routes),
        }
    keys = ["id", "name", "phase", "playbook_classes", "tools", "batch_approval_required", "outputs", "gates"]
    summaries = [{key: route.get(key) for key in keys} for route in matches]
    result: dict[str, Any] = {
        "ok": True,
        "status": "ok",
        "result_type": "expert_route",
        "count": len(summaries),
        "next_step": "Use the route, read the clueboard, then form one falsifiable hypothesis before active validation.",
    }
    if len(summaries) == 1:
        result["route"] = summaries[0]
    else:
        result["routes"] = summaries
    return result


def clueboard_path_for_run(run_dir: Path) -> Path:
    return run_dir / "CLUEBOARD.md"


def clueboard_graph_path_for_run(run_dir: Path) -> Path:
    return run_dir / "CLUEBOARD.json"


def ensure_clueboard(run_dir: Path, run_meta: dict[str, Any]) -> Path:
    path = clueboard_path_for_run(run_dir)
    if path.is_file():
        return path
    template_path = BASE_DIR / "templates" / "clueboard.md"
    text = template_path.read_text(encoding="utf-8")
    target = str(run_meta.get("asset") or run_meta.get("program") or "target")
    text = text.replace("# Hunt Clueboard - <target>", f"# Hunt Clueboard - {target}")
    text = text.replace("- Program:", f"- Program: {run_meta.get('program', '')}")
    text = text.replace("- Asset:", f"- Asset: {run_meta.get('asset', '')}")
    text = text.replace("- Policy:", f"- Policy: {run_meta.get('policy_url', '')}")
    text = text.replace("- Authorization:", f"- Authorization: {run_meta.get('authorization_confirmed') is True}")
    path.write_text(text, encoding="utf-8")
    return path


def ensure_clueboard_graph(run_dir: Path, run_meta: dict[str, Any]) -> dict[str, Any]:
    path = clueboard_graph_path_for_run(run_dir)
    if path.is_file():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                for key in ("facts", "intents", "hints"):
                    if not isinstance(data.get(key), list):
                        data[key] = []
                return data
        except (OSError, json.JSONDecodeError):
            pass
    data = {
        "schema_version": 1,
        "origin": str(run_meta.get("asset") or run_meta.get("program") or "target"),
        "goal": "Find and verify an authorized, reproducible, reportable security finding without leaving scope.",
        "facts": [],
        "intents": [],
        "hints": [],
        "created_at": utc_now(),
        "updated_at": utc_now(),
    }
    path.write_text(compact(data), encoding="utf-8")
    return data


def save_clueboard_graph(run_dir: Path, graph: dict[str, Any]) -> None:
    graph["updated_at"] = utc_now()
    clueboard_graph_path_for_run(run_dir).write_text(compact(graph), encoding="utf-8")


def next_graph_id(prefix: str, items: list[dict[str, Any]]) -> str:
    maximum = 0
    for item in items:
        match = re.fullmatch(rf"{re.escape(prefix)}-(\d+)", str(item.get("id", "")))
        if match:
            maximum = max(maximum, int(match.group(1)))
    return f"{prefix}-{maximum + 1:03d}"


def clueboard_graph_summary(graph: dict[str, Any]) -> dict[str, Any]:
    return {
        "origin": graph.get("origin"),
        "goal": graph.get("goal"),
        "facts": len(graph.get("facts", [])),
        "intents": len(graph.get("intents", [])),
        "hints": len(graph.get("hints", [])),
        "pending_intents": sum(1 for item in graph.get("intents", []) if item.get("status") == "pending"),
        "in_progress_intents": sum(1 for item in graph.get("intents", []) if item.get("status") == "in_progress"),
        "updated_at": graph.get("updated_at"),
    }


def append_clueboard_section_line(text: str, heading: str, line: str) -> str:
    match = re.search(rf"(?ms)^## {re.escape(heading)}\s*\n(.*?)(?=^## |\Z)", text)
    if not match:
        raise ValueError(f"Clueboard section not found: {heading}")
    existing = match.group(1).strip()
    new_body = f"{existing}\n\n{line}" if existing else line
    return replace_clueboard_section(text, heading, new_body)


def replace_clueboard_section(text: str, heading: str, new_body: str) -> str:
    pattern = re.compile(rf"(?ms)^## {re.escape(heading)}\s*\n(.*?)(?=^## |\Z)")
    match = pattern.search(text)
    if not match:
        raise ValueError(f"Clueboard section not found: {heading}")
    replacement = f"## {heading}\n\n{new_body.strip()}\n\n"
    return text[:match.start()] + replacement + text[match.end():]


def clueboard_tool(args: dict[str, Any]) -> dict[str, Any]:
    run_dir, run_meta = load_run(str(args.get("run_id", "")))
    path = ensure_clueboard(run_dir, run_meta)
    graph_path = clueboard_graph_path_for_run(run_dir)
    graph = ensure_clueboard_graph(run_dir, run_meta)
    action = str(args.get("action", "read")).strip().lower()
    text = path.read_text(encoding="utf-8")
    if action == "read":
        return {
            "ok": True,
            "status": "clueboard",
            "run_id": run_meta["run_id"],
            "path": str(path),
            "graph_path": str(graph_path),
            "content": text,
            "graph_summary": clueboard_graph_summary(graph),
        }
    if action == "graph":
        return {
            "ok": True,
            "status": "clueboard_graph",
            "run_id": run_meta["run_id"],
            "graph_path": str(graph_path),
            "graph": graph,
            "graph_summary": clueboard_graph_summary(graph),
        }
    if action == "set_focus":
        content = str(args.get("content", "")).strip()
        if not content:
            return {"ok": False, "status": "invalid_clueboard_update", "message": "content is required for set_focus"}
        if len(content) > 1000:
            return {"ok": False, "status": "clueboard_content_too_long", "message": "Focus content must be 1000 characters or fewer"}
        updated = replace_clueboard_section(text, "Current focus", f"- {content}")
    elif action == "append":
        section = str(args.get("section", "")).strip().lower()
        content = str(args.get("content", "")).strip()
        status = str(args.get("status", "")).strip().lower()
        if section not in CLUEBOARD_SECTIONS:
            return {"ok": False, "status": "invalid_clueboard_section", "available_sections": sorted(CLUEBOARD_SECTIONS)}
        if not content:
            return {"ok": False, "status": "invalid_clueboard_update", "message": "content is required for append"}
        if len(content) > 4000:
            return {"ok": False, "status": "clueboard_content_too_long", "message": "Append content must be 4000 characters or fewer"}
        if status and status not in CLUEBOARD_STATUSES:
            return {"ok": False, "status": "invalid_clueboard_status", "available_statuses": sorted(CLUEBOARD_STATUSES)}
        heading = CLUEBOARD_SECTIONS[section]
        entry = f"- {utc_now()} [{status or 'note'}] {content}"
        updated = append_clueboard_section_line(text, heading, entry)
    elif action in {"add_fact", "add_intent", "add_hint"}:
        content = str(args.get("content", "")).strip()
        if not content:
            return {"ok": False, "status": "invalid_clueboard_update", "message": f"content is required for {action}"}
        if len(content) > 4000:
            return {"ok": False, "status": "clueboard_content_too_long", "message": "Graph content must be 4000 characters or fewer"}
        related_ids = [str(value) for value in (args.get("related_ids") or []) if str(value).strip()]
        if action == "add_fact":
            node = {
                "id": next_graph_id("F", graph["facts"]),
                "content": content,
                "status": "confirmed",
                "evidence": str(args.get("evidence", "")).strip(),
                "related_ids": related_ids,
                "created_at": utc_now(),
            }
            graph["facts"].append(node)
            line = f"- FACT `{node['id']}`: {content}"
        elif action == "add_intent":
            node_status = str(args.get("node_status", "pending")).strip().lower()
            if node_status not in {"pending", "in_progress", "done", "rejected"}:
                return {"ok": False, "status": "invalid_graph_status", "available_statuses": ["pending", "in_progress", "done", "rejected"]}
            node = {
                "id": next_graph_id("I", graph["intents"]),
                "content": content,
                "status": node_status,
                "from_facts": related_ids,
                "created_at": utc_now(),
            }
            graph["intents"].append(node)
            line = f"- INTENT `{node['id']}` [{node_status}]: {content}"
        else:
            node = {
                "id": next_graph_id("H", graph["hints"]),
                "content": content,
                "related_ids": related_ids,
                "created_at": utc_now(),
            }
            graph["hints"].append(node)
            line = f"- HINT `{node['id']}`: {content}"
        save_clueboard_graph(run_dir, graph)
        updated = append_clueboard_section_line(text, "Fact-Intent graph", line)
        path.write_text(updated, encoding="utf-8")
        return {
            "ok": True,
            "status": "clueboard_graph_updated",
            "run_id": run_meta["run_id"],
            "path": str(path),
            "graph_path": str(graph_path),
            "node": node,
            "graph_summary": clueboard_graph_summary(graph),
        }
    elif action == "update_intent":
        node_id = str(args.get("node_id", "")).strip().upper()
        node_status = str(args.get("node_status", "")).strip().lower()
        if node_status not in {"pending", "in_progress", "done", "rejected"}:
            return {"ok": False, "status": "invalid_graph_status", "available_statuses": ["pending", "in_progress", "done", "rejected"]}
        node = next((item for item in graph["intents"] if str(item.get("id", "")).upper() == node_id), None)
        if not node:
            return {"ok": False, "status": "intent_not_found", "node_id": node_id}
        node["status"] = node_status
        node["updated_at"] = utc_now()
        save_clueboard_graph(run_dir, graph)
        updated = append_clueboard_section_line(text, "Fact-Intent graph", f"- INTENT `{node_id}` -> {node_status}")
        path.write_text(updated, encoding="utf-8")
        return {
            "ok": True,
            "status": "clueboard_graph_updated",
            "run_id": run_meta["run_id"],
            "path": str(path),
            "graph_path": str(graph_path),
            "node": node,
            "graph_summary": clueboard_graph_summary(graph),
        }
    else:
        return {
            "ok": False,
            "status": "invalid_clueboard_action",
            "available_actions": ["read", "graph", "append", "set_focus", "add_fact", "add_intent", "add_hint", "update_intent"],
        }
    path.write_text(updated, encoding="utf-8")
    return {
        "ok": True,
        "status": "clueboard_updated",
        "run_id": run_meta["run_id"],
        "path": str(path),
        "graph_path": str(graph_path),
        "action": action,
        "content": updated,
        "graph_summary": clueboard_graph_summary(graph),
    }

def redact_audit_snippet(value: str) -> str:
    value = re.sub(r"(?i)((?:api[_-]?key|app[_-]?secret|client[_-]?secret|password|passwd|access[_-]?token|refresh[_-]?token)\b\s*[:=]\s*)[^\s,;]{6,}", r"\1<redacted>", value)
    value = re.sub(r"[A-Za-z0-9+/=_-]{32,}", "<redacted>", value)
    value = re.sub(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", "<email>", value)
    return value.strip()[:180]


def skill_audit_tool(args: dict[str, Any]) -> dict[str, Any]:
    raw_path = str(args.get("path", "")).strip()
    if not raw_path:
        return {"ok": False, "status": "invalid_skill_path", "message": "path is required"}
    skill_root = Path(raw_path).expanduser().resolve()
    skill_md = skill_root / "SKILL.md"
    if not skill_root.is_dir() or not skill_md.is_file():
        return {"ok": False, "status": "invalid_skill_directory", "message": "The path must be a directory containing SKILL.md"}
    max_files = max(1, min(int(args.get("max_files", 200)), 500))
    max_total_bytes = max(65_536, min(int(args.get("max_total_bytes", 2_000_000)), 10_000_000))
    max_file_bytes = 512_000
    findings: list[dict[str, Any]] = []
    files_scanned = 0
    bytes_scanned = 0
    truncated = False
    rule_counts: dict[str, int] = {}
    for current_root, dirs, files in os.walk(skill_root, followlinks=False):
        dirs[:] = [name for name in dirs if name not in SKILL_AUDIT_SKIP_DIRS and not (Path(current_root) / name).is_symlink()]
        for name in files:
            source_path = Path(current_root) / name
            if source_path.is_symlink() or source_path.suffix.lower() not in SKILL_AUDIT_TEXT_EXTENSIONS:
                continue
            if files_scanned >= max_files or bytes_scanned >= max_total_bytes:
                truncated = True
                break
            try:
                size = source_path.stat().st_size
                if size > max_file_bytes:
                    continue
                content = source_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            files_scanned += 1
            bytes_scanned += len(content.encode("utf-8", errors="replace"))
            seen_rules: set[str] = set()
            for rule_id, severity, pattern, message, redact in SKILL_AUDIT_RULES:
                matches = list(pattern.finditer(content))
                if not matches:
                    continue
                rule_counts[rule_id] = rule_counts.get(rule_id, 0) + len(matches)
                if rule_id in seen_rules:
                    continue
                seen_rules.add(rule_id)
                first = matches[0]
                line_number = content.count("\n", 0, first.start()) + 1
                line_text = content.splitlines()[line_number - 1] if content.splitlines() else ""
                excerpt = "<redacted>" if redact else redact_audit_snippet(line_text)
                findings.append({
                    "rule_id": rule_id,
                    "severity": severity,
                    "path": str(source_path.relative_to(skill_root)),
                    "line": line_number,
                    "message": message,
                    "occurrences": len(matches),
                    "excerpt": excerpt,
                })
        if truncated:
            break
    weight = {"critical": 35, "high": 20, "medium": 8, "low": 3, "info": 1}
    score = 100
    for rule_id, count in rule_counts.items():
        severity = next((item[1] for item in SKILL_AUDIT_RULES if item[0] == rule_id), "info")
        score -= weight.get(severity, 1) * min(count, 3)
    score = max(0, min(100, score))
    critical_count = sum(1 for finding in findings if finding["severity"] == "critical")
    if critical_count:
        score = min(score, 29)
    if score >= 90:
        grade = "S+"
    elif score >= 80:
        grade = "S"
    elif score >= 65:
        grade = "A"
    elif score >= 50:
        grade = "B"
    elif score >= 30:
        grade = "C"
    else:
        grade = "D"
    severity_counts = {level: sum(1 for finding in findings if finding["severity"] == level) for level in ["critical", "high", "medium", "low", "info"]}
    return {
        "ok": True,
        "status": "skill_audit",
        "path": str(skill_root),
        "score": score,
        "grade": grade,
        "findings": findings,
        "finding_counts": severity_counts,
        "rule_counts": rule_counts,
        "scan": {
            "files_scanned": files_scanned,
            "bytes_scanned": bytes_scanned,
            "max_files": max_files,
            "max_total_bytes": max_total_bytes,
            "truncated": truncated,
            "text_extensions": sorted(SKILL_AUDIT_TEXT_EXTENSIONS),
        },
        "notes": [
            "Static pre-install audit only; it is not a security certification.",
            "Review every finding in context and inspect runtime behavior in an isolated environment before trusting a third-party skill.",
            "Do not paste full secrets into the report; excerpts are redacted by the scanner.",
        ],
    }

INSTALL_REGISTRY: dict[str, list[str]] = {
    "httpx": ["go", "install", "github.com/projectdiscovery/httpx/cmd/httpx@latest"],
    "subfinder": ["go", "install", "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"],
    "dnsx": ["go", "install", "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"],
    "katana": ["go", "install", "github.com/projectdiscovery/katana/cmd/katana@latest"],
    "nuclei": ["go", "install", "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"],
    "gau": ["go", "install", "github.com/lc/gau/v2/cmd/gau@latest"],
    "ffuf": ["go", "install", "github.com/ffuf/ffuf/v2@latest"],
    "python-deps": ["python", "-m", "pip", "install", "-r", str(BASE_DIR / "requirements.txt")],
}


def intel_status_tool(_: dict[str, Any]) -> dict[str, Any]:
    return {"ok": True, "status": "ok", "providers": intel_provider_status()}


def tool_status(_: dict[str, Any]) -> dict[str, Any]:
    names = ["python", "node", "go", "httpx", "subfinder", "dnsx", "katana", "nuclei", "gau", "ffuf", "burp", "caido"]
    tools: dict[str, Any] = {}
    for name in names:
        path = shutil.which(name)
        info: dict[str, Any] = {"path": path, "available": bool(path)}
        if name == "httpx" and path:
            try:
                probe = subprocess.run([path, "-version"], capture_output=True, text=True, timeout=5)
                flavor_text = (probe.stdout + " " + probe.stderr).lower()
                info["flavor"] = "projectdiscovery" if "projectdiscovery" in flavor_text else "non-projectdiscovery"
            except Exception as exc:  # noqa: BLE001 - tool detection must not fail the workflow
                info["flavor"] = "unknown"
                info["probe_error"] = str(exc)
        tools[name] = info
    missing = [name for name, info in tools.items() if not info.get("available")]
    return {
        "ok": True,
        "status": "ok",
        "mcp_server": str(Path(__file__).resolve()),
        "tools": tools,
        "missing": missing,
        "notes": "A non-projectdiscovery httpx binary is not the ProjectDiscovery recon tool; install the allowlisted httpx if needed.",
    }


def install_tool(args: dict[str, Any]) -> dict[str, Any]:
    name = str(args.get("tool", "")).strip().lower()
    confirm = bool(args.get("confirm", False))
    if name not in INSTALL_REGISTRY:
        return {"ok": False, "status": "unsupported_tool", "message": f"Allowed tools: {', '.join(sorted(INSTALL_REGISTRY))}"}
    command = INSTALL_REGISTRY[name]
    if command[0] == "python":
        command = [sys.executable, *command[1:]]
    if not confirm:
        return {"ok": True, "status": "confirmation_required", "tool": name, "command": command}
    try:
        result = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=900)
    except Exception as exc:  # noqa: BLE001 - surface installer failures
        return {"ok": False, "status": "install_failed", "tool": name, "message": str(exc)}
    return {
        "ok": result.returncode == 0,
        "status": "installed" if result.returncode == 0 else "install_failed",
        "tool": name,
        "stdout": result.stdout[-8000:],
        "stderr": result.stderr[-8000:],
    }

def input_schema(properties: dict[str, Any], required: list[str] | None = None) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": properties,
        "required": required or [],
        "additionalProperties": False,
    }


TOOL_DEFINITIONS = [
    {
        "name": "src_start",
        "description": "Create an authorized run, perform passive DNS/CT reconnaissance, and collect one low-impact GET baseline. Requires explicit authorization_confirmed=true.",
        "inputSchema": input_schema({
            "asset": {"type": "string", "description": "Explicitly authorized absolute URL"},
            "program": {"type": "string", "description": "SRC program name"},
            "policy_url": {"type": "string", "description": "Program policy or scope URL"},
            "authorization_confirmed": {"type": "boolean"},
            "platform": {"type": "string"},
            "contact": {"type": "string"},
            "operator": {"type": "string"},
            "scope": {"type": "object", "description": "Optional minimal scope override"},
            "include_recon": {"type": "boolean", "default": True},
            "baseline": {"type": "boolean", "default": True},
            "save_baseline_body": {"type": "boolean", "default": False},
            "accounts": {"type": "array", "items": {"type": "object"}},
        }, ["asset", "program", "policy_url", "authorization_confirmed"]),
    },
    {
        "name": "src_prepare_run",
        "description": "Create a scoped run without sending target traffic.",
        "inputSchema": input_schema({
            "asset": {"type": "string"},
            "program": {"type": "string"},
            "policy_url": {"type": "string"},
            "authorization_confirmed": {"type": "boolean"},
            "platform": {"type": "string"},
            "contact": {"type": "string"},
            "operator": {"type": "string"},
            "scope": {"type": "object"},
            "accounts": {"type": "array", "items": {"type": "object"}},
        }, ["asset", "program", "policy_url", "authorization_confirmed"]),
    },
    {
        "name": "src_passive_recon",
        "description": "Collect DNS, certificate-transparency, and passive observations for a prepared run. Does not send requests to the target.",
        "inputSchema": input_schema({
            "run_id": {"type": "string"},
            "include_dns": {"type": "boolean", "default": True},
            "include_ct": {"type": "boolean", "default": True},
        }, ["run_id"]),
    },
    {
        "name": "src_asset_intel",
        "description": "Query configured passive asset-intelligence providers such as FOFA, Shodan, Quake, Hunter, ZoomEye, and urlscan. Results are leads and are marked in_scope or out-of-scope.",
        "inputSchema": input_schema({
            "run_id": {"type": "string"},
            "query": {"type": "string"},
            "providers": {"type": "array", "items": {"enum": ["fofa", "shodan", "quake", "hunter", "zoomeye", "urlscan"]}},
            "max_results": {"type": "integer", "minimum": 1, "maximum": 50, "default": 20},
        }, ["run_id", "query"]),
    },
    {
        "name": "src_intel_status",
        "description": "Show which passive intelligence provider API keys are configured.",
        "inputSchema": input_schema({}),
    },
    {
        "name": "src_js_inventory",
        "description": "Fetch the baseline page and a bounded set of in-scope JavaScript assets, then inventory endpoints, parameters, and source maps. Requires a batch approval code.",
        "inputSchema": input_schema({
            "run_id": {"type": "string"},
            "asset": {"type": "string"},
            "max_assets": {"type": "integer", "minimum": 1, "maximum": 20, "default": 10},
            "approval_code": {"type": "string"},
            "approval_note": {"type": "string"},
        }, ["run_id"]),
    },
    {
        "name": "src_import_har",
        "description": "Import a browser or Burp HAR file stored inside the run directory and build an in-scope endpoint and parameter inventory.",
        "inputSchema": input_schema({
            "run_id": {"type": "string"},
            "har_path": {"type": "string"},
        }, ["run_id", "har_path"]),
    },
    {
        "name": "src_path_probe",
        "description": "Probe 1-25 supplied paths with rate limiting and a batch approval code. It does not use a wordlist or brute force.",
        "inputSchema": input_schema({
            "run_id": {"type": "string"},
            "base_url": {"type": "string"},
            "paths": {"type": "array", "minItems": 1, "maxItems": 25, "items": {"type": "string"}},
            "method": {"type": "string", "enum": ["GET", "HEAD"], "default": "GET"},
            "approval_code": {"type": "string"},
            "approval_note": {"type": "string"},
        }, ["run_id", "paths"]),
    },
    {
        "name": "src_port_probe",
        "description": "Check 1-20 explicitly scoped ports with a batch approval code. Ports must already be allowed by scope.",
        "inputSchema": input_schema({
            "run_id": {"type": "string"},
            "ports": {"type": "array", "minItems": 1, "maxItems": 20, "items": {"type": "integer", "minimum": 1, "maximum": 65535}},
            "approval_code": {"type": "string"},
            "approval_note": {"type": "string"},
        }, ["run_id", "ports"]),
    },
    {
        "name": "src_check_scope",
        "description": "Check a URL and method against the active run scope.",
        "inputSchema": input_schema({
            "run_id": {"type": "string"},
            "url": {"type": "string"},
            "method": {"type": "string", "default": "GET"},
        }, ["run_id", "url"]),
    },
    {
        "name": "src_http",
        "description": "Send one scoped request via the guarded HTTP wrapper. Defaults to dry-run; high-risk or write operations require a chat approval code.",
        "inputSchema": input_schema({
            "run_id": {"type": "string"},
            "url": {"type": "string"},
            "method": {"type": "string", "default": "GET"},
            "risk": {"type": "string", "default": "standard"},
            "execute": {"type": "boolean", "default": False},
            "save_body": {"type": "boolean", "default": False},
            "max_body": {"type": "integer", "minimum": 1024, "maximum": 20000000},
            "headers": {"type": "object", "additionalProperties": {"type": "string"}},
            "approval_code": {"type": "string"},
            "approval_note": {"type": "string"},
        }, ["run_id", "url"]),
    },
    {
        "name": "src_request_approval",
        "description": "Create a pending chat approval request for a write or high-risk operation.",
        "inputSchema": input_schema({
            "run_id": {"type": "string"},
            "method": {"type": "string"},
            "risk": {"type": "string"},
            "url": {"type": "string"},
            "reason": {"type": "string"},
            "max_uses": {"type": "integer", "minimum": 1, "maximum": 100, "default": 1},
        }, ["run_id", "method", "risk", "url", "reason"]),
    },
    {
        "name": "src_confirm_approval",
        "description": "Confirm a pending approval only after the human replies with the exact APPROVE <code> phrase.",
        "inputSchema": input_schema({
            "run_id": {"type": "string"},
            "approval_code": {"type": "string"},
            "user_confirmation": {"type": "string"},
        }, ["run_id", "approval_code", "user_confirmation"]),
    },
    {
        "name": "src_save_finding",
        "description": "Save and schema-check a candidate or verified finding in the run directory.",
        "inputSchema": input_schema({
            "run_id": {"type": "string"},
            "finding": {"type": "object"},
        }, ["run_id", "finding"]),
    },
    {
        "name": "src_validate_finding",
        "description": "Run the evidence and schema gate for a saved finding.",
        "inputSchema": input_schema({
            "run_id": {"type": "string"},
            "finding_id": {"type": "string"},
        }, ["run_id", "finding_id"]),
    },
    {
        "name": "src_render_report",
        "description": "Render a human-reviewable Markdown report from a validated finding.",
        "inputSchema": input_schema({
            "run_id": {"type": "string"},
            "finding_id": {"type": "string"},
            "output": {"type": "string"},
        }, ["run_id", "finding_id"]),
    },
    {
        "name": "src_status",
        "description": "Show run state, request count, findings, and approval status.",
        "inputSchema": input_schema({"run_id": {"type": "string"}}, ["run_id"]),
    },
    {
        "name": "src_tool_status",
        "description": "Detect which local reconnaissance and testing tools are available.",
        "inputSchema": input_schema({}),
    },
    {
        "name": "src_vuln_playbook",
        "description": "Return vulnerability classification and safe detection guidance by class ID, keyword, or priority.",
        "inputSchema": input_schema({
            "class_id": {"type": "string", "description": "Playbook ID, for example idor_bola or ssrf"},
            "query": {"type": "string", "description": "Keyword such as JWT, upload, tenant, or GraphQL"},
            "priority": {"type": "string", "enum": ["critical", "high", "medium", "low"]},
        }),
    },
    {
        "name": "src_hunt_route",
        "description": "Route a feature, technology, or observed signal to the relevant expert workflow, playbook classes, tools, and evidence gates.",
        "inputSchema": input_schema({
            "query": {"type": "string", "description": "Feature or signal, for example JWT login, webpack source map, file upload, or blocked by WAF"},
            "route_id": {"type": "string", "description": "Exact expert route ID, for example recon-js-analysis or auth-access-control"},
            "max_routes": {"type": "integer", "minimum": 1, "maximum": 3, "default": 1, "description": "Return only the best route by default; increase only when ambiguity is material."},
        }),
    },
    {
        "name": "src_clueboard",
        "description": "Read the Markdown clueboard or update its Markdown sections and Fact-Intent-Hint graph without writing outside the run directory.",
        "inputSchema": input_schema({
            "run_id": {"type": "string"},
            "action": {"type": "string", "enum": ["read", "graph", "append", "set_focus", "add_fact", "add_intent", "add_hint", "update_intent"], "default": "read"},
            "section": {"type": "string", "enum": sorted(CLUEBOARD_SECTIONS)},
            "status": {"type": "string", "enum": sorted(CLUEBOARD_STATUSES)},
            "node_status": {"type": "string", "enum": sorted(CLUEBOARD_GRAPH_STATUSES)},
            "node_id": {"type": "string"},
            "related_ids": {"type": "array", "items": {"type": "string"}},
            "evidence": {"type": "string"},
            "content": {"type": "string", "maxLength": 4000},
        }, ["run_id"]),
    },
    {
        "name": "src_skill_audit",
        "description": "Statically audit a local Skill directory before installation. Detects risky execution, approval bypass, prompt injection, secret, exfiltration, and obfuscation patterns; this is not a security certification.",
        "inputSchema": input_schema({
            "path": {"type": "string", "description": "Directory containing SKILL.md"},
            "max_files": {"type": "integer", "minimum": 1, "maximum": 500, "default": 200},
            "max_total_bytes": {"type": "integer", "minimum": 65536, "maximum": 10000000, "default": 2000000},
        }, ["path"]),
    },
    {
        "name": "src_install_tool",
        "description": "Install one allowlisted official tool after explicit user confirmation.",
        "inputSchema": input_schema({
            "tool": {"type": "string", "enum": sorted(INSTALL_REGISTRY)},
            "confirm": {"type": "boolean", "default": False},
        }, ["tool"]),
    },
]


def check_scope_tool(args: dict[str, Any]) -> dict[str, Any]:
    run_dir, run_meta = load_run(str(args.get("run_id", "")))
    scope = load_scope_for_run(run_dir, run_meta)
    decision = evaluate_url(scope, str(args.get("url", "")), str(args.get("method", "GET")))
    return {"ok": decision.allowed, "status": "in_scope" if decision.allowed else "blocked", "decision": decision.as_dict()}


TOOL_HANDLERS: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
    "src_start": start_workflow,
    "src_prepare_run": prepare_run,
    "src_passive_recon": passive_recon,
    "src_asset_intel": asset_intel,
    "src_intel_status": intel_status_tool,
    "src_js_inventory": js_inventory,
    "src_import_har": import_har,
    "src_path_probe": path_probe,
    "src_port_probe": port_probe,
    "src_check_scope": check_scope_tool,
    "src_http": guarded_http,
    "src_request_approval": request_approval,
    "src_confirm_approval": confirm_approval,
    "src_save_finding": save_finding,
    "src_validate_finding": validate_finding_tool,
    "src_render_report": render_report_tool,
    "src_status": workflow_status,
    "src_tool_status": tool_status,
    "src_vuln_playbook": vuln_playbook,
    "src_hunt_route": hunt_route,
    "src_clueboard": clueboard_tool,
    "src_skill_audit": skill_audit_tool,
    "src_install_tool": install_tool,
}


def tools_list() -> dict[str, Any]:
    return {"tools": TOOL_DEFINITIONS}


def tools_call(params: dict[str, Any]) -> dict[str, Any]:
    name = str(params.get("name", ""))
    arguments = params.get("arguments") or {}
    handler = TOOL_HANDLERS.get(name)
    if not handler:
        return {"content": [{"type": "text", "text": f"Unknown tool: {name}"}], "isError": True}
    started = time.monotonic()
    try:
        result = handler(arguments)
    except Exception as exc:  # noqa: BLE001 - MCP must return structured tool failures
        result = {"ok": False, "status": "tool_error", "message": str(exc)}
    response_text = compact(result)
    elapsed_ms = round((time.monotonic() - started) * 1000, 1)
    try:
        MCP_CALL_LOG.parent.mkdir(parents=True, exist_ok=True)
        with MCP_CALL_LOG.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps({
                "timestamp": utc_now(),
                "tool": name,
                "ok": bool(result.get("ok", False)),
                "status": result.get("status"),
                "result_type": result.get("result_type"),
                "elapsed_ms": elapsed_ms,
                "response_chars": len(response_text),
            }, ensure_ascii=False) + "\n")
    except OSError:
        pass
    return {
        "content": [{"type": "text", "text": response_text}],
        "structuredContent": result,
        "isError": not bool(result.get("ok", False)),
    }


def handle_message(message: dict[str, Any]) -> dict[str, Any] | None:
    method = message.get("method")
    request_id = message.get("id")
    if method == "initialize":
        requested = (message.get("params") or {}).get("protocolVersion") or "2025-06-18"
        return {"jsonrpc": "2.0", "id": request_id, "result": {
            "protocolVersion": requested,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "src-guarded-workflow", "version": SERVER_VERSION},
        }}
    if method == "notifications/initialized":
        return None
    if method == "ping":
        return {"jsonrpc": "2.0", "id": request_id, "result": {}}
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": request_id, "result": tools_list()}
    if method == "tools/call":
        return {"jsonrpc": "2.0", "id": request_id, "result": tools_call(message.get("params") or {})}
    if request_id is None:
        return None
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": -32601, "message": f"Method not found: {method}"}}


def read_messages():
    stream = sys.stdin.buffer
    while True:
        line = stream.readline()
        if not line:
            break
        if line.lower().startswith(b"content-length:"):
            try:
                length = int(line.split(b":", 1)[1].strip())
                stream.readline()
                body = stream.read(length)
                if body:
                    yield json.loads(body)
            except Exception:
                continue
        else:
            text = line.decode("utf-8", errors="replace").strip()
            if text:
                try:
                    yield json.loads(text)
                except json.JSONDecodeError:
                    continue


def main() -> int:
    for message in read_messages():
        if not isinstance(message, dict):
            continue
        response = handle_message(message)
        if response is not None:
            sys.stdout.write(json.dumps(response, ensure_ascii=False) + "\n")
            sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())





















