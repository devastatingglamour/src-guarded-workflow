#!/usr/bin/env python3
"""Create a new isolated run directory for one authorized SRC session."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))

from scope_rules import ScopeError, load_scope  # noqa: E402


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def slug(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", value.strip()).strip("-")
    return cleaned or "program"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scope", required=True, help="Active scope YAML")
    parser.add_argument("--program", help="Program name; defaults to scope.program.name")
    parser.add_argument("--operator", default="local-operator", help="Operator label, not a credential")
    parser.add_argument("--output-root", default="runs", help="Directory where run folders are created")
    parser.add_argument("--date", help="Optional UTC timestamp label, primarily for tests")
    args = parser.parse_args()

    try:
        scope = load_scope(args.scope)
    except ScopeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    program_name = args.program or str(scope.get("program", {}).get("name", "program"))
    program_slug = slug(program_name)
    timestamp = args.date or datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    timestamp = slug(timestamp)
    run_dir = Path(args.output_root).resolve() / program_slug / timestamp
    if run_dir.exists():
        print(f"ERROR: run directory already exists: {run_dir}", file=sys.stderr)
        return 2

    for child in ["evidence", "candidates", "reports", "logs"]:
        (run_dir / child).mkdir(parents=True, exist_ok=False if child == "evidence" else True)

    scope_path = Path(args.scope).resolve()
    scope_hash = hashlib.sha256(scope_path.read_bytes()).hexdigest()
    run_meta = {
        "schema_version": 1,
        "run_id": f"{program_slug}/{timestamp}",
        "program": program_name,
        "platform": scope.get("program", {}).get("platform"),
        "policy_url": scope.get("program", {}).get("policy_url"),
        "authorization_confirmed": scope.get("authorization_confirmed") is True,
        "scope_file": str(scope_path),
        "scope_sha256": scope_hash,
        "operator": args.operator,
        "created_at": utc_now(),
        "status": "planning",
        "request_count": 0,
        "finding_counts": {"candidate": 0, "verified": 0, "rejected": 0},
    }
    (run_dir / "run.json").write_text(json.dumps(run_meta, ensure_ascii=False, indent=2), encoding="utf-8")

    attack_surface = """# Attack Surface

## Observed facts

- Add only facts supported by public information or actual in-scope responses.

## Candidate areas

- [ ] Authentication and session handling
- [ ] Authorization and tenant boundaries
- [ ] API and object-level access control
- [ ] Business logic and workflow state
- [ ] File handling and upload paths
- [ ] Server-side request paths
- [ ] Client-side rendering and data exposure

## Out-of-scope or blocked

- Record anything intentionally not tested and why.
"""
    (run_dir / "attack-surface.md").write_text(attack_surface, encoding="utf-8")

    notes = """# Run Notes

## Authorization

- Program policy reviewed:
- Scope reviewed:
- Test window:
- Operator:

## Decisions and approvals

- 

## Blockers

- 

## Timeline

- 
"""
    (run_dir / "notes.md").write_text(notes, encoding="utf-8")

    clueboard_template = Path(__file__).resolve().parent.parent / "templates" / "clueboard.md"
    clueboard = clueboard_template.read_text(encoding="utf-8")
    allowed_hosts = scope.get("scope", {}).get("allowed_hosts", [])
    target_label = str(allowed_hosts[0]) if allowed_hosts else program_name
    clueboard = clueboard.replace("# Hunt Clueboard - <target>", f"# Hunt Clueboard - {target_label}")
    clueboard = clueboard.replace("- Program:", f"- Program: {program_name}")
    clueboard = clueboard.replace("- Asset:", f"- Asset: {target_label}")
    clueboard = clueboard.replace("- Policy:", f"- Policy: {scope.get('program', {}).get('policy_url', '')}")
    clueboard = clueboard.replace("- Authorization:", f"- Authorization: {scope.get('authorization_confirmed') is True}")
    (run_dir / "CLUEBOARD.md").write_text(clueboard, encoding="utf-8")
    clueboard_graph = {
        "schema_version": 1,
        "origin": target_label,
        "goal": "Find and verify an authorized, reproducible, reportable security finding without leaving scope.",
        "facts": [],
        "intents": [],
        "hints": [],
        "created_at": utc_now(),
        "updated_at": utc_now(),
    }
    (run_dir / "CLUEBOARD.json").write_text(json.dumps(clueboard_graph, ensure_ascii=False, indent=2), encoding="utf-8")
    (run_dir / "logs" / "requests.jsonl").touch()
    (run_dir / "logs" / "approvals.jsonl").touch()
    print(str(run_dir))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
