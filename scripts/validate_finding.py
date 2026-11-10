#!/usr/bin/env python3
"""Validate a finding against the schema and the workflow evidence gate."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))

from jsonschema import Draft202012Validator, ValidationError  # noqa: E402
from scope_rules import ScopeError, load_scope  # noqa: E402


ROOT = Path(__file__).resolve().parent.parent
SCHEMA_PATH = ROOT / "schemas" / "finding.schema.json"


def add(errors: list[str], message: str) -> None:
    errors.append(message)


def load_scope_from_run(run_dir: Path) -> dict:
    run_meta = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
    scope_path = Path(str(run_meta.get("scope_file", "")))
    if not scope_path.is_absolute():
        scope_path = (run_dir / scope_path).resolve()
    return load_scope(scope_path)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--finding", required=True, help="Finding JSON file")
    parser.add_argument("--run-dir", help="Run directory for evidence and scope checks")
    parser.add_argument("--json", action="store_true", help="Print machine-readable output")
    args = parser.parse_args()

    finding_path = Path(args.finding).resolve()
    errors: list[str] = []
    warnings: list[str] = []
    try:
        finding = json.loads(finding_path.read_text(encoding="utf-8"))
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        Draft202012Validator(schema).validate(finding)
    except (OSError, json.JSONDecodeError, ValidationError) as exc:
        result = {"valid": False, "errors": [f"Schema or JSON error: {exc}"], "warnings": []}
        print(json.dumps(result, ensure_ascii=False, indent=2) if args.json else str(exc))
        return 1

    status = finding.get("status")
    if status == "verified":
        if finding.get("human_verified") is not True:
            add(errors, "verified finding requires human_verified=true")
        if finding.get("in_scope") is not True:
            add(errors, "verified finding requires in_scope=true")
        if finding.get("confidence") != "high":
            add(errors, "verified finding requires confidence=high")
        if not finding.get("preconditions"):
            add(errors, "verified finding requires at least one precondition")
        if not finding.get("reproduction_steps"):
            add(errors, "verified finding requires reproduction steps")
        if not finding.get("impact"):
            add(errors, "verified finding requires an impact statement")
        reviewer = finding.get("reviewer") or {}
        if reviewer.get("status") != "passed":
            add(errors, "verified finding requires reviewer.status=passed")
        if not args.run_dir:
            add(errors, "--run-dir is required for a verified finding")
        if finding.get("data_sensitivity") == "real_user" and not finding.get("real_user_data_approved"):
            add(errors, "real_user data requires explicit real_user_data_approved=true")
        if not finding.get("evidence"):
            add(errors, "verified finding requires at least one evidence entry")

    if args.run_dir:
        run_dir = Path(args.run_dir).resolve()
        if not (run_dir / "run.json").is_file():
            add(errors, f"run.json not found in {run_dir}")
        try:
            scope = load_scope_from_run(run_dir)
            if finding.get("data_sensitivity") == "real_user" and not scope.get("data", {}).get("allow_real_user_data", False):
                add(errors, "scope.data.allow_real_user_data is false")
        except (OSError, json.JSONDecodeError, ScopeError) as exc:
            add(errors, f"Unable to load run scope: {exc}")

        for index, evidence in enumerate(finding.get("evidence", [])):
            raw_path = str(evidence.get("path", ""))
            evidence_path = (run_dir / raw_path).resolve()
            try:
                evidence_path.relative_to(run_dir)
            except ValueError:
                add(errors, f"evidence[{index}] escapes the run directory: {raw_path}")
                continue
            if not evidence_path.is_file():
                add(errors, f"evidence[{index}] does not exist: {raw_path}")
                continue
            expected_hash = evidence.get("sha256")
            if status == "verified" and not expected_hash:
                add(errors, f"evidence[{index}] requires sha256 for a verified finding")
            if expected_hash:
                actual_hash = hashlib.sha256(evidence_path.read_bytes()).hexdigest()
                if actual_hash.lower() != str(expected_hash).lower():
                    add(errors, f"evidence[{index}] sha256 does not match: {raw_path}")
    elif status == "verified":
        add(errors, "verified finding requires evidence hash verification with --run-dir")

    result = {
        "valid": not errors,
        "finding_id": finding.get("finding_id"),
        "status": status,
        "errors": errors,
        "warnings": warnings,
    }
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print("VALID" if not errors else "INVALID")
        for item in errors:
            print(f"ERROR: {item}")
        for item in warnings:
            print(f"WARNING: {item}")
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
