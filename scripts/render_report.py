#!/usr/bin/env python3
"""Render a human-reviewable Markdown report from a validated finding."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys
from string import Template

sys.path.insert(0, str(Path(__file__).resolve().parent))

ROOT = Path(__file__).resolve().parent.parent
TEMPLATE_PATH = ROOT / "templates" / "report.md"


def bullets(items: list[str], prefix: str = "- ") -> str:
    return "\n".join(prefix + item for item in items) if items else "- None recorded"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--finding", required=True, help="Verified finding JSON")
    parser.add_argument("--run-dir", required=True, help="Run directory")
    parser.add_argument("--output", help="Output Markdown path")
    args = parser.parse_args()

    finding_path = Path(args.finding).resolve()
    run_dir = Path(args.run_dir).resolve()
    validator = Path(__file__).with_name("validate_finding.py")
    check = subprocess.run(
        [sys.executable, str(validator), "--finding", str(finding_path), "--run-dir", str(run_dir)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if check.returncode != 0:
        print("REPORT BLOCKED: finding did not pass validation", file=sys.stderr)
        print(check.stdout, file=sys.stderr)
        print(check.stderr, file=sys.stderr)
        return 1

    finding = json.loads(finding_path.read_text(encoding="utf-8"))
    if finding.get("status") != "verified":
        print("REPORT BLOCKED: only verified findings can be rendered", file=sys.stderr)
        return 1

    evidence_lines = []
    for item in finding.get("evidence", []):
        line = f"- `{item.get('path')}` — {item.get('description')}"
        if item.get("sha256"):
            line += f" (sha256: `{item['sha256']}`)"
        evidence_lines.append(line)
    reviewer = finding.get("reviewer") or {}
    values = {
        "title": finding.get("title", "Untitled finding"),
        "summary": finding.get("summary", ""),
        "program": finding.get("program", ""),
        "asset": finding.get("asset", ""),
        "method": finding.get("method", ""),
        "vulnerability_class": finding.get("vulnerability_class", ""),
        "severity": finding.get("severity", ""),
        "preconditions": bullets(finding.get("preconditions", [])),
        "reproduction_steps": "\n".join(
            f"{index}. {step}" for index, step in enumerate(finding.get("reproduction_steps", []), start=1)
        ) or "1. None recorded",
        "evidence": "\n".join(evidence_lines) or "- None recorded",
        "impact": finding.get("impact", ""),
        "remediation": finding.get("remediation", ""),
        "reviewer_notes": reviewer.get("notes", "No reviewer notes recorded."),
    }
    template = Template(TEMPLATE_PATH.read_text(encoding="utf-8"))
    content = template.substitute(values)
    output = Path(args.output) if args.output else run_dir / "reports" / f"{finding['finding_id']}.md"
    output = output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(content, encoding="utf-8")
    print(str(output))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
