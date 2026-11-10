#!/usr/bin/env python3
"""Check whether a URL and method are inside an authorized scope."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

# Allow direct execution from the project root and from scripts/.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from scope_rules import ScopeError, evaluate_url, load_scope  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scope", required=True, help="Path to the active scope YAML")
    parser.add_argument("--url", required=True, help="URL to check")
    parser.add_argument("--method", default="GET", help="HTTP method to check")
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON")
    args = parser.parse_args()

    try:
        scope = load_scope(args.scope)
        decision = evaluate_url(scope, args.url, args.method)
    except ScopeError as exc:
        result = {"allowed": False, "reason": str(exc), "url": args.url, "method": args.method.upper()}
        if args.json:
            print(json.dumps(result, ensure_ascii=False, indent=2))
        else:
            print(f"BLOCKED: {exc}")
        return 3

    if args.json:
        print(json.dumps(decision.as_dict(), ensure_ascii=False, indent=2))
    else:
        state = "ALLOWED" if decision.allowed else "BLOCKED"
        print(f"{state}: {decision.reason}")
        print(f"  {decision.method} {decision.url}")
        print(f"  host={decision.host} port={decision.port} path={decision.path}")
    return 0 if decision.allowed else 2


if __name__ == "__main__":
    raise SystemExit(main())
