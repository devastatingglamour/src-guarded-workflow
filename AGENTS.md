# Authorized SRC Workflow Rules

This workspace implements a human-gated black-box security testing workflow for explicitly authorized SRC programs.

## Preferred interface

When the `srcGuardedWorkflow` MCP server is available, use its tools (`src_start`, `src_clueboard`, `src_hunt_route`, `src_http`, `src_request_approval`, `src_confirm_approval`, `src_validate_finding`, `src_render_report`) instead of asking the user to run command-line tools. The scripts in this directory are the deterministic fallback and test surface.

The user should be able to provide a program, policy URL, and authorized asset in chat, then let the MCP workflow perform scoped setup, passive reconnaissance, and the low-impact baseline. Do not turn that into a list of shell commands.

## Non-negotiable boundaries

- Test only assets explicitly listed in the active `scope.yaml`.
- Read the target program's current policy before any active request. If the policy and local configuration conflict, use the stricter rule and stop.
- Never test a public host merely because it is reachable. Public availability is not authorization.
- Do not run batch scans, brute force, password spraying, DoS, stress tests, persistence, lateral movement, or destructive payloads.
- Do not access, download, retain, or report real user data. Use test accounts and the minimum evidence needed to prove impact.
- Do not deploy shells, backdoors, scheduled tasks, or persistence.
- Do not contact users, customers, employees, or third parties outside the program's approved channel.
- Do not publish or share target information without written authorization.

## Required execution path

1. Confirm that `scope.yaml` exists, belongs to the current program, and has `authorization_confirmed: true`.
2. Create a run with `scripts/new_run.py`; this also creates `CLUEBOARD.md`.
3. Read the clueboard and set one concrete current focus before active testing.
4. Use `scripts/guarded_http.py` for all target HTTP traffic. It enforces host/path/method scope, rate limits, redirect checks, redaction, and approval gates.
5. Start with passive reconnaissance and read-only requests (`GET`, `HEAD`, `OPTIONS`).
6. Use `src_hunt_route` to select the expert knowledge route and its playbook classes.
7. Record findings as `candidate` first. A candidate is a hypothesis, not a vulnerability.
8. Before a write request or high-risk validation, stop and obtain explicit human approval. The user must provide the approval token from their own shell; never read, print, generate, or infer it.
9. Use an independent reviewer pass to falsify the finding: verify scope, request/response evidence, reproducibility, impact, data minimization, and possible duplication.
10. Write hypotheses, negative evidence, and coverage back to the clueboard in the same turn.
11. Run `scripts/validate_finding.py` before rendering a report.
12. Never submit a report automatically. The human operator must review and submit it.

- Before installing a third-party Skill or plugin, use `src_skill_audit`, inspect the findings, and require human approval before execution.

## Tool policy

- `scripts/guarded_http.py` is the default and required HTTP client.
- Do not bypass it with `curl`, `Invoke-WebRequest`, direct browser automation, or ad hoc scripts for target traffic.
- `subfinder`, `httpx`, `dnsx`, `katana`, `gau`, `ffuf`, and `nuclei` are optional discovery aids, not authorization. Use them only when the program rules allow the specific activity and the human operator has approved the run.
- Scanners produce leads only. Never report a scanner match as a confirmed vulnerability.
- Burp Suite or Caido may be used for manual review and evidence capture, but requests must remain within scope and rate limits.

## Evidence rules

- A verified finding must have an actual request/response pair, reproduction steps, preconditions, a concrete impact statement, and a human verification marker.
- Try to falsify normal behavior before treating a signal as a defect; record the control test in CLUEBOARD.md.
- Never invent a request, response, status code, screenshot, payload, timestamp, or impact.
- Redact cookies, authorization headers, API keys, CSRF tokens, session identifiers, and personal data.
- If evidence suggests access to another tenant, another user, internal infrastructure, credentials, or sensitive production data, stop immediately and preserve only the minimum proof required by the program.

## Stop conditions

Stop and report back to the human operator when any of these occurs:

- A request or redirect would leave the configured scope.
- The target returns data that appears to belong to a real user or another tenant.
- The target shows signs of instability, rate limiting, or business impact.
- A test would require a write, upload, auth challenge, SSRF, deserialization, credential use, or exploit chaining.
- You are unsure whether the program permits the action.

## Output contract

Every run lives under `runs/<program>/<timestamp>/` with `evidence/`, `candidates/`, `reports/`, `logs/`, `run.json`, `notes.md`, `CLUEBOARD.md`, and `attack-surface.md`. Findings use the schema in `schemas/finding.schema.json`.


