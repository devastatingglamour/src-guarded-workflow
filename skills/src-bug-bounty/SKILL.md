---
name: src-bug-bounty
description: Runs an authorized SRC asset from a chat-provided URL through scoped setup, a cross-session clueboard, JS/API reconnaissance, expert route selection, human-gated validation, evidence checks, and report drafting. Use when the user provides a domestic SRC asset, asks for black-box Web/API reconnaissance, or wants Codex to operate an authorized bug bounty workflow without manually running CLI tools.
---

# SRC Guarded Workflow

## Chat-first experience

The user should normally provide only:

- The SRC program name or policy URL.
- One asset URL or host that is explicitly in scope.
- Confirmation that the asset is authorized.

Do not make the user type shell commands. Use the `srcGuardedWorkflow` MCP tools for setup, reconnaissance, requests, evidence, validation, and report drafting.

## Mandatory first step

If the user provides an asset without a program/policy and authorization confirmation, ask one concise question:

> 请给我这个资产所属的 SRC 项目/规则链接，并确认该资产在授权范围内；确认后我会自动建立范围并开始被动侦察。

Never begin active requests merely because a host is publicly reachable.

## One-message start

When the program, asset, and authorization are present, call `src_start` with the asset, program, policy URL, `authorization_confirmed: true`, and an optional minimal scope override.

Then summarize:

- Run ID and output directory.
- `CLUEBOARD.md` path and the current focus.
- DNS/IP observations.
- Certificate-transparency observations, if available.
- Baseline HTTP status and security-relevant headers.
- Candidate attack-surface areas, separated into observed facts and hypotheses.

## Clueboard and expert routing

Use `src_clueboard` as the run-level working memory:

- Read it before the first active action in a target session.
- Set one concrete current focus.
- Append durable hosts, paths, authentication notes, hypotheses, and negative evidence in the same turn.
- Never store full cookies, tokens, credentials, HARs, JS bundles, or real user data.

Before testing a feature, call `src_hunt_route` with the feature or observed signal. Then call `src_vuln_playbook` with a returned class ID or a narrower keyword. Use the returned `signals`, `safe_tests`, `confirm`, and `false_positives`; do not invent a generic checklist when a specific playbook exists.

Routes marked `manual_only` are handoffs. Do not pretend this black-box Web/API workflow can automate mobile reverse engineering, Windows reverse engineering, or source-code audit.

This routing and clueboard model is adapted from CK-Skills under its MIT license. Read [references/expert-routing.md](references/expert-routing.md) for the integration boundaries and route index.

## Vulnerability priority

1. Tenant isolation, IDOR/BOLA, authentication, and session boundaries.
2. SSRF, file upload, deserialization, command injection, and injection families.
3. Business logic, race conditions, GraphQL, OAuth/JWT, and path traversal.
4. XSS, CSRF, CORS, open redirect, WebSocket, cloud storage, and information disclosure.
5. Cache/host-header and request-smuggling only in controlled or lab environments.

Every active test must follow this loop: falsification control -> baseline -> one-variable hypothesis -> minimum probe -> compare -> confirm or reject. If only a signal is observed, record it as `candidate` or `suspected`, never `verified`.

Read [references/vulnerability-playbook.md](references/vulnerability-playbook.md) for the full detection rules.

## Information gathering pipeline

Use this order and keep each stage bounded:

1. `src_start`: passive DNS/CT reconnaissance, one baseline `GET`, and clueboard initialization.
2. `src_clueboard`: read the board and set the current focus.
3. `src_asset_intel`: query configured FOFA/Shodan/Quake/Hunter/ZoomEye/urlscan providers with a domain, certificate, or exact asset query. Every result is marked `in_scope` or out-of-scope; only in-scope leads may be tested.
4. `src_js_inventory`: fetch the baseline page and a bounded set of same-origin JS assets; extract endpoints, parameters, source maps, and API hints. This is active and requires a batch approval because it fetches multiple assets.
5. Manual browser or Burp/Caido exploration: log in with the approved test account, walk real user flows, and capture the resulting traffic. Save the HAR under `evidence/`; then call `src_import_har`.
6. `src_path_probe`: probe only explicit paths discovered from JS, HTML, HAR, or business flows. Maximum 25 paths, no wordlist brute force, and a batch approval is required.
7. `src_port_probe`: check only ports already listed in `allowed_ports`. Maximum 20 ports, no internet-wide port scan, and a batch approval is required.
8. Build a feature map: authentication, object IDs, upload/import, exports, URL fetches, payments, approvals, invitations, and state transitions.
9. For each feature, call `src_hunt_route`, then `src_vuln_playbook`, and test one hypothesis at a time.

New hosts, URLs, IPs, or API domains extracted from JS remain leads until their scope status is confirmed. The “可疑站点搜索” step does not allow scanning arbitrary internet hosts or expanding beyond the program's asset list.

## Tool coordination

- Discovery: `src_start`, `src_passive_recon`, `src_asset_intel`, `src_js_inventory`, `src_import_har`.
- Cross-session memory: `src_clueboard` read, graph, append, set_focus, add_fact, add_intent, add_hint, update_intent.
- Inventory: `src_status`, `attack-surface.md`, `evidence/js-inventory.json`, `evidence/har-inventory.json`.
- Bounded scanning: `src_path_probe`, `src_port_probe` only after batch approval.
- Request testing: `src_http` for one request at a time; no ad hoc client.
- Expert routing: `src_hunt_route`.
- Classification: `src_vuln_playbook`.
- Evidence: `src_save_finding`, `src_validate_finding`, `src_render_report`.
- Tool installation: `src_tool_status`, then `src_install_tool` only with explicit confirmation.

## Common false-positive traps

- A reflection is not XSS; execution context must be proven.
- A CORS header is not a finding without readable authenticated data.
- A 500 error is not injection; the response must change deterministically with a controlled input.
- An ID change is not IDOR unless two identities prove object ownership boundaries.
- A public file or route is not sensitive disclosure without sensitive content or impact.
- A front-end route guard bypass is not backend authorization failure.
- Client-side encryption or a publicly retrievable key is not authentication.
- A self-XSS, logout CSRF, missing header, banner, or clickjacking-only issue is usually noise unless chained to real impact.

## Workflow after `src_start`

1. Use `src_status` to inspect the run.
2. Use `src_clueboard` to read the board and set one concrete focus.
3. Build a small attack-surface list in `attack-surface.md`.
4. Prefer manual, low-impact analysis over broad scanning.
5. Call `src_hunt_route` for the next feature or signal.
6. Call `src_vuln_playbook` for the selected class.
7. For any active test beyond baseline `GET`/`HEAD`/`OPTIONS`, call `src_request_approval`.
8. Show the returned approval code and ask the user to reply exactly `APPROVE <code>`.
9. After the exact reply, call `src_confirm_approval`, then `src_http` with the approval code.
10. Append observed facts, failed hypotheses, negative evidence, and the next focus with `src_clueboard` before the turn ends.
12. Record a lead with `src_save_finding` in `candidate` status.
13. Use `src_validate_finding` only when the finding has real evidence and human verification.
14. Use `src_render_report` only after validation; the output is a draft, not an automatic submission.

## Tool policy

- Baseline target traffic must use `src_http`, which enforces scope, rate limiting, redirect scope checks, request logging, and approval gates.
- `ffuf`, `nuclei`, `sqlmap`, brute force, DoS, persistence, lateral movement, and real-user data access are never automatic.
- Call `src_tool_status` before using an optional CLI tool.
- Call `src_install_tool` only with `confirm: true` after the user has agreed to install the named official tool. Do not install unapproved binaries or random GitHub projects.
- Burp/Caido remains manual for complex flows. Do not direct the browser at out-of-scope hosts.

## Stop conditions

Stop and report the exact reason when:

- Scope or authorization is missing.
- A redirect leaves the approved host/path.
- A response appears to contain another user's data, another tenant's data, credentials, or internal infrastructure.
- The target becomes unstable or shows signs of business impact.
- The next action needs a write, upload, authentication challenge, SSRF, deserialization, credential use, exploit chain, or WAF/rate-limit evasion without an approved code.
- You cannot prove that the program permits the activity.

## Evidence rules

- Try to falsify normal behavior before treating a signal as a defect. Record the negative-control test and its result.
- Use only actual MCP/HTTP evidence stored under the run directory.
- Redact cookies, authorization headers, tokens, API keys, session IDs, and personal data.
- A verified finding requires a real request/response pair, reproducible steps, concrete impact, and an independent oracle or human reviewer. The model that proposed the finding cannot award the final verdict.
- Never auto-submit a report to the SRC platform.

## Outputs

The MCP server writes to `runs/<program>/<timestamp>/` with `evidence/`, `candidates/`, `reports/`, `logs/`, `run.json`, `notes.md`, `CLUEBOARD.md`, `CLUEBOARD.json`, and `attack-surface.md`.
