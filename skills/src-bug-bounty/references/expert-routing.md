# Expert Routing and Clueboard

This workflow adapts the reusable ideas from CK-Skills without importing its autonomous or unrestricted operating assumptions.

Source reference:

- Repository: `https://github.com/zhaji2333/CkSKILLS`
- Reviewed commit: `ffd042b5d7b67295e71eda8f377f397a00092f9d`
- License: MIT

## What was adopted

1. **Scenario-to-specialist routing.** A feature or signal is routed to a narrow knowledge pack instead of asking the model to improvise a generic checklist.
2. **Cross-session clueboard.** Hypotheses, hosts, paths, authentication notes, negative evidence, and coverage status are persisted inside the run so a later chat does not restart from the homepage.
3. **JS-first reconnaissance.** Understand routes, API calls, parameters, authentication flows, and feature flags before sending speculative requests.
4. **Falsification first.** Try to prove the behavior is normal, public, cached, client-side-only, or otherwise a false positive before recording a finding.
5. **Coverage discipline.** Track tested, untested, variants, related surfaces, and blocked items.
6. **Layered evidence gates.** A signal is not a vulnerability. The defect needs an actual executable path, reproducible evidence, and a concrete but safely demonstrated impact.

## What was intentionally not imported

- Any-target or no-compliance assumptions.
- Credential guessing, spraying, broad brute force, or authentication attacks against real accounts.
- Automatic evasion of WAFs, rate limits, or other protections.
- Broad internet scanning, arbitrary asset expansion, or exploitation beyond the recorded scope.
- Reading, downloading, or reporting real user data.
- Fully autonomous exploitation or report submission.
- Mobile binary, Windows reverse engineering, and source-code audit automation. These remain manual handoffs to a separately reviewed skill.

## Runtime flow

```text
src_start
  -> src_clueboard(read)
  -> src_asset_intel / src_js_inventory / manual browser walk / src_import_har
  -> src_clueboard(append findings and negative evidence)
  -> src_hunt_route(feature or signal)
  -> src_vuln_playbook(class)
  -> bounded src_http or manual verification
  -> src_clueboard(update focus and coverage)
  -> src_save_finding(candidate)
  -> src_validate_finding
  -> src_render_report
```

## Route index

| Route | Main use | Typical playbook classes | Approval |
|---|---|---|---|
| `hunt-clueboard` | Cross-session state and negative evidence | none | No |
| `recon-js-analysis` | JS, source maps, APIs, hidden routes | information disclosure, GraphQL, WebSocket | Batch |
| `unauth-path-key-hunt` | Anonymous path and key-boundary analysis | information disclosure, auth bypass | Batch |
| `auth-access-control` | Login, session, role, IDOR, tenant boundaries | auth/session/JWT, IDOR/BOLA, tenant isolation | Required |
| `api-protocol-security` | REST, GraphQL, WebSocket, method testing | GraphQL, WebSocket, IDOR/BOLA, smuggling | Required |
| `injection-vulns` | SQL/NoSQL/SSTI/command injection | injection classes | Required |
| `business-logic-race` | State machines, price, coupon, quota, race | business logic, race condition | Required |
| `file-handling` | Upload, download, import, archive, traversal | file upload, path traversal | Required |
| `ssrf-internal-network` | Server-side URL fetching and redirects | SSRF, open redirect | Required |
| `deserialization-xxe` | Serialized data and XML parsers | deserialization | Required |
| `xss-frontend-security` | XSS, CSRF, CORS, open redirect, browser trust | client-side classes | Required |
| `cloud-infra-supply-chain` | Public storage, debug endpoints, secrets | cloud storage, information disclosure | Required |
| `ai-llm-agent-security` | Prompt injection and tool boundaries | LLM prompt injection | Required |
| `waf-bypass-techniques` | Blocked-signal escalation planning | original class only | Required |
| `skill-supply-chain-audit` | Pre-install static audit of third-party Skills and plugins | agentic workflow security | No |
| `agentic-workflow-security` | Agents, RAG, multi-agent systems, MCP, tools | agentic workflow security, LLM prompt injection | Required |
| `capability-radar` | Build-versus-buy and external tool evaluation | none | Required |
| `report` | Evidence-gated report closeout | none | Human review |
| `mobile-package-manual` | APK or mini-program work | manual handoff | Required |
| `source-windows-manual` | Source or binary reverse engineering | manual handoff | Required |

The machine-readable source is `knowledge/expert-routes.json`; use `src_hunt_route` instead of manually searching that file.

## Evidence gates

Before a finding can become `verified`, confirm:

1. The asset, path, method, and account state are authorized.
2. The behavior is not an expected public feature.
3. A one-variable negative-control test was attempted.
4. The request or action was actually executed.
5. The result is reproducible and attributable to the target.
6. The impact is concrete and demonstrated without harming real users.
7. Evidence is minimal, redacted, and stored in the run directory.
8. A human reviewer has independently checked the evidence and scope.

## Clueboard protocol

- Read it before the first active action in each target session.
- Write durable discoveries in the same turn.
- Record negative evidence so tests are not repeated blindly.
- Keep secrets redacted; never paste complete cookies, tokens, or personal data.
- Keep hypotheses to a short prioritized list.
- Use `set_focus` to state the next concrete action.
- Use `add_fact`, `add_intent`, and `add_hint` to maintain the Fact-Intent-Hint graph in `CLUEBOARD.json`.
- A fact needs provenance; an intent is a proposed exploration; a hint is human judgment or a constraint.

## SecSkills-derived additions

- Skill supply-chain review: `src_skill_audit` performs static warning checks before a third-party Skill or plugin is trusted.
- State-space graph: the clueboard stores confirmed facts, proposed intents, and human hints.
- Agentic workflow review: map tools, MCP servers, connectors, memory, retrieval, and approval boundaries before testing prompts.
- Independent oracle: model output never self-awards a verified verdict.
- Script-plus-LLM separation: deterministic enumeration supplies coverage; the model supplies context and false-positive filtering.

See [secskills-integration.md](secskills-integration.md) and [agentic-workflow-security.md](agentic-workflow-security.md).
