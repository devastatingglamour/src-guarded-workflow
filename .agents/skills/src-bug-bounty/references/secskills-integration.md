# SecSkills Integration Notes

`DaoYiSec/SecSkills` is a curated index of 102 security Agents, Skills, and MCP projects rather than a single executable skill. The useful contribution is capability discovery plus a few strong architectural patterns.

Source:

- Repository: `https://github.com/DaoYiSec/SecSkills`
- Reviewed archive commit: `1867eb6`
- License: Apache-2.0

## Patterns adopted

### 1. Skill supply-chain audit

Inspired by the Skill safety projects in the SecSkills index. A third-party Skill is executable guidance, not inert documentation. Before installation:

- run `src_skill_audit`;
- inspect dangerous execution and approval bypasses;
- check for prompt injection, secrets, exfiltration, and obfuscation;
- read the actual files in context;
- isolate any dynamic test;
- require human approval before installation or execution.

`src_skill_audit` is a static warning system, not a security certificate.

### 2. Facts, intents, and hints

Inspired by Cairn's state-space model. The clueboard now has a machine-readable graph:

- **Fact**: a confirmed observation with provenance.
- **Intent**: a proposed next exploration derived from facts.
- **Hint**: human judgment or a constraint injected into the investigation.

The graph is stored in `CLUEBOARD.json`; `CLUEBOARD.md` remains the human-readable summary. Use `src_clueboard` actions `add_fact`, `add_intent`, `add_hint`, `update_intent`, and `graph`.

### 3. Agentic workflow security

Inspired by Agentic Radar. When the target is an agent, RAG system, multi-agent workflow, or MCP-enabled app, inspect:

- workflow graph;
- external and custom tools;
- MCP servers and connectors;
- data stores and memory;
- prompt and retrieved-content trust boundaries;
- tool approval and side-effect controls.

This is a separate class from ordinary prompt injection.

### 4. Independent verification

Inspired by Pentest-AI's oracle model. The model that proposed a finding cannot award the final verified verdict. A verified result needs a deterministic replay, machine check, or human reviewer with actual evidence. The existing validation gate remains authoritative.

### 5. Script plus LLM separation

Inspired by the mini-program audit pattern. Deterministic scripts enumerate coverage; the LLM performs context-aware triage and false-positive filtering. Scripts do not decide impact, and the LLM does not replace evidence collection.

## Not adopted

- The full 102-project catalog.
- Automatic installation of external Agent platforms.
- CTF, malware analysis, binary exploitation, domain penetration, and mobile reverse-engineering workflows outside this Web/API plugin.
- Vendor claims such as "zero false positives" without local evidence.
- Autonomous operation that bypasses scope, approval, or human verification.

## Decision rule

Use the existing guarded tool when it covers the capability. If a capability gap remains, evaluate an external project as an untrusted candidate: audit its skills and manifests, isolate it, test it on a lab target, and require explicit approval before it touches an authorized asset.
