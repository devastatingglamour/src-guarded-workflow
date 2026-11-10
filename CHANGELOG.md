# Changelog

All notable changes to `src-guarded-workflow` are documented here.

## [0.7.2] - 2026-11-10

### Fixed

- Made `src_hunt_route` return a stable `status: ok` result and a separate `result_type: expert_route`.
- Flattened the default route response to one best match to avoid MCP client timeouts.
- Added server-side MCP call timing metadata without logging request content or secrets.

### Tooling

- Added `scripts/build_release.ps1` for deterministic release packaging.
- Added a GitHub Actions tag workflow that tests, builds, and publishes migration and portable ZIP assets.

## [0.7.1] - 2026-11-10

### Fixed

- Added the required `$schema` to plugin MCP configuration so Codex loads `srcGuardedWorkflow`.
- Corrected marketplace/plugin installation paths.
- Verified live `src_tool_status` calls through the local plugin.

## [0.7.0] - 2026-11-10

### Added

- `src_skill_audit` static supply-chain audit for third-party Skills and plugins.
- Fact-Intent-Hint graph in `CLUEBOARD.json`, with graph actions on `src_clueboard`.
- `agentic_workflow_security` playbook class and expert route.
- Capability radar for build-versus-buy and external tool evaluation.
- SecSkills and additional design references with third-party notices.

## [0.6.0] - 2026-11-09

### Added

- Expert routing derived from CK-Skills.
- Cross-session Markdown clueboard and negative-evidence workflow.
- Additional guidance for JS-first reconnaissance, falsification, coverage, and report gates.

## Versioning rules

- Patch versions: compatibility fixes, documentation, and small behavior corrections.
- Minor versions: new playbooks, routes, tools, or workflow capabilities.
- Major versions: breaking plugin APIs, scope formats, MCP contracts, or approval semantics.

Before a release:

1. Update `plugin.json`, `.codex-plugin/plugin.json`, and `server/src_guarded_mcp.py` version values.
2. Run `python -m unittest discover -s tests -v`.
3. Run the skill validator.
4. Rebuild migration and portable artifacts.
5. Commit, tag `vX.Y.Z`, push the branch and tag, and create a GitHub Release.
