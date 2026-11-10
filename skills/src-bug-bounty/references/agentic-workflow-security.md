# Agentic Workflow Security Review

Use this reference when the authorized target is an AI agent, RAG application, chatbot with tools, multi-agent system, MCP-enabled product, or plugin marketplace.

## Static map first

Record:

- entry points and trust boundaries;
- agent roles and instructions;
- system prompts and prompt templates;
- tools with names, permissions, inputs, and side effects;
- MCP servers, transport, authentication, and source reputation;
- connectors, data stores, memory, and retrieval sources;
- inter-agent messages and their provenance;
- outbound network destinations;
- human approval and sandbox controls.

## High-value questions

1. Can untrusted user or retrieved content reach a privileged tool?
2. Can a tool run without the approval required for its impact?
3. Can one agent impersonate another or inject a message into its instructions?
4. Can memory or RAG content persist attacker-controlled instructions?
5. Can the workflow read data outside its stated task?
6. Can output be sent to an unapproved destination?
7. Is the MCP or tool server trusted, pinned, and least-privileged?
8. Does a failure produce security evidence, or only a model refusal?

## Safe validation

- Use synthetic documents, markers, accounts, and data.
- Test one instruction or tool boundary at a time.
- Prefer local/static inspection before running the workflow.
- Do not trigger payments, deletion, messaging, external publishing, or real credential use.
- Do not treat a model refusal or a successful prompt as a vulnerability without a boundary violation and concrete impact.
- Human review is required before verification.

## Evidence

A valid finding should show the workflow node, tool or data boundary, synthetic input, observed behavior, expected security rule, actual impact, and reproducibility. A prompt-only interaction that produces no unauthorized action or data access remains a candidate.
