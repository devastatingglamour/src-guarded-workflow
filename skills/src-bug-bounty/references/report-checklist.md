# Report Checklist

Before submitting a report, confirm:

- The title states the defect and impact, not just the endpoint.
- The affected asset is explicitly in scope.
- The summary explains who can do what, under which conditions, and why it matters.
- Preconditions and test-account roles are clear.
- Reproduction steps are ordered, minimal, and independently repeatable.
- The evidence matches the claimed request and response.
- Impact is demonstrated, not hypothetical.
- Sensitive values and real user data are removed.
- Severity and CVSS use the program's rules.
- The finding has been checked against known disclosed reports.
- A human has reviewed the final text and submitted it through the approved channel.

Avoid:

- Generic vulnerability explanations without target-specific evidence.
- AI-generated filler, invented screenshots, or speculative impact.
- Bulk submissions or duplicate variants of the same root cause.
- Claims that require out-of-scope follow-up testing.

## Falsification gate

Before accepting a finding, record the normal-behavior explanation that was tested and why it did not hold:

- Public or intended behavior was ruled out.
- Shared, cached, or client-side-only state was ruled out where relevant.
- The test used the correct identity and object ownership.
- The changed variable was isolated.
- The result remained reproducible after a minimal retry.

## Type-specific proof

- Authorization: two approved test identities or an anonymous/test-account boundary demonstrate the same object or action.
- Authentication: the protected state or action is actually reached; front-end route hiding alone is insufficient.
- Injection: a deterministic server-side difference is shown without data dumping or command execution.
- SSRF: server-side fetching is distinguished from a client-side redirect or browser request.
- Upload/path traversal: a synthetic marker proves the parser or file boundary without touching real files.
- Business logic: one invariant violation is reproduced with synthetic data and no real financial impact.
- XSS/CORS: execution or authenticated-data readability is proven in a real security context.

## Evidence and AI-use rules

- Use only requests, responses, timestamps, and screenshots that were actually produced.
- A scanner, secret scanner, or AI model may provide a lead, not a confirmed vulnerability.
- Do not paste real user data, live credentials, private tokens, or unnecessary internal infrastructure into the report.
- State when a test was blocked, inconclusive, or performed only against synthetic data.
- The final report is a human-reviewed draft until the operator submits it through the authorized channel.
