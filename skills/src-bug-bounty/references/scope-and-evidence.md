# Scope and Evidence Rules

## Scope model

- Authorization is asset-specific, not company-wide by implication.
- A wildcard such as `*.example.com` matches subdomains but not the bare domain unless the bare domain is also listed.
- Denied hosts and paths always take precedence over allowed entries.
- Ports are part of scope. Do not assume non-default ports are allowed.
- HTTP methods are part of scope. Default to `GET`, `HEAD`, and `OPTIONS`.
- A redirect to a different host must be checked against scope before it is followed.
- A third-party service or external integration is out of scope unless the program explicitly allows it.
- Publicly reachable does not mean authorized.

## Data handling

- Use test accounts and test data.
- Do not download source code, operational data, user records, or credentials unless the program explicitly requires a minimal sample.
- If a sensitive value is obtained accidentally, stop, record only that it was encountered, and follow the program's reporting channel.
- Delete or minimize retained data according to the program rules and the run's retention policy.
- Never put cookies, tokens, API keys, session IDs, or personal data in Git, logs, screenshots, or final reports.

## Evidence checklist

For each verified finding:

- Asset and endpoint are explicitly in scope.
- Preconditions and account roles are recorded.
- The exact request and response are available or accurately summarized.
- The test was executed, not generated from a template.
- The result is reproducible with minimal steps.
- The impact is concrete and attributable to the defect.
- Evidence contains no unnecessary secrets or personal data.
- The finding is checked for duplicates and expected behavior.
- Severity follows the program's own rules.

## Stop conditions

Immediately stop expansion when:

- A response contains another user's or tenant's data.
- A credential or internal endpoint appears.
- The service becomes unstable or rate limiting suggests impact.
- A redirect or link leaves the configured scope.
- A requested action would require write access, persistence, or lateral movement.
- The operator cannot confirm that the activity is allowed.
