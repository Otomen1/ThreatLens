# Phases D/E — Analyst Workflow and Identity Intelligence

The analyst workflow now has a deterministic comparison endpoint:

```text
GET /api/v1/workspace/{before_id}/compare/{after_id}
```

It reports added, removed, and severity-changed findings plus posture before
and after. It compares saved engine output and never invents a new verdict.

Identity Intelligence now has an optional Have I Been Pwned provider for email
entities. Configure it with `HIBP_API_KEY` and optionally `HIBP_ENABLED`,
`HIBP_BASE_URL`, and `HIBP_TIMEOUT`. Missing credentials produce a structured
`unauthorized` result and do not break investigations. Identity results are
available from `GET /api/v1/identity?value=...` and are included additively in
`POST /api/v1/investigate`.

Identity data remains descriptive and separate from Threat Intelligence,
Exposure Intelligence, and deterministic reasoning. It does not create a
maliciousness verdict or modify severity, confidence, priority, or findings.
