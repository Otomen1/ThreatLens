# Phase B — Reliability

Phase B adds operational safeguards without changing any investigation result
contracts:

- Every HTTP response carries an `X-Request-ID`. A valid caller-supplied UUID
  is preserved; otherwise the API generates one. One structured JSON request
  event is emitted for log aggregation.
- Threat-intelligence, reference, and exposure provider calls are bounded by
  `THREATLENS_PROVIDER_CONCURRENCY` (default `8`). This prevents a large
  provider registry or burst of requests from exhausting the event loop or
  upstream quotas.
- Existing HTTP provider retry/backoff behavior remains the single transport
  policy for transient timeouts, transport failures, and 5xx responses.

The request ID is intentionally transport-level: it is not persisted into
investigations and cannot affect deterministic engine output.
