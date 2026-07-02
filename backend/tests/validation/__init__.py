"""Platform validation & IOC regression suite (Phase 3.16).

A persisted corpus of ~100 real-world IOC investigations that exercises the
*complete* pipeline — detection → normalization → provider routing → reasoning →
InvestigationSummary — the way a SOC analyst uses ThreatLens. It is the permanent
integration regression suite: future phases must run exactly this dataset, and a
golden snapshot fails the build on any unintended change to engine output.

Everything is offline and deterministic. Detection and routing are validated
against the *live* engine; reasoning is validated against per-case provider-
faithful intelligence (external TI providers need network/keys, so their results
are simulated exactly as they would be normalized), so the suite is reproducible
in CI without a network, API keys, or a model.
"""
