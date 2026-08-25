# Phase A — Investigation Experience

Phase A makes the existing investigation engines visible as one analyst-facing
workflow without changing the frozen reasoning contract.

`POST /api/v1/investigate` now returns two additive projections:

- `exposure`: descriptive Exposure Intelligence results from the configured
  exposure providers. Exposure never changes severity, confidence, priority, or
  recommendations.
- `correlation`: deterministic observations derived from the completed
  `InvestigationSummary`. Correlation references existing findings and never
  creates new evidence or changes the reasoning result.

The frontend presents these projections in a clearly labeled **Context Signals**
section directly below the primary assessment. Empty exposure data, unmatched
correlation rules, and provider errors are shown explicitly rather than being
mistaken for a clean result.

The change is additive and backward-compatible: existing fields retain their
meaning, and clients that ignore `exposure` and `correlation` continue to work.
