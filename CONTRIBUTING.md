# Contributing to ThreatLens

Thanks for contributing! ThreatLens is a deterministic security platform — the
bar is correctness, explainability, and reproducibility. This guide covers the
standards every change is held to.

## Ground rules

1. **The deterministic core is sacred.** Detection, aggregation, and the
   Reasoning Engine must stay pure: no AI, no randomness, no network, no
   wall-clock reads (time is injected). AI and other consumers live strictly
   downstream of `InvestigationSummary` and never write back into it.
2. **Engine output changes are deliberate.** If your change alters any
   `InvestigationSummary` (findings, confidence, priority, ordering, IDs), the
   golden regression will fail. That is by design: regenerate with
   `THREATLENS_UPDATE_GOLDEN=1 pytest`, bump `ENGINE_VERSION`
   (`backend/src/threatlens/reasoning/engine.py`), and explain the change in
   your PR. Unexplained golden churn will not be merged.
3. **Failures are values.** Providers and the AI layer return structured
   statuses (`error`, `timeout`, `unavailable`, …) — they never raise across
   the boundary and never fail an investigation.
4. **No secrets in the repo.** API keys live in `backend/.env` (git-ignored).
   `.env.example` documents them.

## Coding standards

**Backend (Python 3.11+)**

- Formatting/linting: `ruff format` + `ruff check` (line length 100).
- Types: `mypy --strict` must pass — full annotations, no untyped defs.
- Models: Pydantic v2, `ConfigDict(frozen=True)` for value objects.
- Style: match the existing modules — module docstrings that explain *why*,
  small pure functions, explicit enums over strings, no speculative
  abstractions ("an abstraction earns its place when ≥2 concrete uses exist").

**Frontend (TypeScript / Next.js)**

- The UI is a **pure consumer** of the API: it never recalculates severity,
  confidence, or priority, and never re-sorts backend-ordered lists.
- `npm run build` (includes type-checking) and `npm test` must pass.
- Styling: Tailwind, zinc palette, consistent with existing components.

## Branch strategy

- `main` is the stable release branch — always green, protected.
- Work happens on feature branches (`feature/<topic>`, `fix/<topic>`, or your
  own naming), branched from the latest `main`.
- Changes land on `main` only through a pull request with passing CI.

## Testing

Run everything before opening a PR:

```bash
cd backend
ruff check src tests
mypy src/threatlens          # (or: python -m mypy src/threatlens)
pytest                       # full suite — offline, no keys, no model needed

cd ../frontend
npm test
npm run build
```

Expectations:

- **New code ships with tests.** Providers get offline contract tests against
  recorded/simulated payloads; reasoning changes get scenario coverage in
  `tests/benchmark/`; pipeline-visible changes belong in the 100-IOC corpus
  (`tests/validation/`).
- **Never require the network, API keys, or a local LLM in tests.** Mock HTTP
  with `httpx.MockTransport`; the Ollama provider is always mocked.
- **Golden snapshots** (`tests/benchmark/golden.json`,
  `tests/validation/golden.json`) are regenerated only intentionally (see
  ground rule 2).

## Commit expectations

- Conventional-commit style subjects: `feat(scope): …`, `fix(scope): …`,
  `test(scope): …`, `docs(scope): …`, `chore(scope): …`.
- One logical change per commit; the body explains *what changed and why*,
  including test results for non-trivial changes.
- Never commit secrets, generated artifacts, or unexplained golden updates.

## Pull requests

- Keep PRs focused; unrelated refactors go in separate PRs.
- The description states what changed, why, how it was verified, and — if
  engine output changed — why the new golden snapshot is correct.
- CI must be green: Ruff, mypy strict, backend tests (incl. golden
  regression), frontend build + tests.
- New environment variables must be documented in `README.md` and
  `backend/.env.example`.
- API changes must be **additive** (new optional fields/endpoints). Breaking
  changes to `/api/v1/*` or the `InvestigationSummary` contract require a
  major-version discussion first.
