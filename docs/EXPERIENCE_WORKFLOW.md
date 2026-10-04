# Personal experience workflow

Search remains the home page. The independent Start here panels load after the
search controls, showing public feed highlights and (only when signed in) the
latest five saved investigations, counts, and observed provider issues.
Continuing saved work reads storage; it never reruns providers. The authenticated
`GET /api/v1/workspace/start-summary` fails closed when sign-in is unavailable,
returns private/no-store data, and independently reports unavailable sections.

## Investigate, save, generate, review, export

Progress reports extraction, confirmation and investigation stages with elapsed
time, not a fabricated single-search percentage. Browser cancellation and the
45-second deadline cannot guarantee an upstream provider stopped or avoided
quota consumption. Batch concurrency remains four.

The last successful single result stays visible during another request, failure,
or cancellation, labelled with its original entity. Obsolete responses cannot
replace a newer session. Retrying investigations is manual and may consume quota.

Generation is explicit and optional. Save before or after generation; the package
is included when creating a record, or attached to the known saved ID afterward.
Failed rule persistence retains the generated package for retry without another
generation request. Review links filter Detection Workspace to that record.
Validation and review counts do not imply live SIEM verification or whole-package
approval. Approved-version protections remain enforced by existing storage rules.
If an initial create response is ambiguous, inspect Workspace before allowing
another create. Rule export remains available without saving.

## Preferences and data ownership

Settings → Experience stores only validated scan mode, rule-format presentation,
compact/card view, page size and collapsed-section preferences in a versioned
browser-local record. URL filters override defaults. Reset Preferences removes
only that record; it does not remove bookmarks, identity history or saved work.
No queries, credentials, identities or provider exclusions enter this store.

- Temporary: live investigations, generated-but-unsaved rules and PoC results.
- Browser-local: preferences, bookmarks, identity history and batch recovery.
- Saved to database: explicitly saved Workspace records and Cases, using the
  configured storage adapter (PostgreSQL in production; local adapters still work).

Cache age/expiry comes from response metadata. Existing batch recovery expires
after 24 hours and identity email history after 90 days. Password checks are not
retained. Public feeds and browser-local data are excluded from personal server
backups. Settings links the separate backup/restore and local clearing controls;
there is no destructive clear-everything control.

## Verification

Unit tests cover safe transport errors/cooldowns, preference validation and reset
boundaries, bounded passive start summaries and deterministic overviews.
Browser tests cover save/generate/persistence retry/review/export, retained results,
cancellation and late responses, URL precedence and preference reset.

For an already-installed local browser, set `THREATLENS_TEST_BROWSER` to its
executable path when running Playwright. CI continues to use its installed
Playwright browser by default. No new runtime dependencies or migrations are needed.
