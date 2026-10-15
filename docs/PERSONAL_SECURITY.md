# Personal-use security and reliable storage

ThreatLens remains a single-owner application. Public Threat Feed metadata stays
public; investigations, Cases, backups, identity checks and live PoC lookups do not.
No roles, organizations, new authentication provider or paid service are added.

## Required owner configuration

Set `THREATLENS_OWNER_USER_ID` to the permanent UUID of your existing Supabase
Authentication user. Keep it server-side: do not use a `NEXT_PUBLIC_` variable.
The backend and protected-page proxy use the same setting. Existing saved records
remain in their personal namespace; no user IDs are assigned to individual records.

Supabase project URL/publishable key must still be configured. The API verifies
the access token with Supabase, retains only its digest and verified identity in a
bounded short-lived cache, and never caches past the token expiry. Owner policy
is checked on every private request, including cached tokens. Another account
receives 403; invalid/missing credentials receive 401; missing setup receives 503.
An optional server-only service API key is an owner credential, not a browser key.
PoC and `/auth/me` still require a Supabase sign-in.

For offline development only, explicitly set both `THREATLENS_ENV=development`
and `THREATLENS_ALLOW_UNAUTHENTICATED_LOCAL=true`. The bypass works only when
authentication is unconfigured and is ignored on Vercel. It does not grant a
verified browser identity or enable sensitive browser-history persistence.

Private API requests share a durable fixed-minute owner bucket (default 60).
Identity email/password requests retain stricter configured limits (default 30).
PostgreSQL and SQLite use atomic counters; local files use cross-process locks.
Requests rejected with 429 include Retry-After; no automatic quota-consuming
retry is introduced. Rate state uses existing storage and is excluded from backups.

## Browser-local history

One shared session provider verifies `/api/v1/auth/me`. Sensitive IndexedDB
records are partitioned by that verified user ID. Signing out/account changes
clear displayed private data and cancel pending browser work, but retain the
owner's local partition for the next sign-in. Late responses cannot write into
another account's partition. This is access separation, not encryption: someone
inspecting the same browser profile directly can inspect its local records.

Batch recovery expires after 24 hours. Email history keeps the latest 20 checks
per email for 90 days, with cleanup on reads and saves. Legacy unscoped history
remains hidden until the owner explicitly imports or deletes it in Settings.
Import only records you recognize as yours. Separate clear controls do not erase
bookmarks, preferences, saved investigations or server backups. Passwords and
password checks are never stored in history.

## Storage and backups

Local record/cache writes use unique same-directory temporary files, flush them,
then atomically replace the destination. Reentrant thread/process locks protect
read-modify-write operations. SQLite uses operation/transaction-scoped connections.
PostgreSQL personal-record transactions share an advisory transaction lock and
reuse one connection while holding it; no external pool service is required.

Investigation cache TTL remains 12 hours. PostgreSQL, SQLite and local JSON
adapters persist completed snapshots; explicit memory mode is test-only.
Configuration fingerprints contain hashes, not provider credential values.

New backups use schema v2 and include owner metadata. Their SHA-256 digest detects
accidental changes; it is not a signature or proof of who created the file.
V2 ownership must match this workspace. V1 digests remain compatible, but restore
requires an explicit ownership confirmation. Never import an untrusted backup.
Duplicate IDs, unsupported versions, oversized bundles and invalid timestamps
are rejected. PostgreSQL/SQLite restore both record families atomically and skip
equal/older versions. Local-file restoration is locked but is not a multi-file
database transaction: a failure can leave some successful merges, which the UI
discloses. Inspect Workspace before retrying. Restore never deliberately deletes
existing records.

## Feed read performance

News, vulnerability and IOC pages filter/count/paginate inside the database.
The homepage retains one database query with counts and limited regional rows.
Unified search and related links use a compact stored-reference index with exact
CVE/IOC/canonical URL matching. Index/backfill operations use existing metadata,
not publisher or intelligence requests. Old metadata is backfilled once; successful
collection maintains it. Five-minute public caching and 30-day retention remain.

## Rollout and verification

Before deployment, set the owner UUID and apply migration
`202610140001_personal_security_and_feed_reads.sql` using the existing migration
workflow. Private tables deny Supabase browser roles; the server connection needs
the existing privileged database role. Back up personal records first. No live
database migration or production configuration is applied by local implementation.

Verify owner sign-in, non-owner rejection, public feed access, a saved record,
backup validation/restoration and concurrent updates on a disposable PostgreSQL
database before the production smoke test. Unit/mock tests cannot prove the live
role configuration or PostgreSQL behavior. Push/deployment remain separate steps.
