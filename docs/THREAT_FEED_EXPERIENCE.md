# Threat Feed reading and browser-local controls

## Delivered plan

1. Saved-page speed and Settings recovery: one availability request for each
   visible bookmark page (maximum 20), plus independent saved-data retries.
2. Feed reading: optional quick previews, read markers, compact/comfortable
   spacing, optional column visibility, and exact dates with timezones.
3. Bookmark transfer: versioned JSON export, validated import preview, explicit
   confirmation and non-destructive merging. Regression and browser coverage.

No dependencies, paid services, external collection requests, or database
migrations are added. Existing detail URLs and full-page navigation remain.

## Feed layout and reading polish

The four views share aligned toolbars, quiet status messages, compact activity
cards and consistent controls. News keeps its three existing activity cards,
followed by the visit brief, filters, latest ten reports and regional links.
Vulnerability activity cards appear before the filters. Reload is visually primary;
source collection remains a separate manual action. Explanations are expandable.
Source diagnostics are collapsed initially and retain their existing loading policy.

On screens at least 1280 pixels wide, the existing navigation can dock in the
reserved side gutter. Smaller screens retain inline tabs and more reading width.
Docking preserves the content edges. News rows keep two-line titles, full accessible
link names and a separate, always-available preview button. Regional pages omit
redundant placement badges; explicit targeting evidence remains separate. Missing
severity is muted text, not an implied risk rating.

Preview drawers keep a persistent Close control while the complete title and
metadata scroll below it. Detail pages share title/action ordering and place
source facts alongside the main reading column on desktop, stacking on smaller
screens. IOC indicator tables keep the full content width. Saved bookmarks use
compact typed rows and keep unavailable records visible. No bookmark, export,
provider, scoring or authentication contract is changed.

PoC searches keep their manual authenticated execution. The compact form and source
panels use the same control style. Verification wording remains explicit, and an
official CVE reference is informational provenance, not a successful exploit test.
No tools are downloaded or executed by this presentation update.

Browser coverage checks long-title previews, unchanged content edges while docking,
mobile/tablet/desktop layouts, enlarged text, action accessibility and the absence
of automatic investigations, collections or PoC lookups. Optional local screenshots
use synthetic fixtures for visual review. These are local UI checks, not production
deployment or live source verification. No dependencies or database changes are added.

## News and Vulnerabilities loading reliability

Public Threat Feed GET requests skip authentication/session lookup, omit bearer
tokens and cookies, and coalesce identical in-flight reads. Each consumer can
cancel without cancelling other consumers; the upstream browser request stops
when everyone cancels. Ordinary public reads have a 12-second deadline, including
body loading. This deadline does not apply to source-collection POSTs or private
PoC lookups. Failed reads and mutations are never retried automatically.

News home, regional News and Vulnerabilities use the same browser cache policy:
five minutes fresh, up to 24 hours as an older fallback, eight filter/page entries
and at most 1 MiB per view. Older browser caches remain readable. Fresh entries
render without another list request. Older entries render immediately and update
in the background. Invalid responses cannot replace a good list or cache entry.
Search typing is briefly debounced; pagination and explicit reloads start directly.
Rows remain visible on loading, timeout and errors. A hint appears after four
seconds; Retry is manual and respects a supplied retry time.

**Reload saved data** only reads the database. It bypasses browser/CDN and warm
backend caches using `fresh=true` with a no-store response. **Refresh sources**
contacts the existing source collectors and retains the durable 30-minute public
cooldown. A failed collection or failed follow-up read cannot produce a success
notification. Successful collection clears compact browser caches. The six-hour
schedule, source failure isolation and retention policies are unchanged.

Detailed collection diagnostics load only when expanded, with a five-minute
in-memory copy. Their failure cannot delay the main table. Collection time,
publication dates and browser-cache freshness remain distinct.

Feed and IOC database setup use version markers in the existing feed-state table.
Current schemas skip DDL. Upgrades acquire one transaction advisory lock in
PostgreSQL, or a SQLite immediate transaction, before any table changes, then
recheck the marker. Markers commit only with successful setup. RLS stays enabled.
Future schema changes must use a new marker version. A process lock also prevents
duplicate service construction in one instance. Existing metadata backfills stay
idempotent and use no external requests.

PostgreSQL connections retain unnamed statements for transaction poolers and use
a four-second connect timeout. Each transaction sets a six-second statement
timeout and two-second lock timeout locally, without changing pooled session
defaults. Bounded list reads still use one combined data query, plus this
transaction-local timeout setup. `Server-Timing: feed;dur=...` on home and
vulnerability responses measures handler work, excluding connection startup in
the dependency, network transit and browser rendering. Warm CDN responses can
carry an older timing; it is diagnostic evidence, not a latency promise.

Tests cover SQLite concurrent startup/rollback, PostgreSQL driver lock ordering,
request cancellation/deadlines, cache expiry/bounds and browser recovery. Live
PostgreSQL concurrency and production latency require deployment verification;
local fixtures do not establish either. No paid cache, new table, migration,
credential or provider request is needed to test these changes.

## Previews and dates

The separate Preview button in News, Vulnerabilities and IOC Reports reads the
existing stored detail endpoint only when pressed. It does not investigate,
refresh sources, scan targets, or perform live PoC lookups. IOC previews show
the first ten defanged indicators and attribution; full details retain the
complete list and existing exports. No preview content enters persistent history.

The drawer supports Escape, focus wrapping, focus restoration and unchanged list
scroll. Mobile uses the available screen width. The 150 ms slide respects reduced
motion. Dates show an exact timestamp and UTC offset on hover or keyboard focus;
relative ages update once a minute while the page is visible.

## Reading and display preferences

Read markers are browser-local, scoped by record type and capped at 500 IDs per
type. Existing News, Vulnerability and IOC reading IDs are accepted as the
baseline. Successful previews and full details mark records read; failed previews
do not. Reading does not establish that intelligence is verified.

Display preferences contain only density and allowlisted optional column names.
Titles always remain visible; hidden columns do not change source data or
collection. Preferences are versioned, shared between feed views and retained
across reloads. Reset table display affects that table's columns and common
spacing. Settings → Reset Preferences also resets feed display preferences, but
does not erase bookmarks or reading history. Storage failure keeps display
changes for the current visit and shows an explanation.

## Saved availability and transfer

`POST /api/v1/threat-feed/bookmarks/availability` accepts 1–20 typed record IDs and
returns only kind, ID, availability and the current stored title. Responses are
private/no-store. Reads use one parameterized combined metadata query on warmed
database adapters (IOC schema initialization may run separately on first use).
Article-derived vulnerabilities, including zero-day reports without a CVE,
remain compatible. No per-bookmark detail or external provider requests occur.

Unavailable records remain bookmarked. A failed request means availability is
unknown, not that all records have expired. Retry is manual and preserves prior
checks and local records.

Portable JSON has format `threatlens-feed-bookmarks`, version 1, export time and
up to 500 bookmark entries: type, ID, title, internal link and saved time. It
contains no article bodies, indicator lists, PoC results, authentication tokens
or credentials. Import accepts at most 1 MiB and 500 entries. Unsupported schemas,
malformed records and unsafe links are rejected before writing. Additional fields
are discarded. Confirmation merges unique records without replacing existing
titles or removing bookmarks. Entries exceeding available capacity are skipped
and disclosed. Storage-write failures are shown inline.

Bookmark export is separate from database backup. Imports do not restore expired
feed items, synchronize devices, or change server records.

## Verification

Backend tests exercise memory/SQLite parity, PostgreSQL query shape, official and
derived vulnerabilities, bounded payloads and absence of per-record reads.
Frontend tests cover preference validation, reading migration/caps, dates, safe
merges, duplicates, unsafe imports and storage failure. Browser workflows cover
desktop/mobile drawers, focus/scroll preservation, read state, column persistence,
IOC provenance, a single Saved-page request, transfer confirmation and independent
Settings recovery. Live PostgreSQL and production deployment are separate rollout
checks; no production refresh or intelligence requests are needed for these tests.
