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
