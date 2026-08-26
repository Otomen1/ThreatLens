# Detection operations

ThreatLens generates deterministic rules from completed investigation findings.
Generated rules are drafts until an analyst reviews and approves them.

## Workflow

1. Run an investigation and save it to the Workspace.
2. Generate detections from the saved investigation.
3. Review the generated content and test it with representative JSON samples.
4. Add an analyst note, approve or reject the rule, and export only approved content.
5. For related indicators, select same-type IOC groups and save a combined Sigma draft.

Excluded rules are hidden by default in the Detection Workspace and can be restored
with **Show excluded**. Exclusion is analyst metadata; it does not erase the original
investigation finding.

## Environment variables

Provider credentials belong in Vercel or the local deployment environment, never in
the repository. The VirusTotal key is `VIRUSTOTAL_API_KEY`. Supabase/PostgreSQL
workspace storage uses `DATABASE_URL` and `THREATLENS_STORAGE_BACKEND=postgres`.

## Validation limits

Sigma and YARA receive offline structural checks. SIEM formats receive deterministic
parser-level checks for required structure; validate against the target platform
before production deployment. ThreatLens does not automatically push or activate
rules in a SIEM.

## Database migration

The audit tables are in `supabase/migrations/202608270001_detection_audit.sql`.
Apply migrations through the Supabase migration workflow. Review the row-level
security policy and add the project’s user/organization boundary before exposing
these tables directly to browser clients.

## Rule history

Review, note, exclusion, restore, and saved combined-rule changes append an
immutable snapshot to the artifact metadata as `version_history`. The Detection
Workspace shows recorded versions and can export each prior rule body. This
works before a SIEM is available. The Supabase audit tables remain the durable
server-side follow-up once authenticated user or organization ownership is
available in workspace storage.
