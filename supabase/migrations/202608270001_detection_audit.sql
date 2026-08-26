-- ThreatLens detection audit schema.
-- Safe to apply alongside the existing JSON workspace record table.
-- Application rollout should write both the current package and audit rows.

create table if not exists public.detection_versions (
  id uuid primary key default gen_random_uuid(),
  investigation_id uuid not null,
  artifact_id text not null,
  version integer not null check (version > 0),
  content text not null,
  changed_fields jsonb not null default '[]'::jsonb,
  mapping_version text not null default 'default',
  engine_version text not null,
  reviewer text,
  approved boolean not null default false,
  created_at timestamptz not null default now(),
  unique (artifact_id, version)
);

create table if not exists public.detection_exclusions (
  id uuid primary key default gen_random_uuid(),
  investigation_id uuid not null,
  subject_type text not null,
  subject_value text not null,
  reason text not null,
  expires_at timestamptz,
  created_by uuid references auth.users(id),
  created_at timestamptz not null default now()
);

create index if not exists detection_versions_investigation_idx on public.detection_versions (investigation_id);
create index if not exists detection_versions_artifact_idx on public.detection_versions (artifact_id, version desc);
create index if not exists detection_exclusions_lookup_idx on public.detection_exclusions (investigation_id, subject_type, subject_value);

alter table public.detection_versions enable row level security;
alter table public.detection_exclusions enable row level security;

-- Workspace records currently contain the authenticated-user boundary in the
-- application adapter. These policies are intentionally deny-by-default until
-- a user_id/organization_id column is added to the workspace table.
drop policy if exists "detection versions service role only" on public.detection_versions;
create policy "detection versions service role only" on public.detection_versions
  for all using (auth.role() = 'service_role') with check (auth.role() = 'service_role');
drop policy if exists "detection exclusions service role only" on public.detection_exclusions;
create policy "detection exclusions service role only" on public.detection_exclusions
  for all using (auth.role() = 'service_role') with check (auth.role() = 'service_role');
