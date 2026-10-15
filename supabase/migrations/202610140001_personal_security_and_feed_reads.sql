-- Single-owner API authorization; private tables are not exposed through Supabase REST.
begin;
create table if not exists public.threatlens_request_limits (
  key text primary key, window_start bigint not null, requests bigint not null
);
alter table public.threatlens_request_limits enable row level security;

-- Existing personal records stay in one namespace. Backend database credentials
-- remain server-only; no browser-user access policies are introduced.
do $$
declare table_name text;
begin
  foreach table_name in array array[
    'threatlens_workspace_records', 'threatlens_case_records',
    'threatlens_investigation_cache', 'threatlens_request_limits'
  ] loop
    if to_regclass('public.' || table_name) is not null then
      execute format('alter table public.%I enable row level security', table_name);
      execute format('revoke all on public.%I from anon, authenticated', table_name);
    end if;
  end loop;
end $$;

alter table public.threat_feed_items add column if not exists published_epoch double precision;
alter table public.threat_feed_vulnerabilities add column if not exists activity_epoch double precision;
update public.threat_feed_items set published_epoch=extract(epoch from published_at::timestamptz) where published_epoch is null;
update public.threat_feed_vulnerabilities set activity_epoch=extract(epoch from activity_at::timestamptz) where activity_epoch is null;
create index if not exists threat_feed_items_epoch_idx on public.threat_feed_items(published_epoch desc,id);
create index if not exists threat_feed_vulnerabilities_epoch_idx on public.threat_feed_vulnerabilities(activity_epoch desc,id);
create index if not exists threat_feed_region_epoch_idx on public.threat_feed_items((payload->>'region'),published_epoch desc,id);
create index if not exists threat_feed_source_id_epoch_idx on public.threat_feed_items((payload->>'source_id'),published_epoch desc,id);
create index if not exists threat_feed_topic_epoch_idx on public.threat_feed_items((payload->>'topic'),published_epoch desc,id);
create table if not exists public.threat_feed_read_references (
  kind text not null,id text not null,activity_epoch double precision not null,
  search_text text not null,payload jsonb not null,primary key(kind,id)
);
create index if not exists threat_feed_references_activity_idx on public.threat_feed_read_references(kind,activity_epoch desc,id);
create index if not exists threat_feed_references_payload_idx on public.threat_feed_read_references using gin(payload);
alter table public.threat_feed_read_references enable row level security;
commit;
