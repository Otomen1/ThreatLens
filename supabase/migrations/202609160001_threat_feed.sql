create table if not exists public.threat_feed_items (
  id text primary key,
  published_at text not null,
  payload jsonb not null
);
create index if not exists threat_feed_items_published_idx
  on public.threat_feed_items (published_at desc);

create table if not exists public.threat_feed_sources (
  id text primary key,
  payload jsonb not null
);

create table if not exists public.threat_feed_state (
  key text primary key,
  value text not null
);

create table if not exists public.threat_feed_refresh_runs (
  id text primary key,
  started_at text not null,
  payload jsonb not null
);
create index if not exists threat_feed_refresh_runs_started_idx
  on public.threat_feed_refresh_runs (started_at desc);

alter table public.threat_feed_items enable row level security;
alter table public.threat_feed_sources enable row level security;
alter table public.threat_feed_state enable row level security;
alter table public.threat_feed_refresh_runs enable row level security;

-- Threat Feed data is exposed only through the FastAPI routes. Direct Data API
-- access remains deny-by-default; the DATABASE_URL connection owns writes.
