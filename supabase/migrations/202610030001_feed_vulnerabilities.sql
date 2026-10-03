-- Metadata only; all writes pass through the existing server-side database connection.
CREATE TABLE IF NOT EXISTS threat_feed_vulnerabilities (
  id text PRIMARY KEY,
  activity_at text NOT NULL,
  payload jsonb NOT NULL
);
CREATE INDEX IF NOT EXISTS threat_feed_vulnerability_activity_idx
  ON threat_feed_vulnerabilities(activity_at DESC);
CREATE TABLE IF NOT EXISTS threat_feed_refresh_lease (
  id text PRIMARY KEY,
  owner text NOT NULL,
  expires_at double precision NOT NULL
);
ALTER TABLE threat_feed_vulnerabilities ENABLE ROW LEVEL SECURITY;
ALTER TABLE threat_feed_refresh_lease ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON threat_feed_vulnerabilities, threat_feed_refresh_lease FROM anon, authenticated;
