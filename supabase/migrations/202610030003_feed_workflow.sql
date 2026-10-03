CREATE TABLE IF NOT EXISTS threat_feed_ioc_revisions (
    id text PRIMARY KEY,
    report_id text NOT NULL REFERENCES threat_feed_ioc_reports(id) ON DELETE CASCADE,
    observed_at text NOT NULL,
    bytes integer NOT NULL CHECK (bytes >= 0),
    payload jsonb NOT NULL
);
CREATE INDEX IF NOT EXISTS ioc_revisions_report_idx
    ON threat_feed_ioc_revisions(report_id, observed_at DESC);
ALTER TABLE threat_feed_ioc_revisions ENABLE ROW LEVEL SECURITY;
