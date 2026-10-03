-- Backend database role writes; direct anonymous/authenticated database access has no policies.
CREATE TABLE IF NOT EXISTS threat_feed_ioc_reports (
  id text PRIMARY KEY, vendor text NOT NULL, title text NOT NULL,
  activity_at text NOT NULL, payload jsonb NOT NULL
);
CREATE TABLE IF NOT EXISTS threat_feed_indicators (
  id text PRIMARY KEY, type text NOT NULL, value text NOT NULL,
  payload jsonb NOT NULL, UNIQUE(type,value)
);
CREATE TABLE IF NOT EXISTS threat_feed_report_indicators (
  report_id text NOT NULL REFERENCES threat_feed_ioc_reports(id) ON DELETE CASCADE,
  indicator_id text NOT NULL REFERENCES threat_feed_indicators(id), original text NOT NULL,
  PRIMARY KEY(report_id,indicator_id)
);
CREATE INDEX IF NOT EXISTS ioc_reports_vendor_activity_idx ON threat_feed_ioc_reports(vendor,activity_at DESC);
CREATE INDEX IF NOT EXISTS ioc_reports_activity_idx ON threat_feed_ioc_reports(activity_at DESC);
CREATE INDEX IF NOT EXISTS ioc_indicator_value_idx ON threat_feed_indicators(value);
CREATE INDEX IF NOT EXISTS ioc_indicator_type_idx ON threat_feed_indicators(type);
CREATE INDEX IF NOT EXISTS ioc_edges_indicator_idx ON threat_feed_report_indicators(indicator_id);
ALTER TABLE threat_feed_ioc_reports ENABLE ROW LEVEL SECURITY;
ALTER TABLE threat_feed_indicators ENABLE ROW LEVEL SECURITY;
ALTER TABLE threat_feed_report_indicators ENABLE ROW LEVEL SECURITY;
