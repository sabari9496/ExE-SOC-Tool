"""Email notification tables (new tables only; no existing table is altered). SMTP passwords are NEVER stored in the database."""
SCHEMA = """
CREATE TABLE IF NOT EXISTS notification_settings(key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS notification_recipients(id INTEGER PRIMARY KEY, email TEXT NOT NULL UNIQUE, name TEXT DEFAULT '', enabled INTEGER DEFAULT 1, severities TEXT DEFAULT '', level INTEGER DEFAULT 1, created_by TEXT, created TEXT);
CREATE TABLE IF NOT EXISTS notification_history(id INTEGER PRIMARY KEY, notification_id TEXT, incident_id INTEGER, incident_code TEXT, alert_id INTEGER, ntype TEXT, recipient TEXT, subject TEXT, severity TEXT,
  ts TEXT, sent_at TEXT, status TEXT, attempts INTEGER DEFAULT 0, next_try REAL DEFAULT 0, error TEXT, body_html TEXT, body_text TEXT, occurrences INTEGER DEFAULT 1);
CREATE INDEX IF NOT EXISTS ix_nh_due ON notification_history(status, next_try); CREATE INDEX IF NOT EXISTS ix_nh_inc ON notification_history(incident_id); CREATE INDEX IF NOT EXISTS ix_nh_ts ON notification_history(ts);
CREATE TABLE IF NOT EXISTS notification_dedupe(key TEXT PRIMARY KEY, incident_id INTEGER, alert_id INTEGER, first_sent REAL, last_sent REAL, severity TEXT, sent_count INTEGER DEFAULT 0, suppressed INTEGER DEFAULT 0, occurrences_last INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS notification_escalation(incident_id INTEGER PRIMARY KEY, ts TEXT, level INTEGER);
"""
