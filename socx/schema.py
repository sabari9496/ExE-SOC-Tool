"""EXE-SOC advanced layer: new tables only (existing tables are never altered or dropped)."""
SCHEMA = """
CREATE TABLE IF NOT EXISTS incidents(id INTEGER PRIMARY KEY, title TEXT, severity TEXT, risk_score INTEGER DEFAULT 0, status TEXT DEFAULT 'New',
  assignee TEXT, host TEXT, username TEXT, source_ip TEXT, first_seen TEXT, last_seen TEXT, event_count INTEGER DEFAULT 0, alert_count INTEGER DEFAULT 0,
  mitre TEXT DEFAULT '', tactics TEXT DEFAULT '', summary TEXT DEFAULT '', score_detail TEXT DEFAULT '', created TEXT, updated TEXT, closed_at TEXT);
CREATE TABLE IF NOT EXISTS incident_alerts(incident_id INTEGER, alert_id INTEGER, PRIMARY KEY(incident_id, alert_id));
CREATE TABLE IF NOT EXISTS incident_notes(id INTEGER PRIMARY KEY, incident_id INTEGER, author TEXT, note TEXT, ts TEXT);
CREATE INDEX IF NOT EXISTS ix_inc_status ON incidents(status, last_seen); CREATE INDEX IF NOT EXISTS ix_inc_host ON incidents(host); CREATE INDEX IF NOT EXISTS ix_ia_alert ON incident_alerts(alert_id);
CREATE TABLE IF NOT EXISTS alert_meta(alert_id INTEGER PRIMARY KEY, detection_id TEXT, mitre TEXT, tactic TEXT, risk_score INTEGER, score_detail TEXT, ioc TEXT, username TEXT, process TEXT,
  command_line TEXT, parent_process TEXT, event_id INTEGER, data_source TEXT, reason TEXT, first_seen TEXT, last_seen TEXT, suppressed_by INTEGER);
CREATE TABLE IF NOT EXISTS assets(hostname TEXT PRIMARY KEY, criticality INTEGER DEFAULT 2, role TEXT DEFAULT '', owner TEXT DEFAULT '', updated TEXT);
CREATE TABLE IF NOT EXISTS whitelist(id INTEGER PRIMARY KEY, kind TEXT NOT NULL, detection TEXT DEFAULT '*', host TEXT DEFAULT '', username TEXT DEFAULT '', source_ip TEXT DEFAULT '',
  pattern TEXT DEFAULT '', starts TEXT, expires TEXT, reason TEXT NOT NULL, enabled INTEGER DEFAULT 1, hits INTEGER DEFAULT 0, last_hit TEXT, created_by TEXT, created_at TEXT);
CREATE TABLE IF NOT EXISTS whitelist_audit(id INTEGER PRIMARY KEY, ts TEXT, rule_id INTEGER, action TEXT, user TEXT, detail TEXT);
CREATE TABLE IF NOT EXISTS sx_state(key TEXT PRIMARY KEY, value TEXT, ts TEXT);
CREATE TABLE IF NOT EXISTS agent_health(host TEXT PRIMARY KEY, last_event TEXT, last_heartbeat TEXT, events_10m INTEGER DEFAULT 0, baseline_rate REAL DEFAULT 0, status TEXT DEFAULT 'Active', silent_alerted TEXT, updated TEXT);
CREATE TABLE IF NOT EXISTS mitre_map(rule TEXT PRIMARY KEY, mitre TEXT, tactic TEXT);
"""
