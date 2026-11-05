"""Unified event store schema (additive: existing tables are never altered or dropped)."""
SCHEMA_VERSION = 1
SCHEMA = """
CREATE TABLE IF NOT EXISTS norm_events(
  id INTEGER PRIMARY KEY, event_db_id INTEGER, schema_version INTEGER, dedupe_key TEXT UNIQUE,
  event_id INTEGER, event_record_id INTEGER, timestamp TEXT, ingested_at TEXT,
  host TEXT, hostname TEXT, platform TEXT, source TEXT, channel TEXT, provider TEXT,
  username TEXT, subject_user TEXT, target_username TEXT, logon_type TEXT, logon_id TEXT,
  source_ip TEXT, source_port INTEGER, destination_ip TEXT, destination_port INTEGER, protocol TEXT,
  process_id INTEGER, process_guid TEXT, process_name TEXT, image TEXT, command_line TEXT,
  parent_process_id INTEGER, parent_process_guid TEXT, parent_process_name TEXT, current_directory TEXT,
  hashes TEXT, integrity_level TEXT, dns_query_name TEXT, file_path TEXT, target_filename TEXT,
  registry_key TEXT, registry_value TEXT, service_name TEXT, task_name TEXT, group_name TEXT,
  rule_name TEXT, raw_event TEXT, collector_name TEXT, extra TEXT, activity TEXT);
CREATE INDEX IF NOT EXISTS ix_ne_act ON norm_events(source, activity, timestamp);
CREATE INDEX IF NOT EXISTS ix_ne_host_ts ON norm_events(host, timestamp);
CREATE INDEX IF NOT EXISTS ix_ne_ts ON norm_events(timestamp);
CREATE INDEX IF NOT EXISTS ix_ne_src_eid ON norm_events(source, event_id, timestamp);
CREATE INDEX IF NOT EXISTS ix_ne_user ON norm_events(target_username, timestamp);
CREATE INDEX IF NOT EXISTS ix_ne_sip ON norm_events(source_ip, timestamp);
CREATE INDEX IF NOT EXISTS ix_ne_dip ON norm_events(destination_ip, timestamp);
CREATE INDEX IF NOT EXISTS ix_ne_logon ON norm_events(host, logon_id);
CREATE INDEX IF NOT EXISTS ix_ne_pguid ON norm_events(process_guid);
CREATE INDEX IF NOT EXISTS ix_ne_pid ON norm_events(host, process_id);
CREATE INDEX IF NOT EXISTS ix_ne_evdb ON norm_events(event_db_id);
CREATE TABLE IF NOT EXISTS collector_state(host TEXT, source TEXT, channel TEXT, last_record_id INTEGER, last_event_ts TEXT, last_ingest_ts TEXT,
  events_total INTEGER DEFAULT 0, parse_errors INTEGER DEFAULT 0, dropped INTEGER DEFAULT 0, last_error TEXT, PRIMARY KEY(host, source, channel));
CREATE TABLE IF NOT EXISTS telemetry_flags(host TEXT, flag TEXT, detail TEXT, first_seen TEXT, last_seen TEXT, hits INTEGER DEFAULT 1, PRIMARY KEY(host, flag));
CREATE TABLE IF NOT EXISTS u_rule_cfg(rule_id TEXT PRIMARY KEY, enabled INTEGER, params TEXT, updated TEXT, updated_by TEXT);
CREATE TABLE IF NOT EXISTS u_allowlist(id INTEGER PRIMARY KEY, rule_id TEXT, field TEXT NOT NULL, value TEXT NOT NULL, reason TEXT, created TEXT, created_by TEXT);
CREATE TABLE IF NOT EXISTS u_alert_evidence(alert_id INTEGER PRIMARY KEY, rule_id TEXT, rule_version TEXT, confidence REAL, summary TEXT, evidence_ids TEXT,
  fp_notes TEXT, steps TEXT, mitre TEXT, first_seen TEXT, last_seen TEXT, host TEXT, account TEXT, event_ids TEXT);
CREATE TABLE IF NOT EXISTS u_status_history(id INTEGER PRIMARY KEY, alert_id INTEGER, ts TEXT, user TEXT, old_status TEXT, new_status TEXT, note TEXT);
CREATE INDEX IF NOT EXISTS ix_ush ON u_status_history(alert_id);
CREATE TABLE IF NOT EXISTS u_correlations(id INTEGER PRIMARY KEY, created TEXT, host TEXT, anchor TEXT, window_s INTEGER, confidence REAL, summary TEXT);
CREATE TABLE IF NOT EXISTS u_corr_links(corr_id INTEGER, from_id INTEGER, to_id INTEGER, reason TEXT, basis TEXT, confidence REAL);
CREATE INDEX IF NOT EXISTS ix_ucl ON u_corr_links(corr_id);
"""
