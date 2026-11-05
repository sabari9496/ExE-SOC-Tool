"""Fleet (multi-endpoint) tables. Additive only: existing tables are never dropped; columns are added with ALTER in init()."""
SCHEMA = """
CREATE TABLE IF NOT EXISTS agents(
  id TEXT PRIMARY KEY, hostname TEXT NOT NULL, device_name TEXT, os TEXT, os_version TEXT, ip TEXT, ips TEXT, agent_version TEXT,
  registered_at TEXT, last_heartbeat TEXT, last_event_at TEXT, status TEXT DEFAULT 'active', monitoring TEXT DEFAULT 'active',
  credential_id TEXT, enrolled_by TEXT, owner_note TEXT, endpoint_id INTEGER, events_total INTEGER DEFAULT 0, health TEXT);
CREATE TABLE IF NOT EXISTS agent_credentials(
  credential_id TEXT PRIMARY KEY, agent_id TEXT NOT NULL, secret_hash TEXT NOT NULL, created_at TEXT, revoked_at TEXT, revoked_by TEXT,
  FOREIGN KEY(agent_id) REFERENCES agents(id));
CREATE TABLE IF NOT EXISTS enrollment_tokens(
  id INTEGER PRIMARY KEY, token_hash TEXT UNIQUE NOT NULL, label TEXT, created_by TEXT, created_at TEXT, expires_at TEXT,
  used_at TEXT, used_by_agent TEXT, revoked_at TEXT, revoked_by TEXT);
CREATE TABLE IF NOT EXISTS agent_heartbeats(
  id INTEGER PRIMARY KEY, agent_id TEXT NOT NULL, ts TEXT NOT NULL, cpu REAL, mem REAL, events_sent INTEGER, events_queued INTEGER,
  upload_failures INTEGER, last_success TEXT, version TEXT, ip TEXT);
CREATE TABLE IF NOT EXISTS agent_event_ids(agent_id TEXT NOT NULL, uid TEXT NOT NULL, ts TEXT, status TEXT NOT NULL DEFAULT 'processed', claimed_at TEXT, PRIMARY KEY(agent_id, uid)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS event_quarantine(
  id INTEGER PRIMARY KEY, agent_id TEXT NOT NULL, uid TEXT NOT NULL, reason TEXT NOT NULL, attempts INTEGER DEFAULT 0, payload TEXT,
  created_at TEXT NOT NULL, replayed_at TEXT, UNIQUE(agent_id, uid));
CREATE INDEX IF NOT EXISTS ix_quar_agent ON event_quarantine(agent_id, id);
CREATE TABLE IF NOT EXISTS agent_nonces(nonce TEXT PRIMARY KEY, ts REAL) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS ix_agents_status ON agents(status, last_heartbeat);
CREATE INDEX IF NOT EXISTS ix_agents_host ON agents(hostname);
CREATE INDEX IF NOT EXISTS ix_hb_agent ON agent_heartbeats(agent_id, ts);
CREATE INDEX IF NOT EXISTS ix_tok_exp ON enrollment_tokens(expires_at);
CREATE INDEX IF NOT EXISTS ix_aev_ts ON agent_event_ids(ts);
"""
# columns added to existing tables (agent_id lets events/alerts be queried per endpoint without relying on hostnames)
ALTERS = {"events": [("agent_id", "TEXT")], "alerts": [("agent_id", "TEXT")],
          "agent_credentials": [("sign_key_enc", "TEXT"), ("scopes", "TEXT"), ("sig_required", "INTEGER DEFAULT 0"), ("last_used", "TEXT"), ("legacy_uses", "INTEGER DEFAULT 0")],
          "agent_event_ids": [("status", "TEXT NOT NULL DEFAULT 'processed'"), ("claimed_at", "TEXT"), ("attempts", "INTEGER DEFAULT 0"), ("last_error", "TEXT")]}
INDEXES = """
CREATE INDEX IF NOT EXISTS ix_ev_agent ON events(agent_id, id);
CREATE INDEX IF NOT EXISTS ix_ev_agent_ts ON events(agent_id, ts);
CREATE INDEX IF NOT EXISTS ix_ev_sev ON events(risk, ts);
CREATE INDEX IF NOT EXISTS ix_al_agent ON alerts(agent_id, id);
CREATE INDEX IF NOT EXISTS ix_al_sev ON alerts(severity, ts);
CREATE INDEX IF NOT EXISTS ix_al_status ON alerts(status, ts);
"""
