"""Automated tests for the e-mail notification layer. Uses a local mock SMTP server only: no real e-mail is ever sent.
Run:  python -m unittest tests.test_notify -v        (from the project folder)"""
import os, sys, json, time, tempfile, unittest, io, contextlib, base64
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, ROOT)
_tmp = tempfile.mkdtemp(); os.environ["SOC_DB"] = os.path.join(_tmp, "t.db"); os.environ["SOC_LOCAL_LOGS"] = "0"
for k in ("SMTP_HOST", "SMTP_PORT", "SMTP_USERNAME", "SMTP_PASSWORD", "SMTP_SECURITY", "SMTP_ENABLED", "EMAIL_FROM", "SOC_BASE_URL", "SMTP_PASSWORD_FILE", "SMTP_ALLOW_INSECURE", "EMAIL_METHOD", "GMAIL_CLIENT_ID", "GMAIL_CLIENT_SECRET", "GMAIL_REFRESH_TOKEN", "GMAIL_REFRESH_TOKEN_FILE"): os.environ.pop(k, None)
import db; db.init_db()
import app as A, notify
from notify import config, smtpx, policy, render
from db import q, x
from tests.mock_smtp import MockSMTP
from tests.mock_gmail import MockGmail
from notify import gmailapi
SECRET = "S3cr3tPass!xyz"

def reset():
    for t in ("alerts", "events", "incidents", "incident_alerts", "alert_meta", "incident_notes", "notification_history", "notification_dedupe", "notification_escalation", "notification_recipients", "notification_settings", "whitelist", "endpoints", "iocs", "sx_state", "blocklist"):
        try: x(f"DELETE FROM {t}")
        except Exception: pass
    notify._TRIG.clear(); os.environ.pop("SMTP_PASSWORD", None)

class Base(unittest.TestCase):
    def setUp(self):
        reset(); self.srv = MockSMTP(); self.c = A.app.test_client(); self.login(self.c, "admin", "Admin@123")
        self.key = self.c.get("/api/settings").get_json()["api_key"]; self.configure()
    def tearDown(self): self.srv.stop(); os.environ.pop("SMTP_PASSWORD", None)
    def login(self, c, u, p): return c.post("/login", data={"username": u, "password": p})
    def H(self): return {"X-Requested-With": "fetch"}
    def api(self, method, path, body=None, client=None):
        return getattr(client or self.c, method)("/api/v1/notifications" + path, json=body, headers=self.H())
    def configure(self, **extra):
        v = {"enabled": "1", "smtp_host": "127.0.0.1", "smtp_port": str(self.srv.port), "smtp_security": "none", "email_from": "soc@example.com"}; v.update(extra)
        ok, err = config.set_values(v); self.assertTrue(ok, err)
        self.rec = self.api("post", "/recipients", {"email": "analyst1@example.com", "name": "A1"}).get_json()["id"]
    def ingest(self, items): return self.c.post("/api/ingest", json=items, headers={"X-API-Key": self.key}).get_json()
    def run_notify(self, rounds=1):
        n = 0
        for _ in range(rounds): n += notify.process_now()
        return n
    def hist(self, **w): return q("SELECT * FROM notification_history ORDER BY id")
    def heartbeat(self, host, os_="Ubuntu 24.04"): return self.c.post("/api/agent/heartbeat", json={"hostname": host, "os": os_, "cpu": 5, "ram": 30}, headers={"X-API-Key": self.key})
    def fail_logins(self, host="UBUNTU-001", ip="192.168.1.50", n=6, ident="sshd"):
        base = time.time(); items = []
        for i in range(n): items.append({"host": host, "channel": "journald", "provider": ident, "record_id": 1000 + i + int(base) % 100000, "message": f"Failed password for root from {ip} port 22 ssh2", "source_ip": ip, "log_only": False, "raw": "{}"})
        return self.ingest(items)
    def last_msg(self): return self.decode(self.srv.messages[-1]["data"])
    def html_part(self, raw):
        import email, email.policy
        m = email.message_from_string(raw, policy=email.policy.default); return next(p.get_content() for p in m.walk() if p.get_content_type() == "text/html")
    def decode(self, raw):
        """Subject + decoded text and HTML parts of a received MIME message (so assertions work on what the analyst reads)."""
        import email, email.policy
        m = email.message_from_string(raw, policy=email.policy.default); out = [f"Subject: {m['Subject']}", f"To: {m['To']}"]
        for part in m.walk():
            if part.get_content_type() in ("text/plain", "text/html"): out.append(part.get_content())
        return "\n".join(out)

class T01_Config(Base):
    def test_01_valid_configuration(self): self.assertEqual(config.validate_smtp(), [])
    def test_02_invalid_configuration(self):
        for bad in ({"smtp_port": "70000"}, {"smtp_security": "tls1"}, {"smtp_host": "bad host!"}, {"email_from": "nope"}, {"retry_delays": "a,b"}, {"base_url": "ftp://x"}):
            ok, err = config.set_values(bad); self.assertFalse(ok, bad)
        config.set_values({"smtp_host": "mail.example.com", "smtp_security": "none"}); self.assertTrue(any("Unencrypted" in p for p in config.validate_smtp()))
        config.set_values({"smtp_host": "", "smtp_security": "starttls"}); self.assertTrue(config.validate_smtp())
    def test_03_password_cannot_be_set_in_dashboard(self):
        r = self.api("put", "/settings", {"smtp_password": "x"}); self.assertEqual(r.status_code, 400); self.assertIn("environment", r.get_json()["error"])
        self.assertNotIn("password", json.dumps([dict(r) for r in q("SELECT * FROM notification_settings")]).lower().replace("smtp_password_file", ""))
    def test_04_env_overrides_and_is_locked(self):
        os.environ["SMTP_HOST"] = "envhost.example.com"
        try:
            s = self.api("get", "/settings").get_json()["settings"]["smtp_host"]; self.assertTrue(s["locked"]); self.assertEqual(s["value"], "envhost.example.com")
        finally: os.environ.pop("SMTP_HOST")
    def test_05_password_file_secret(self):
        p = os.path.join(_tmp, "pw"); open(p, "w").write(SECRET + "\n"); os.environ["SMTP_PASSWORD_FILE"] = p
        try: self.assertEqual(config.password(), SECRET)
        finally: os.environ.pop("SMTP_PASSWORD_FILE")

class T02_Smtp(Base):
    def test_01_test_email_success(self):
        r = self.api("post", "/test", {"recipient": "analyst1@example.com"}).get_json(); self.assertTrue(r["ok"]); self.assertIn("sent successfully", r["message"])
        self.assertEqual(len(self.srv.messages), 1); self.assertIn("Test email", self.decode(self.srv.messages[0]["data"]))
    def test_02_auth_success_with_password_from_env(self):
        self.srv.user, self.srv.password = "soc@example.com", SECRET; os.environ["SMTP_PASSWORD"] = SECRET; config.set_values({"smtp_username": "soc@example.com"})
        self.assertTrue(self.api("post", "/test", {}).get_json()["ok"]); self.assertEqual(self.srv.messages[0]["user"], "soc@example.com")
    def test_03_auth_failure_no_password_leak(self):
        self.srv.mode = "auth_fail"; os.environ["SMTP_PASSWORD"] = SECRET; config.set_values({"smtp_username": "soc@example.com"})
        r = self.api("post", "/test", {}); j = r.get_json(); self.assertFalse(j["ok"]); self.assertIn("authentication failed", j["message"]); self.assertNotIn(SECRET, r.get_data(as_text=True))
        self.assertNotIn(SECRET, json.dumps([dict(x_) for x_ in self.hist()], default=str))
    def test_04_connection_failure(self):
        self.srv.stop(); self.srv = MockSMTP(); config.set_values({"smtp_port": "1"})
        j = self.api("post", "/test", {}).get_json(); self.assertFalse(j["ok"]); self.assertIn("Cannot connect", j["message"])
    def test_05_unauthenticated_over_tls_less_connection_blocked_for_remote_host(self):
        cfg = config.smtp_config(); cfg.update(host="smtp.example.com", security="none", allow_insecure=False, username="u", password="p")
        with self.assertRaises(smtpx.NotifyError): smtpx.send(cfg, "a@example.com", "s", "<p>x</p>", "x")
    def test_06_starttls_and_ssl_use_correct_client(self):
        import smtplib; calls = []
        class FS:
            def __init__(s, *a, **k): calls.append(("SMTP", a[:2]))
            def ehlo(s): pass
            def starttls(s, context=None): calls.append("starttls")
            def login(s, *a): calls.append("login")
            def send_message(s, m): calls.append("send")
            def quit(s): pass
        class FSSL(FS):
            def __init__(s, *a, **k): calls.append(("SSL", a[:2]))
        old = (smtplib.SMTP, smtplib.SMTP_SSL); smtplib.SMTP, smtplib.SMTP_SSL = FS, FSSL
        try:
            cfg = dict(host="smtp.example.com", port=587, security="starttls", username="u", password="p", **{"from": "soc@example.com"}, allow_insecure=False); smtpx.send(cfg, "a@example.com", "s", "<p>x</p>", "x")
            self.assertEqual(calls[:4], [("SMTP", ("smtp.example.com", 587)), "starttls", "login", "send"]); calls.clear()
            cfg.update(security="ssl", port=465); smtpx.send(cfg, "a@example.com", "s", "<p>x</p>", "x"); self.assertEqual(calls[0], ("SSL", ("smtp.example.com", 465)))
        finally: smtplib.SMTP, smtplib.SMTP_SSL = old
    def test_07_header_injection_blocked(self):
        cfg = config.smtp_config()
        with self.assertRaises(smtpx.NotifyError): smtpx.send(cfg, "a@example.com\r\nBcc: x@evil.com", "s", "<p>x</p>", "x")

class T03_Alerts(Base):
    def test_01_critical_alert_email_linux_ubuntu(self):
        self.heartbeat("UBUNTU-001"); r = self.fail_logins(); self.assertTrue(any(r["alert_ids"])); self.run_notify()
        self.assertEqual(len(self.srv.messages), 1); m = self.last_msg(); self.assertIn("[CRITICAL] EXE-SOC", m); self.assertIn("UBUNTU-001", m); self.assertIn("Ubuntu 24.04", m); self.assertIn("192.168.1.50", m)
        for sec in ("Alert summary", "Recommended actions", "T1110"): self.assertIn(sec, m)
    def test_02_duplicate_alert_suppression_500_events(self):
        self.heartbeat("UBUNTU-001")
        for b in range(5): self.fail_logins(n=100, ip="192.168.1.50"); self.run_notify()
        self.assertEqual(len(self.srv.messages), 1, "500 failed logins must produce ONE email"); self.assertEqual(len(self.hist()), 1)
        self.assertGreaterEqual(q("SELECT suppressed FROM notification_dedupe", one=True)["suppressed"], 1)
    def test_03_rate_limit_then_update_after_window(self):
        self.heartbeat("UBUNTU-001"); self.fail_logins(); self.run_notify(); self.assertEqual(len(self.srv.messages), 1)
        x("UPDATE notification_dedupe SET last_sent=last_sent-3600"); self.fail_logins(n=20); self.run_notify()
        self.assertEqual(len(self.srv.messages), 2); self.assertIn("UPDATE", self.decode(self.srv.messages[1]["data"]))
    def test_04_new_incident_email_has_incident_id_and_link(self):
        config.set_values({"base_url": "https://soc.example.com"}); self.heartbeat("UBUNTU-001"); self.fail_logins(); self.run_notify(); m = self.last_msg(); inc = q("SELECT * FROM incidents", one=True)
        self.assertIn(render.code(inc["id"], inc["created"]), m); self.assertIn(f"https://soc.example.com/incidents?open={inc['id']}", m); self.assertIn("View Incident in EXE-SOC", m)
    def test_05_no_link_without_base_url(self):
        self.heartbeat("UBUNTU-001"); self.fail_logins(); self.run_notify(); self.assertNotIn("View Incident in EXE-SOC", self.last_msg())
    def test_06_medium_configurable(self):
        med = lambda h: self.ingest([{"host": h, "message": f"Medium test event on {h}", "severity": "Medium", "title": "Medium Test Detection", "category": "custom", "log_only": False}])
        med("H1"); self.run_notify(); self.assertEqual(len(self.srv.messages), 0)     # Medium: off by default
        config.set_values({"sev_medium": "1"}); med("H2"); self.run_notify(); self.assertEqual(len(self.srv.messages), 1); self.assertIn("[MEDIUM] EXE-SOC", self.last_msg())
    def test_07_agent_offline_email(self):
        from socx import correlation
        correlation.emit("HLT-001", "WIN-PC-7", None, None, "WIN-PC-7 sent no events for 40 min. Possible agent failure"); self.run_notify(); self.assertEqual(len(self.srv.messages), 1)
        m = self.last_msg(); self.assertIn("[HIGH] EXE-SOC", m); self.assertIn("Agent Offline", m); self.assertIn("WIN-PC-7", m)
    def test_08_network_scan_email(self):
        from socx import correlation
        correlation.emit("THR-005", "FW-1", "10.9.9.9", None, "50 ports contacted in 30 seconds by 10.9.9.9"); self.run_notify(); m = self.last_msg(); self.assertIn("[HIGH] EXE-SOC", m); self.assertIn("Network Scan", m)
    def test_09_large_outbound_email(self):
        from socx import correlation
        correlation.emit("THR-006", "SRV-1", "203.0.113.9", None, "3.2 GB sent to 203.0.113.9"); self.run_notify(); m = self.last_msg(); self.assertIn("Large Outbound", m); self.assertIn("[HIGH]", m)
    def test_10_ioc_email(self):
        x("INSERT INTO iocs(value,type,source,ts) VALUES('198.51.100.7','ip','test feed',datetime('now','localtime'))"); self.heartbeat("UBUNTU-001"); self.fail_logins(ip="198.51.100.7", n=3); self.run_notify()
        self.assertGreaterEqual(len(self.srv.messages), 1); m = self.last_msg(); self.assertIn("IOC Match", m); self.assertIn("[CRITICAL]", m)
    def test_11_windows_powershell_alert_email(self):
        self.heartbeat("WIN-PC-1", "Windows 11")
        raw = {"NewProcessName": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "CommandLine": "powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAA=", "SubjectUserName": "bob", "ParentProcessName": "C:\\Windows\\System32\\cmd.exe"}
        r = self.ingest([{"host": "WIN-PC-1", "channel": "Security", "event_id": 4688, "provider": "p", "record_id": 77, "message": "proc", "raw": json.dumps(raw), "log_only": True}]); self.assertTrue(any(r["alert_ids"])); self.run_notify()
        self.assertEqual(len(self.srv.messages), 1); m = self.last_msg(); self.assertIn("WIN-PC-1", m); self.assertIn("Windows 11", m); self.assertIn("[HIGH]", m)
    def test_12_whitelisted_alert_sends_nothing(self):
        x("INSERT INTO whitelist(kind,detection,host,reason,enabled,created_by,created_at) VALUES('approved_scanner','*','UBUNTU-001','test',1,'t',datetime('now','localtime'))")
        self.heartbeat("UBUNTU-001"); self.fail_logins(); self.run_notify(); self.assertEqual(len(self.srv.messages), 0)
    def test_13_per_recipient_severity(self):
        self.api("post", "/recipients", {"email": "critonly@example.com", "severities": ["Critical"]}); self.api("post", "/recipients", {"email": "mediumonly@example.com", "severities": ["Medium"]})
        self.heartbeat("UBUNTU-001"); self.fail_logins(); self.run_notify(); to = sorted(m["to"][0] for m in self.srv.messages); self.assertEqual(to, ["analyst1@example.com", "critonly@example.com"])
    def test_14_disabled_recipient_and_type(self):
        self.api("patch", f"/recipients/{self.rec}", {"enabled": False}); self.heartbeat("UBUNTU-001"); self.fail_logins(); self.run_notify(); self.assertEqual(len(self.srv.messages), 0)
    def test_15_master_switch_off(self):
        config.set_values({"enabled": "0"}); self.heartbeat("UBUNTU-001"); self.fail_logins(); self.run_notify(); self.assertEqual(len(self.srv.messages), 0)
    def test_16_email_content_is_escaped_and_redacted(self):
        self.heartbeat("UBUNTU-001"); self.ingest([{"host": "UBUNTU-001", "channel": "journald", "provider": "sshd", "record_id": 5, "source_ip": "192.168.1.60", "log_only": False, "raw": "{}",
            "message": "Failed password for <b>BOLDINJECT</b> from 192.168.1.60 port 22 ssh2 password=hunter2 token=abc123secret"} for _ in range(0)] or [{"host": "UBUNTU-001", "channel": "journald", "provider": "sshd", "record_id": 900 + i, "source_ip": "192.168.1.60", "log_only": False, "raw": "{}",
            "message": "Failed password for <b>BOLDINJECT</b> from 192.168.1.60 port 22 ssh2 password=hunter2 token=abc123secret"} for i in range(6)]); self.run_notify(); m = self.last_msg(); hp = self.html_part(self.srv.messages[-1]["data"])
        self.assertNotIn("<b>BOLDINJECT</b>", hp); self.assertIn("&lt;b&gt;BOLDINJECT", hp); self.assertNotIn("hunter2", m); self.assertNotIn("abc123secret", m)

class T04_Retry(Base):
    def test_01_retry_backoff_then_failed(self):
        self.srv.mode = "temp_fail"; config.set_values({"retry_delays": "30,120,300", "max_attempts": "4"}); self.heartbeat("UBUNTU-001"); self.fail_logins(); self.run_notify()
        h = self.hist()[0]; self.assertEqual((h["status"], h["attempts"]), ("RETRYING", 1)); self.assertTrue(22 <= h["next_try"] - time.time() <= 38, "base 30 s delay with +-25% jitter")
        for exp in (120, 300):
            x("UPDATE notification_history SET next_try=0"); notify.send_due(); h = self.hist()[0]; self.assertEqual(h["status"], "RETRYING"); self.assertTrue(exp * 0.75 - 3 <= h["next_try"] - time.time() <= exp * 1.25 + 1, "configured delay with +-25% jitter")
        x("UPDATE notification_history SET next_try=0"); notify.send_due(); h = self.hist()[0]; self.assertEqual((h["status"], h["attempts"]), ("FAILED", 4)); self.assertTrue(h["error"])
    def test_02_recovers_when_smtp_returns(self):
        self.srv.mode = "temp_fail"; self.heartbeat("UBUNTU-001"); self.fail_logins(); self.run_notify(); self.assertEqual(self.hist()[0]["status"], "RETRYING")
        self.srv.mode = "ok"; x("UPDATE notification_history SET next_try=0"); notify.send_due(); self.assertEqual(self.hist()[0]["status"], "SENT"); self.assertEqual(len(self.srv.messages), 1)
    def test_03_permanent_errors_do_not_retry(self):
        self.srv.mode = "reject_rcpt"; self.heartbeat("UBUNTU-001"); self.fail_logins(); self.run_notify(); h = self.hist()[0]; self.assertEqual((h["status"], h["attempts"]), ("FAILED", 1))
    def test_04_smtp_down_does_not_break_detection(self):
        self.srv.stop(); config.set_values({"smtp_port": "1"}); self.heartbeat("UBUNTU-001"); r = self.fail_logins(); self.assertTrue(any(r["alert_ids"]))
        self.run_notify(); self.assertGreaterEqual(q("SELECT COUNT(*) c FROM alerts", one=True)["c"], 1); self.assertGreaterEqual(q("SELECT COUNT(*) c FROM incidents", one=True)["c"], 1)
        st = self.api("get", "/status").get_json(); self.assertEqual(st["state"], "DEGRADED"); self.assertIn("retry", st["message"]); self.assertEqual(self.c.get("/alerts").status_code, 200); self.srv = MockSMTP()
    def test_05_hook_never_blocks_or_raises(self):
        import unittest.mock as M
        with M.patch("notify.policy.decide", side_effect=RuntimeError("boom")): notify.on_alert(1, None); notify.process_now()      # must not raise
    def test_06_manual_retry_of_failed(self):
        self.srv.mode = "temp_fail"; config.set_values({"max_attempts": "1"}); self.heartbeat("UBUNTU-001"); self.fail_logins(); self.run_notify(); h = self.hist()[0]; self.assertEqual(h["status"], "FAILED")
        self.srv.mode = "ok"; self.assertEqual(self.api("post", f"/history/{h['id']}/retry").status_code, 200); notify.send_due(); self.assertEqual(self.hist()[0]["status"], "SENT")

class T05_Escalation(Base):
    def test_01_escalates_unacknowledged_incident_to_level2(self):
        self.api("post", "/recipients", {"email": "lead@example.com", "level": 2}); config.set_values({"escalation_enabled": "1", "escalation_min": "15"}); self.heartbeat("UBUNTU-001"); self.fail_logins(); self.run_notify()
        self.assertEqual([m["to"][0] for m in self.srv.messages], ["analyst1@example.com"])
        x("UPDATE notification_dedupe SET first_sent=first_sent-3600"); self.run_notify(); self.assertEqual(sorted(m["to"][0] for m in self.srv.messages), ["analyst1@example.com", "lead@example.com"]); self.assertIn("ESCALATION", self.decode(self.srv.messages[-1]["data"]))
        self.run_notify(); self.assertEqual(len(self.srv.messages), 2)       # only once
    def test_02_no_escalation_when_acknowledged(self):
        self.api("post", "/recipients", {"email": "lead@example.com", "level": 2}); config.set_values({"escalation_enabled": "1"}); self.heartbeat("UBUNTU-001"); self.fail_logins(); self.run_notify()
        x("UPDATE incidents SET status='In Progress'"); x("UPDATE notification_dedupe SET first_sent=first_sent-3600"); self.run_notify(); self.assertEqual(len(self.srv.messages), 1)

class T06_Api(Base):
    def test_01_audit_log_and_history(self):
        self.heartbeat("UBUNTU-001"); self.fail_logins(); self.run_notify(); h = self.api("get", "/history").get_json()["rows"]; self.assertEqual(len(h), 1); r = h[0]
        for k in ("notification_id", "incident_id", "alert_id", "recipient", "subject", "severity", "ts", "status", "error"): self.assertIn(k, r)
        self.assertEqual((r["status"], r["recipient"], r["severity"]), ("SENT", "analyst1@example.com", "Critical")); self.assertNotIn("body_html", r)
        self.assertIsNone(q("SELECT body_html FROM notification_history", one=True)["body_html"])
        self.assertEqual(len(self.api("get", "/history?status=FAILED").get_json()["rows"]), 0)
    def test_02_unauthorized_changes(self):
        an = A.app.test_client(); self.login(an, "analyst", "Analyst@123"); vw = A.app.test_client(); self.login(vw, "viewer", "Viewer@123"); anon = A.app.test_client()
        self.assertEqual(self.api("put", "/settings", {"smtp_host": "evil.example.com"}, an).status_code, 403); self.assertEqual(self.api("post", "/test", {}, an).status_code, 403)
        self.assertEqual(self.api("post", "/recipients", {"email": "x@example.com"}, an).status_code, 403); self.assertEqual(self.api("delete", f"/recipients/{self.rec}", None, an).status_code, 403)
        self.assertEqual(self.api("get", "/history", None, an).status_code, 200); self.assertEqual(self.api("get", "/settings", None, an).status_code, 200)
        self.assertEqual(self.api("get", "/history", None, vw).status_code, 403); self.assertEqual(self.api("get", "/settings", None, vw).status_code, 403); self.assertEqual(self.api("put", "/settings", {}, anon).status_code, 401)
        self.assertEqual(config.get("smtp_host"), "127.0.0.1")
    def test_03_csrf_header_required(self):
        self.assertEqual(self.c.put("/api/v1/notifications/settings", json={"enabled": "0"}).status_code, 400)
    def test_04_recipient_validation(self):
        for bad in ("nope", "a@b", "x@example.com\r\nBcc:y@evil.com", "", "<script>@x.com"): self.assertEqual(self.api("post", "/recipients", {"email": bad}).status_code, 400, bad)
        self.assertEqual(self.api("post", "/recipients", {"email": "analyst1@example.com"}).status_code, 409); self.assertEqual(self.api("post", "/recipients", {"email": "z@example.com", "severities": ["Bogus"]}).status_code, 400)
    def test_05_recipient_add_remove_toggle_test(self):
        i = self.api("post", "/recipients", {"email": "soc-team@example.com", "name": "Team"}).get_json()["id"]; self.assertEqual(self.api("patch", f"/recipients/{i}", {"enabled": False}).status_code, 200)
        self.assertEqual(self.api("post", f"/recipients/{i}/test").get_json()["ok"], True); self.assertEqual(self.api("delete", f"/recipients/{i}").status_code, 200)
        self.assertNotIn("soc-team@example.com", [r["email"] for r in self.api("get", "/recipients").get_json()])
    def test_06_dashboard_settings_and_page(self):
        s = self.api("get", "/settings").get_json(); self.assertEqual(set(s["types"]), {"new_incident", "high_alert", "ioc", "agent_offline", "large_outbound", "network_attack", "auth_attack"}); self.assertEqual(s["severities"], ["Critical", "High", "Medium", "Low", "Info"])
        self.assertEqual(s["settings"]["sev_critical"]["value"], "1"); self.assertEqual(s["settings"]["sev_medium"]["value"], "0"); self.assertEqual(self.c.get("/email-notifications").status_code, 200); self.assertIn("/email-notifications", self.c.get("/").get_data(as_text=True))
        self.assertTrue(self.api("get", "/providers").get_json())
    def test_07_audit_trail_has_changes_not_secrets(self):
        os.environ["SMTP_PASSWORD"] = SECRET; self.api("put", "/settings", {"smtp_host": "mail.example.com"}); self.api("post", "/test", {}); rows = " ".join(r["action"] for r in q("SELECT action FROM audit"))
        self.assertIn("email notification settings", rows); self.assertNotIn(SECRET, rows)
    def test_08_password_never_in_any_api_response_or_log(self):
        os.environ["SMTP_PASSWORD"] = SECRET; buf = io.StringIO(); self.srv.mode = "auth_fail"; config.set_values({"smtp_username": "u@example.com"})
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            self.api("post", "/test", {}); self.heartbeat("UBUNTU-001"); self.fail_logins(); self.run_notify()
        dump = buf.getvalue() + self.api("get", "/settings").get_data(as_text=True) + self.api("get", "/history").get_data(as_text=True) + self.api("get", "/status").get_data(as_text=True)
        self.assertNotIn(SECRET, dump); self.assertTrue(self.api("get", "/settings").get_json()["status"]["password_configured"])

GSECRET, GREFRESH = "GOCSPX-clientSecret123", "1//0refreshTokenValueXYZ"
class T07_GmailApi(Base):
    """Gmail API transport against a local mock of Google's token and send endpoints. Real Google is never contacted."""
    def setUp(self):
        super().setUp(); self.g = MockGmail(); self._old = (gmailapi.TOKEN_URL, gmailapi.SEND_URL); gmailapi.TOKEN_URL, gmailapi.SEND_URL = self.g.token_url, self.g.send_url
        gmailapi._CACHE.clear(); os.environ.update(GMAIL_CLIENT_ID="cid.apps.googleusercontent.com", GMAIL_CLIENT_SECRET=GSECRET, GMAIL_REFRESH_TOKEN=GREFRESH, NO_PROXY="127.0.0.1", no_proxy="127.0.0.1")
        ok, err = config.set_values({"email_method": "gmail_api"}); self.assertTrue(ok, err)
    def tearDown(self):
        self.g.stop(); gmailapi.TOKEN_URL, gmailapi.SEND_URL = self._old; gmailapi._CACHE.clear()
        for k in ("GMAIL_CLIENT_ID", "GMAIL_CLIENT_SECRET", "GMAIL_REFRESH_TOKEN", "GMAIL_REFRESH_TOKEN_FILE", "EMAIL_METHOD"): os.environ.pop(k, None)
        super().tearDown()
    def test_01_validation(self):
        self.assertEqual(config.validate_smtp(), [])
        os.environ.pop("GMAIL_REFRESH_TOKEN"); self.assertTrue(any("GMAIL_REFRESH_TOKEN" in p for p in config.validate_smtp()))
        os.environ["GMAIL_REFRESH_TOKEN"] = GREFRESH; config.set_values({"email_from": ""}) if False else None
        ok, err = config.set_values({"email_method": "pigeon"}); self.assertFalse(ok)
    def test_02_test_email_sent_with_bearer_token(self):
        r = self.api("post", "/test", {"recipient": "analyst1@example.com"}).get_json(); self.assertTrue(r["ok"], r); self.assertEqual(len(self.g.messages), 1); self.assertEqual(len(self.srv.messages), 0)
        self.assertEqual(self.g.messages[0]["auth"], "Bearer ya29.mock-1"); m = self.decode(self.g.messages[0]["data"]); self.assertIn("Test email", m); self.assertIn("To: analyst1@example.com", m)
        t = self.g.token_requests[0]; self.assertEqual((t["grant_type"], t["refresh_token"], t["client_secret"]), ("refresh_token", GREFRESH, GSECRET))
    def test_03_access_token_is_cached(self):
        for _ in range(3): self.assertTrue(self.api("post", "/test", {"recipient": "analyst1@example.com"}).get_json()["ok"])
        self.assertEqual(len(self.g.token_requests), 1); self.assertEqual(len(self.g.messages), 3)
    def test_04_expired_access_token_refreshes_and_retries(self):
        self.g.mode = "send_401_once"; r = self.api("post", "/test", {"recipient": "analyst1@example.com"}).get_json(); self.assertTrue(r["ok"], r); self.assertEqual(len(self.g.token_requests), 2)
    def test_05_revoked_or_expired_refresh_token_is_permanent_with_hint(self):
        self.g.mode = "invalid_grant"; self.api("post", "/test", {"recipient": "analyst1@example.com"})
        h = self.hist()[-1]; self.assertEqual(h["status"], "FAILED"); self.assertIn("gmail_auth.py", h["error"]); self.assertNotIn(GREFRESH, h["error"] + str(self.hist()))
        self.fail_logins(); self.heartbeat("UBUNTU-001"); self.run_notify(3); self.assertTrue(all(r["attempts"] == 1 for r in self.hist() if r["status"] == "FAILED"))
    def test_06_invalid_client(self):
        self.g.mode = "invalid_client"; r = self.api("post", "/test", {"recipient": "analyst1@example.com"}).get_json(); self.assertFalse(r["ok"]); self.assertIn("GMAIL_CLIENT_ID", r["message"])
    def test_07_temporary_errors_retry_permanent_do_not(self):
        for mode, status in (("rate_limit", "RETRYING"), ("server_error", "RETRYING"), ("insufficient_scope", "FAILED"), ("api_disabled", "FAILED"), ("bad_request", "FAILED")):
            reset(); self.g.mode = mode; gmailapi._CACHE.clear(); self.configure(email_method="gmail_api"); self.fail_logins(); self.heartbeat("UBUNTU-001"); self.run_notify()
            rows = self.hist(); self.assertTrue(rows, mode); self.assertEqual(rows[0]["status"], status, (mode, rows[0]["status"], rows[0]["error"]))
    def test_08_connection_failure_is_retried(self):
        gmailapi.SEND_URL = "http://127.0.0.1:1/send"; self.fail_logins(); self.heartbeat("UBUNTU-001"); self.run_notify()
        self.assertEqual(self.hist()[0]["status"], "RETRYING"); self.assertIn("Cannot reach Google", self.hist()[0]["error"])
    def test_09_alert_email_end_to_end(self):
        self.heartbeat("UBUNTU-001"); self.fail_logins(); self.run_notify(); rows = self.hist(); self.assertEqual([r["status"] for r in rows], ["SENT"]); self.assertEqual(len(self.g.messages), 1); self.assertEqual(len(self.srv.messages), 0)
        m = self.decode(self.g.messages[0]["data"]); self.assertIn("UBUNTU-001", m)
    def test_10_credentials_never_exposed(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            self.g.mode = "invalid_grant"; self.api("post", "/test", {}); self.g.mode = "ok"; gmailapi._CACHE.clear(); self.api("post", "/test", {}); self.heartbeat("UBUNTU-001"); self.fail_logins(); self.run_notify()
        dump = buf.getvalue() + "".join(self.api("get", p).get_data(as_text=True) for p in ("/settings", "/history", "/status")) + str(q("SELECT * FROM audit")) + str(q("SELECT * FROM notification_settings")) + str(q("SELECT error FROM notification_history"))
        for sec in (GSECRET, GREFRESH): self.assertNotIn(sec, dump)
        st = self.api("get", "/settings").get_json(); self.assertEqual(st["gmail"], {"client_id": True, "client_secret": True, "refresh_token": True}); self.assertEqual(st["status"]["method"], "gmail_api")
        ok, err = config.set_values({"gmail_refresh_token": "x"}); self.assertFalse(ok)
    def test_11_secret_from_file_and_env_lock(self):
        f = os.path.join(_tmp, "rt"); open(f, "w").write(GREFRESH + "\n"); os.environ.pop("GMAIL_REFRESH_TOKEN"); os.environ["GMAIL_REFRESH_TOKEN_FILE"] = f
        self.assertEqual(config.gmail_creds()["refresh_token"], GREFRESH); self.assertTrue(self.api("post", "/test", {}).get_json()["ok"])
        os.environ["EMAIL_METHOD"] = "smtp"; s = self.api("get", "/settings").get_json()["settings"]["email_method"]; self.assertTrue(s["locked"]); self.assertEqual(s["value"], "smtp")
    def test_12_switching_back_to_smtp_uses_smtp(self):
        config.set_values({"email_method": "smtp"}); self.assertTrue(self.api("post", "/test", {}).get_json()["ok"]); self.assertEqual((len(self.srv.messages), len(self.g.messages)), (1, 0))
    def test_13_header_injection_still_blocked(self):
        with self.assertRaises(smtpx.NotifyError): smtpx.send(config.smtp_config(), "a@b.com\r\nBcc: x@y.com", "s", "<p>h</p>", "t")

class T08_Helpers(unittest.TestCase):
    def test_env_loader(self):
        import envload
        p = os.path.join(_tmp, "t.env"); open(p, "w").write("# c\nA1=plain   # inline\nexport A2=\"quoted # kept\"\nA3=<placeholder>\nA4=\nA5=fromfile\nbad key=1\n"); os.environ["A5"] = "fromenv"
        for k in ("A1", "A2", "A3", "A4"): os.environ.pop(k, None)
        envload.load(p); self.assertEqual((os.environ.get("A1"), os.environ.get("A2"), os.environ.get("A3"), os.environ.get("A4"), os.environ.get("A5")), ("plain", "quoted # kept", None, None, "fromenv"))
        for k in ("A1", "A2", "A5"): os.environ.pop(k, None)
    def test_gmail_auth_helper(self):
        sys.path.insert(0, os.path.join(ROOT, "tools")); import gmail_auth as G, urllib.parse
        v, c = G.pkce(); import hashlib; self.assertEqual(c, base64.urlsafe_b64encode(hashlib.sha256(v.encode()).digest()).decode().rstrip("="))
        u = urllib.parse.urlparse(G.auth_url("cid", "http://127.0.0.1:9", "st", c)); qs = urllib.parse.parse_qs(u.query)
        self.assertEqual((qs["scope"][0], qs["access_type"][0], qs["code_challenge_method"][0]), (G.SCOPE, "offline", "S256")); self.assertNotIn("mail.google.com", u.query)
        p = os.path.join(_tmp, "u.env"); open(p, "w").write("KEEP=1\nGMAIL_CLIENT_ID=old\n# note\n"); G.upsert_env(p, {"GMAIL_CLIENT_ID": "new", "GMAIL_REFRESH_TOKEN": "rt"}); t = open(p).read()
        self.assertIn("KEEP=1", t); self.assertIn("GMAIL_CLIENT_ID=new", t); self.assertNotIn("=old", t); self.assertIn("GMAIL_REFRESH_TOKEN=rt", t)
        os.environ["NO_PROXY"] = "127.0.0.1"; g = MockGmail()
        try:
            def tok(): return G.exchange("cid", "sec", "code", "http://127.0.0.1:9", v, token_url=g.token_url)
            with self.assertRaises(SystemExit): tok()                       # mock returns no refresh_token for the auth-code grant
        finally: g.stop()

if __name__ == "__main__": unittest.main(verbosity=2)
