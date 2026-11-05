"""Threat intelligence: extract IOCs from text/events and match them against the existing iocs table (ip/domain/hash/url/email) and blocklist."""
import re
from db import q
IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"); DOM = re.compile(r"\b(?:[a-z0-9-]{1,63}\.)+(?:[a-z]{2,24})\b", re.I)
SHA256 = re.compile(r"\b[a-f0-9]{64}\b", re.I); SHA1 = re.compile(r"\b[a-f0-9]{40}\b", re.I); MD5 = re.compile(r"\b[a-f0-9]{32}\b", re.I)
URL = re.compile(r"https?://[^\s'\"<>]+", re.I); MAIL = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
FILE_EXT = {"exe", "dll", "ps1", "bat", "cmd", "vbs", "js", "log", "txt", "conf", "dat", "tmp", "sys", "msi", "lnk", "py", "sh"}

def extract(text):
    t = text or ""; out = {"ip": set(IP.findall(t)), "sha256": set(m.lower() for m in SHA256.findall(t)), "url": set(URL.findall(t)), "email": set(MAIL.findall(t))}
    out["sha1"] = {m.lower() for m in SHA1.findall(t)} - {h[:40] for h in out["sha256"]}
    out["md5"] = {m.lower() for m in MD5.findall(t)} - {h[:32] for h in out["sha256"] | out["sha1"]}
    mail_doms = {m.split("@")[-1].lower() for m in out["email"]}
    out["domain"] = {d.lower() for d in DOM.findall(t) if d.rsplit(".", 1)[-1].lower() not in FILE_EXT and not IP.fullmatch(d)} - mail_doms
    return {k: sorted(v) for k, v in out.items() if v}

def lookup(text):
    """-> list of {type, value, source} for every IOC in `text` that is on the threat list or blocklist."""
    hits = []
    for typ, vals in extract(text).items():
        for v in vals:
            r = q("SELECT source FROM iocs WHERE lower(value)=lower(?)", (v,), one=True)
            if r: hits.append(dict(type=typ, value=v, source=r["source"] or "threat list"))
            elif typ == "ip" and q("SELECT reason FROM blocklist WHERE ip=?", (v,), one=True): hits.append(dict(type="ip", value=v, source="blocklist"))
    return hits
