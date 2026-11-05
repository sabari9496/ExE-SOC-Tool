"""Builds the local collector for this operating system: logs (Windows Event Log or Linux journal + files) + file integrity monitoring + malware scan."""
import platform, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

class MultiCollector:
    def __init__(self, parts, names): self.parts = parts; self.names = names; self.errs = {}
    @property
    def sources(self): return list(getattr(self.parts[0], "sources", None) or getattr(self.parts[0], "channels", [])) + self.names
    @property
    def backlog(self): return any(getattr(p, "backlog", False) for p in self.parts)
    @property
    def interval(self): return self.parts[0].interval
    def poll(self, host):
        out = []
        for p in self.parts:
            name = type(p).__name__
            try: out += p.poll(host); self.errs.pop(name, None)
            except Exception as e:
                if self.errs.get(name) != str(e): print(f"collector {name}: {e}")           # printed once per distinct error, and reported to the SOC via problems()
                self.errs[name] = str(e)
        return out
    def problems(self):
        out = []
        for p in self.parts:
            f = getattr(p, "problems", None)
            if f: out += f()
        return out + [f"{k}: {v}"[:120] for k, v in self.errs.items()]
    def commit(self):
        for p in self.parts: p.commit()

def get_collector(cursor_file=None):
    if platform.system() == "Windows":
        import winevents; base = winevents.Collector(cursor_file=cursor_file)
    else:
        import linuxlogs; base = linuxlogs.Collector(cursor_file=cursor_file)
    d = os.path.dirname(cursor_file) if cursor_file else os.path.dirname(os.path.abspath(__file__)); parts = [base]; names = []
    if os.environ.get("SOC_FIM", "1") != "0":
        import fim; parts.append(fim.FimScanner(os.path.join(d, ".fim_state.json"))); names.append("file integrity monitoring")
    if os.environ.get("SOC_MALWARE", "1") != "0":
        import malware; parts.append(malware.MalwareScanner(os.path.join(d, ".malware_state.json"))); names.append("malware scan")
    if os.environ.get("SOC_ACTIVITY", "1") != "0":
        import procmon; parts.append(procmon.ActivityMonitor()); names.append("process and network monitor")
    return MultiCollector(parts, names)
