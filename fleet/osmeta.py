"""Operating-system classification for the Monitoring Center. Pure functions, no I/O.

Source of truth: what the AGENT read from /etc/os-release (ID, VERSION_ID) or reports as its platform family. The hostname is NEVER used.
Limitation (documented): the values are reported by an authenticated agent; the server cannot independently verify them, so a compromised agent could lie.

Classes: windows | ubuntu | linux (every other Linux distribution) | unknown.
  new agents  : os_family=windows -> windows; os_family=linux + distro_id=ubuntu -> ubuntu; linux + other distro_id -> linux; linux without a distro id -> linux, distribution "unknown".
  legacy agents (no os_family; they send only `os` = os-release NAME, or the kernel release when the file is missing): exact "Windows" -> windows; exact NAME "Ubuntu" -> ubuntu;
                 a NAME that says Linux (Debian GNU/Linux, Fedora Linux, Rocky Linux, ...) -> linux; anything else (including a bare kernel string) -> unknown.
Ubuntu derivatives that have their own ID (for example linuxmint, which only lists ubuntu in ID_LIKE) are NOT Ubuntu."""
import re

FAMILIES = ("windows", "linux", "darwin")
_ID_RX = re.compile(r"[a-z0-9][a-z0-9._-]{0,39}")
_VER_RX = re.compile(r"[A-Za-z0-9][A-Za-z0-9._~+-]{0,39}")
LINUX_NAME_STARTS = ("debian", "fedora", "centos", "rocky", "almalinux", "alpine", "opensuse", "suse", "raspbian", "pop!_os", "kali")

def clean_family(v):
    v = v.strip().lower() if isinstance(v, str) else ""
    return v if v in FAMILIES else None

def clean_distro_id(v):
    v = v.strip().lower() if isinstance(v, str) else ""
    return v if _ID_RX.fullmatch(v) else None

def clean_distro_version(v):
    v = v.strip() if isinstance(v, str) else ""
    return v if _VER_RX.fullmatch(v) else None

def classify(os_family=None, distro_id=None, os_name=None):
    """-> dict(os_class, distro_id, classified_by). `os_name` is the legacy free-text `os` field. Never raises, never looks at a hostname."""
    fam, did, name = clean_family(os_family), clean_distro_id(distro_id), (os_name or "").strip().casefold() if isinstance(os_name, str) else ""
    if fam == "windows": return dict(os_class="windows", distro_id=None, classified_by="os_family")
    if fam == "linux":
        if did == "ubuntu": return dict(os_class="ubuntu", distro_id="ubuntu", classified_by="os_release_id")
        if did: return dict(os_class="linux", distro_id=did, classified_by="os_release_id")
        if name == "ubuntu": return dict(os_class="ubuntu", distro_id="ubuntu", classified_by="legacy_os_name")
        return dict(os_class="linux", distro_id="unknown", classified_by="family_only")
    if fam == "darwin": return dict(os_class="unknown", distro_id=None, classified_by="os_family")
    if name == "windows": return dict(os_class="windows", distro_id=None, classified_by="legacy_os_name")
    if name == "ubuntu": return dict(os_class="ubuntu", distro_id="ubuntu", classified_by="legacy_os_name")
    if name and ("linux" in name or name.startswith(LINUX_NAME_STARTS)): return dict(os_class="linux", distro_id="unknown", classified_by="legacy_os_name")
    return dict(os_class="unknown", distro_id=None, classified_by="unclassified")
