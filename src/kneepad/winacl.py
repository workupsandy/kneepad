"""Windows access-control checks for Kneepad's state directory and audit key.

POSIX gets 0700/0600 modes. NTFS has ACLs instead, and the default ACL of a folder under the user profile is already private
(the account, SYSTEM and Administrators). That default is not guaranteed: ``KNEEPAD_HOME`` may point somewhere that inherits
"Users" or "Everyone" read access, for example under ``C:\\ProgramData`` or the root of another drive.

This module reads a path's ACL through ``icacls /save`` (the output is an SDDL string made of SIDs, so it does not depend on the
Windows display language), decides whether anybody besides the current user, SYSTEM and Administrators can reach it, and can
remove the extra access. It uses only ``icacls`` and ``whoami``, which ship with every supported Windows.

Nothing here runs on the hook path. It is used when the state directory or key is created, by ``kneepad init`` and by
``kneepad doctor``. Every function returns "unknown" or ``False`` on failure instead of raising.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

# SDDL two-letter aliases for the security identifiers that appear in ordinary ACLs.
_ALIASES = {
    "SY": "S-1-5-18", "BA": "S-1-5-32-544", "CO": "S-1-3-0", "OW": "S-1-3-4", "WD": "S-1-1-0", "BU": "S-1-5-32-545",
    "AU": "S-1-5-11", "IU": "S-1-5-4", "NU": "S-1-5-2", "AN": "S-1-5-7", "BG": "S-1-5-32-546", "LG": "S-1-5-32-546",
    "PU": "S-1-5-32-547", "SU": "S-1-5-6", "LS": "S-1-5-19", "NS": "S-1-5-20", "BO": "S-1-5-32-551", "SO": "S-1-5-32-549",
    "RC": "S-1-5-12", "CG": "S-1-3-1", "LU": "S-1-5-32-559", "WR": "S-1-5-33", "AC": "S-1-15-2-1",
}
_NAMES = {
    "S-1-1-0": "Everyone", "S-1-5-32-545": "BUILTIN\\Users", "S-1-5-11": "Authenticated Users", "S-1-5-4": "INTERACTIVE",
    "S-1-5-2": "NETWORK", "S-1-5-7": "ANONYMOUS LOGON", "S-1-5-32-546": "BUILTIN\\Guests", "S-1-5-32-547": "BUILTIN\\Power Users",
    "S-1-15-2-1": "ALL APPLICATION PACKAGES",
}
# Principals that may always have access: SYSTEM, Administrators, CREATOR OWNER, OWNER RIGHTS.
_ALWAYS_OK = frozenset({"S-1-5-18", "S-1-5-32-544", "S-1-3-0", "S-1-3-4"})
_ACE = re.compile(r"\(([^;()]*);([^;()]*);([^;()]*);([^;()]*);([^;()]*);([^;()]*)\)")


@dataclass
class AclReport:
    status: str  # "private" | "exposed" | "unknown"
    exposed: List[str] = field(default_factory=list)  # who else can reach the path
    detail: str = ""


def _run(args: List[str]) -> Tuple[int, str]:
    """Run a helper program and return (exit code, stdout). Isolated so tests can replace it."""
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=30, encoding="utf-8", errors="replace")
        return p.returncode, p.stdout
    except (OSError, subprocess.SubprocessError):
        return 127, ""


_me_cache: List[Optional[str]] = []


def current_user_sid() -> Optional[str]:
    """SID of the account running this process, or None when it cannot be determined."""
    if _me_cache:
        return _me_cache[0]
    sid: Optional[str] = None
    rc, out = _run(["whoami", "/user", "/fo", "csv", "/nh"])
    if rc == 0:
        m = re.search(r'"(S-1-[0-9-]+)"\s*$', out.strip())
        sid = m.group(1) if m else None
    _me_cache.append(sid)
    return sid


def parse_dacl(sddl: str) -> List[Tuple[str, str, str, str]]:
    """Return (type, flags, rights, sid) for each ACE in the DACL part of an SDDL string; aliases are expanded to SIDs."""
    text = sddl.strip()
    if "D:" in text:
        text = text.split("D:", 1)[1]
    text = text.split("S:", 1)[0]
    out = []
    for m in _ACE.finditer(text):
        typ, flags, rights, _og, _ig, sid = (g.strip() for g in m.groups())
        out.append((typ, flags, rights, _ALIASES.get(sid, sid)))
    return out


def exposed_principals(sddl: str, me: Optional[str]) -> List[str]:
    """Names (or SIDs) that an allow entry grants some access to, besides the current user and the always-fine principals."""
    seen: List[str] = []
    for typ, _flags, rights, sid in parse_dacl(sddl):
        if typ not in ("A", "OA") or not rights:
            continue
        if sid in _ALWAYS_OK or sid == me or sid.startswith("S-1-5-80-"):  # S-1-5-80-*: NT SERVICE accounts such as TrustedInstaller
            continue
        name = _NAMES.get(sid, sid)
        if name not in seen:
            seen.append(name)
    return seen


def read_sddl(path: str) -> Optional[str]:
    """The DACL of ``path`` as an SDDL string, or None."""
    d = tempfile.mkdtemp(prefix="kneepad-acl-")
    out = os.path.join(d, "acl.txt")
    try:
        rc, _ = _run(["icacls", path, "/save", out, "/c"])
        if rc != 0 or not os.path.exists(out):
            return None
        with open(out, "rb") as fh:
            raw = fh.read()
    except OSError:
        return None
    finally:
        shutil.rmtree(d, ignore_errors=True)
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        text = raw.decode("utf-16", "replace")
    elif b"\x00" in raw[:8]:
        text = raw.decode("utf-16-le", "replace")
    else:
        text = raw.decode("utf-8", "replace")
    for line in text.splitlines():
        line = line.strip().lstrip("\ufeff")
        if line.startswith("D:"):
            return line
    return None


def check(path: str) -> AclReport:
    """Who besides you, SYSTEM and Administrators can reach ``path``?"""
    me = current_user_sid()
    if me is None:
        return AclReport("unknown", detail="could not determine the current user")
    sddl = read_sddl(path)
    if sddl is None:
        return AclReport("unknown", detail="could not read the ACL (icacls unavailable or access denied)")
    extra = exposed_principals(sddl, me)
    if extra:
        return AclReport("exposed", extra, "also accessible to " + ", ".join(extra))
    return AclReport("private")


def tighten(path: str, is_dir: bool) -> bool:
    """Leave access to the current user, SYSTEM and Administrators only. True when the path ends up private."""
    me = current_user_sid()
    if me is None:
        return False
    before = check(path)
    if before.status == "private":
        return True
    suffix = "(OI)(CI)F" if is_dir else "F"
    grants = [f"*{me}:{suffix}", f"*S-1-5-18:{suffix}", f"*S-1-5-32-544:{suffix}"]
    # Grant ourselves first so removing inherited access can never lock this account out.
    _run(["icacls", path, "/grant:r"] + grants)
    _run(["icacls", path, "/inheritance:r"])
    sddl = read_sddl(path)
    if sddl is not None:
        for name in exposed_principals(sddl, me):
            sid = next((s for s, n in _NAMES.items() if n == name), name)
            if sid.startswith("S-1-"):
                _run(["icacls", path, "/remove:g", f"*{sid}"])
                _run(["icacls", path, "/remove:d", f"*{sid}"])
    return check(path).status == "private"


def tighten_if_exposed(path: str, is_dir: bool) -> Optional[bool]:
    """None when the ACL is already private or cannot be read; otherwise whether tightening worked."""
    rep = check(path)
    if rep.status != "exposed":
        return None
    return tighten(path, is_dir)
