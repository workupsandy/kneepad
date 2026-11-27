"""Small shared helpers: paths, time, redaction."""

from __future__ import annotations

import os
import re
import shlex
import sys
from datetime import datetime, timezone


def kneepad_home() -> str:
    """Directory holding the key, audit log, snapshots and user config."""
    return os.environ.get("KNEEPAD_HOME") or os.path.join(os.path.expanduser("~"), ".kneepad")


def user_home() -> str:
    return os.path.expanduser("~")


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def is_windows() -> bool:
    return sys.platform == "win32"


def ensure_private_dir(path: str) -> None:
    os.makedirs(path, mode=0o700, exist_ok=True)
    if is_windows():
        return  # POSIX mode bits mean nothing on NTFS; the user profile is private to the account by default
    try:  # a directory we did not create may be too open; tighten it if we own it
        st = os.stat(path)
        if st.st_uid == os.getuid() and (st.st_mode & 0o077):
            os.chmod(path, 0o700)
    except OSError:
        pass


def quote_exe(path: str, windows: "bool | None" = None) -> str:
    """Quote an executable path for a hook command line.

    On Windows hook commands are run by cmd.exe, PowerShell or Git Bash depending on the agent, so the
    one form that works in all three is forward slashes inside double quotes when quoting is needed.
    """
    win = is_windows() if windows is None else windows
    if not win:
        return shlex.quote(path)
    p = path.replace("\\", "/")
    return f'"{p}"' if re.search(r"[\s&()^%!;,\[\]{}=+~`$]", p) else p


# Best-effort secret redaction for anything written to the audit log.
_REDACTIONS = [
    (
        re.compile(
            r"(?i)\b([A-Za-z0-9_.-]*(?:password|passwd|secret|token|api[_-]?key|apikey|access[_-]?key))"
            r"\b(\s*[=:]\s*)(\"[^\"]*\"|'[^']*'|\S+)"
        ),
        r"\1\2[REDACTED]",
    ),
    (re.compile(r"(?i)(--(?:password|token|secret|api-key)\s+)(\S+)"), r"\1[REDACTED]"),
    (re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+"), "Bearer [REDACTED]"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED-AWS-KEY]"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"), "[REDACTED-GITHUB-TOKEN]"),
    (re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"), "[REDACTED-API-KEY]"),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "[REDACTED-SLACK-TOKEN]"),
    (re.compile(r"(://[^/\s:@]+:)[^/\s@]+(@)"), r"\1[REDACTED]\2"),
]


def redact(text: str, limit: int = 4096) -> str:
    """Redact obvious secrets and truncate. Best effort, not a guarantee."""
    out = text if len(text) <= limit else text[:limit] + "...[truncated]"
    for pat, repl in _REDACTIONS:
        out = pat.sub(repl, out)
    return out


_OURS_RE = re.compile(r"""(?:(?:^|[\s"'/\\&])kneepad(?:\.exe)?|-m\s+kneepad)["']?\s+hook\s+[a-z]+\b""", re.I)


def is_kneepad_hook_command(cmd: str) -> bool:
    """True only for a command that runs Kneepad's own hook (`kneepad hook X` or `python -m kneepad hook X`).

    A user's unrelated command that merely contains the words "kneepad" and "hook" is not ours and must never be
    removed by `uninstall`.
    """
    return _OURS_RE.search(cmd) is not None
