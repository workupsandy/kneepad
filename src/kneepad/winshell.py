"""Windows command analysis: cmd.exe and PowerShell tokenising, path classification, delete handling.

The POSIX lexer in shellparse.py treats a backslash as an escape, so `C:\\Windows` becomes
`C:Windows`. This module reads the same text with Windows rules instead and feeds the same
engine. It runs on every command string (see Analyzer._walk), so it also works on Linux and
macOS when an agent shells out to pwsh or cmd.

Honest limits: this is a tokenizer plus pattern rules, not a PowerShell parser. Script blocks,
variables set in earlier statements and aliases defined by the user are not resolved. Anything
that cannot be resolved is treated as dynamic and, when it feeds a recursive delete, asked about.
"""

from __future__ import annotations

import base64
import binascii
import glob
import ntpath
import os
import re
from typing import Dict, List, Optional, Tuple

from .argvtools import ParsedArgv, parse_argv
from .rules import match_argv
from .shellparse import Word
from .snapshots import SnapshotPlan, estimate_size

_DRIVE = re.compile(r"^[A-Za-z]:(?:[\\/]|$)")
_EXTS = (".exe", ".cmd", ".bat", ".com", ".ps1", ".vbs", ".msc")


def looks_windows(p: str) -> bool:
    return bool(_DRIVE.match(p)) or p.startswith("\\\\")


def has_marker(text: str) -> bool:
    """True when a token carries Windows path or variable syntax the POSIX lexer would mangle."""
    return bool(
        "\\" in text
        or re.search(r"%[A-Za-z_]\w*%", text)
        or re.search(r"(?i)\$env:|\$\{env:", text)
        or _DRIVE.match(text)
    )


def win_name(tok: str) -> str:
    base = tok.replace("/", "\\").rstrip("\\").rsplit("\\", 1)[-1].lower()
    for ext in _EXTS:
        if base.endswith(ext):
            return base[: -len(ext)]
    return base


# --------------------------------------------------------------------------- tokenising
class Tok:
    __slots__ = ("text", "quoted")

    def __init__(self, text: str, quoted: bool) -> None:
        self.text = text
        self.quoted = quoted


def tokenize(text: str) -> List[Tuple[List[Tok], bool]]:
    """Split into simple commands: list of (tokens, fed_by_pipe)."""
    cmds: List[Tuple[List[Tok], bool]] = []
    cur: List[Tok] = []
    buf: List[str] = []
    have = False
    tq = False
    quote: Optional[str] = None
    pipe_in = False
    n = len(text)
    i = 0

    def flush() -> None:
        nonlocal buf, have, tq
        if have:
            cur.append(Tok("".join(buf), tq))
        buf, have, tq = [], False, False

    def end_cmd(next_pipe: bool) -> None:
        nonlocal cur, pipe_in
        flush()
        if cur:
            cmds.append((cur, pipe_in))
        cur = []
        pipe_in = next_pipe

    while i < n:
        c = text[i]
        if quote:
            if c == quote:
                if i + 1 < n and text[i + 1] == quote:
                    buf.append(c)
                    i += 2
                    continue
                quote = None
                i += 1
                continue
            if quote == '"' and c == "`" and i + 1 < n:
                buf.append(text[i + 1])
                i += 2
                continue
            buf.append(c)
            i += 1
            continue
        if c in "\"'":
            quote, have, tq = c, True, True
            i += 1
            continue
        if c == "`" and i + 1 < n:
            if text[i + 1] in "\r\n":
                i += 2
                continue
            buf.append(text[i + 1])
            have = True
            i += 2
            continue
        if c == "^" and i + 1 < n:
            buf.append(text[i + 1])
            have = True
            i += 2
            continue
        if c in " \t":
            flush()
            i += 1
            continue
        if c in "<>":
            prefix = ""
            if have and not tq and "".join(buf).isdigit():  # 2> and 1>
                prefix = "".join(buf)
                buf, have = [], False
            flush()
            j = i + 1
            while j < n and text[j] == ">":
                j += 1
            if j < n - 1 and text[j] == "&" and (text[j + 1].isdigit() or text[j + 1] == "-"):  # 2>&1
                j += 2
            cur.append(Tok(prefix + text[i:j], False))
            i = j
            continue
        if c == "|":
            if i + 1 < n and text[i + 1] == "|":
                end_cmd(False)
                i += 2
            else:
                end_cmd(True)
                i += 1
            continue
        if c in ";&\n\r(){}":
            end_cmd(False)
            i += 1
            continue
        buf.append(c)
        have = True
        i += 1
    end_cmd(False)
    return cmds


# --------------------------------------------------------------------------- paths
WIN_CRED_DIRS = (".ssh", ".aws", ".gnupg", ".kube", ".azure", ".docker", ".config\\gcloud", ".config\\gh", "appdata\\roaming\\gcloud")
WIN_SYSTEM_TOP = frozenset({
    "windows", "program files", "program files (x86)", "programdata", "system volume information",
    "$recycle.bin", "recovery", "boot", "perflogs", "msocache", "documents and settings", "efi",
})
_CRED_FILE = re.compile(r"(?i)^(id_[a-z0-9_]+|credentials|authorized_keys|config|config\.json|.*\.pem|.*\.key|.*\.pfx|hosts\.yml)$")
_SHORT_NAME = re.compile(r"[a-z0-9_$!#%&'()@^`{}-]{1,6}~\d+")
_REGISTRY = re.compile(r"(?i)^(?:registry::)?hk(?:lm|cu|cr|u|cc|ey_[a-z_]+)(?::|\\|$)")
WIN_PROTECTED_HOME_DIRS = (".ssh", ".aws", ".gnupg", ".kube", ".kneepad")
WIN_PROTECTED_HOME_FILES = (
    ".netrc", "_netrc", ".npmrc", ".pypirc", ".gitconfig", ".docker\\config.json", ".claude\\settings.json",
    ".claude\\settings.local.json", "documents\\windowspowershell\\profile.ps1",
    "documents\\windowspowershell\\microsoft.powershell_profile.ps1", "documents\\powershell\\profile.ps1",
    "documents\\powershell\\microsoft.powershell_profile.ps1",
)
WIN_PROTECTED_ABS = (
    "\\windows\\system32\\drivers\\etc\\hosts",
    "\\windows\\system32\\config",
    "\\windows\\system32\\winevt",
)


def is_registry(p: str) -> bool:
    return bool(_REGISTRY.match(p.strip()))


def norm_path(p: str, cwd: str) -> Optional[str]:
    """Absolute, normalised Windows path, or None when it cannot be resolved."""
    p = p.strip().strip('"').strip("'").replace("/", "\\")
    if p.startswith("\\\\?\\") and not p.startswith("\\\\?\\UNC\\"):
        p = p[4:]
    if re.fullmatch(r"[A-Za-z]:", p):
        p += "\\"
    if not looks_windows(p):
        if p.startswith("\\") and looks_windows(cwd):
            p = ntpath.splitdrive(cwd)[0] + p
        elif looks_windows(cwd):
            p = ntpath.join(cwd, p)
        else:
            return None
    return ntpath.normpath(p)


def classify(p: str, cwd: str, home: str) -> str:
    """catastrophic | ancestor | dotgit | creds | system | normal for a normalised Windows path."""
    low = p.lower().rstrip("\\")
    drive, rest = ntpath.splitdrive(low)
    parts = [x for x in rest.split("\\") if x]
    if drive.startswith("\\\\"):
        return "catastrophic" if not parts else "normal"
    if len(parts) <= 1:
        return "catastrophic"
    h = home.lower().rstrip("\\") if home else ""
    if h and (low == h or h.startswith(low + "\\")):
        return "catastrophic"
    c = cwd.lower().rstrip("\\") if cwd else ""
    if c and (c == low or c.startswith(low + "\\")):
        return "ancestor"
    if parts[-1] == ".git":
        return "dotgit"
    if h:
        for d in WIN_CRED_DIRS:
            base = h + "\\" + d
            if low == base or (low.startswith(base + "\\") and _CRED_FILE.match(parts[-1])):
                return "creds"
    if parts[0] in WIN_SYSTEM_TOP or _SHORT_NAME.fullmatch(parts[0]):
        return "system"  # a top-level 8.3 short name (PROGRA~1, DOCUME~1) is almost always a system directory
    if parts[0] == "users" and not (h and (low == h or low.startswith(h + "\\"))):
        return "system"
    return "normal"


def protected_reason(p: str, home: str, kneepad_dir: str) -> Optional[str]:
    """Why a write to this normalised Windows path needs a decision, or None."""
    low = p.lower()
    h = home.lower().rstrip("\\") if home else ""
    sd = kneepad_dir.lower().rstrip("\\") if kneepad_dir else ""
    if sd and (low == sd or low.startswith(sd + "\\")):
        return "Kneepad's own state"
    if h:
        for rel in WIN_PROTECTED_HOME_DIRS:
            base = h + "\\" + rel
            if low == base or low.startswith(base + "\\"):
                return f"protected directory ~\\{rel}"
        for rel in WIN_PROTECTED_HOME_FILES:
            if low == h + "\\" + rel:
                return f"protected file ~\\{rel}"
        startup = h + "\\appdata\\roaming\\microsoft\\windows\\start menu\\programs\\startup"
        if low == startup or low.startswith(startup + "\\"):
            return "startup folder (persistence)"
    drive, rest = ntpath.splitdrive(low)
    for suffix in WIN_PROTECTED_ABS:
        if rest == suffix or rest.startswith(suffix + "\\"):
            return "system path"
    parts = [x for x in rest.split("\\") if x]
    if parts and (parts[0] in WIN_SYSTEM_TOP or _SHORT_NAME.fullmatch(parts[0])):
        return "system path"
    base = parts[-1] if parts else ""
    if base == ".kneepad.toml":
        return "Kneepad project config"
    return None


# --------------------------------------------------------------------------- expansion
_DEFAULT_ENV = {"systemroot": "C:\\Windows", "windir": "C:\\Windows", "programfiles": "C:\\Program Files",
                "programdata": "C:\\ProgramData", "systemdrive": "C:", "allusersprofile": "C:\\ProgramData"}


def _lookup(az, name: str) -> Optional[str]:
    n = name.lower()
    for k, v in az.env.items():
        if k.lower() == n and v:
            return v
    home = az.home
    table: Dict[str, str] = {"userprofile": home, "home": home, "pwd": az.cwd}
    if looks_windows(home):
        table["appdata"] = home + "\\AppData\\Roaming"
        table["localappdata"] = home + "\\AppData\\Local"
        table["temp"] = home + "\\AppData\\Local\\Temp"
        table["tmp"] = table["temp"]
    table.update({k: v for k, v in _DEFAULT_ENV.items() if k not in table})
    return table.get(n)


def expand(az, text: str) -> Tuple[str, bool]:
    """Expand %VAR%, $env:VAR, $HOME and a leading ~. Returns (text, dynamic)."""
    dyn = False

    def sub(m: "re.Match[str]") -> str:
        nonlocal dyn
        name = next(g for g in m.groups() if g)
        v = _lookup(az, name)
        if v is None:
            dyn = True
            return m.group(0)
        return v

    out = re.sub(r"%([A-Za-z_]\w*)%|\$env:([A-Za-z_]\w*)|\$\{env:([A-Za-z_]\w*)\}|\$(home|pwd)\b", sub, text, flags=re.I)
    if out == "~" or out.startswith("~\\") or out.startswith("~/"):
        out = az.home + out[1:]
    probe = re.sub(r"(?i)\$recycle\.bin", "", out)
    if re.search(r"\$[A-Za-z_{(]|\$_|%[A-Za-z_]", probe):
        dyn = True
    return out, dyn


# --------------------------------------------------------------------------- argv view
def _native_pa(name: str, toks: List[Tok]) -> ParsedArgv:
    tokens = [t.text for t in toks[1:]]
    pa = ParsedArgv(name=name, words=[Word(text=t.text, raw=t.text, quoted=t.quoted) for t in toks], tokens=tokens,
                    raw0=toks[0].text)
    for idx, t in enumerate(toks[1:], start=1):
        s = t.text
        cluster = (not t.quoted) and _SWITCH_CLUSTER.fullmatch(s) is not None and s.count("/") > 1
        if cluster:
            for part in re.findall(r"/[A-Za-z?](?::[^/\s]*)?", s):
                pa.flags.add(part.split(":", 1)[0].lower())
            continue
        is_flag = (s.startswith("-") and len(s) > 1 and not s[1].isdigit()) or bool(re.fullmatch(r"/[A-Za-z?][A-Za-z0-9:=,._-]*", s))
        if is_flag and not t.quoted:
            m = re.split(r"[:=]", s.lower(), maxsplit=1)
            pa.flags.add(m[0])
            if len(m) == 2:
                pa.flag_values[m[0]] = s[len(m[0]) + 1:]
        else:
            pa.pos.append(s)
            pa.pos_words.append(pa.words[idx])
            pa.pos_idx.append(idx)
    pa.argstr = " ".join(tokens)
    return pa


# --------------------------------------------------------------------------- handlers
# cmd.exe accepts switches run together: /s/q, /q/s, /s/q/f. Only used for deletes, never for POSIX words.
_SWITCH_CLUSTER = re.compile(r"(?i)(?:/[a-z?](?::[^/\s]*)?)+")
_RECURSE = re.compile(r"(?i)^-r(?:e(?:c(?:u(?:r(?:s(?:e)?)?)?)?)?)?(?::\S*)?$")
_PS_VALUE_FLAGS = {"-filter", "-include", "-exclude", "-credential", "-stream", "-erroraction", "-ea", "-errorvariable", "-ev",
                   "-warningaction", "-wa", "-informationaction", "-ia", "-outvariable", "-ov", "-outbuffer", "-ob",
                   "-pipelinevariable", "-pv", "-warningvariable", "-wv", "-informationvariable", "-iv"}
_PS_PATH_FLAGS = {"-path", "-literalpath", "-pspath", "-lp", "-pa"}
DELETE_NAMES = frozenset({"del", "erase", "rd", "rmdir", "ri", "remove-item", "rm"})
_WRITERS_PS = frozenset({"set-content", "add-content", "out-file", "clear-content", "new-item", "tee-object", "export-csv", "sc", "ac", "ni"})
_WRITERS_COPY = frozenset({"copy-item", "move-item", "rename-item", "cpi", "mi", "mv", "cp", "copy", "move", "ren", "rename", "xcopy"})


def _ignorable(az, p: str) -> bool:
    parts = {x.lower() for x in re.split(r"[\\/]", p)}
    ign = {x.lower() for x in az.cfg.ignore_dirs}
    base = parts and p.replace("/", "\\").rsplit("\\", 1)[-1].lower()
    return bool(parts & ign) or base == "thumbs.db" or base == "desktop.ini" or str(base).endswith(".pyc")


def _delete(az, name: str, toks: List[Tok], pipe_in: bool) -> None:
    args = toks[1:]
    low = [t.text.lower() for t in args]
    recursive = any(
        (not t.quoted and _SWITCH_CLUSTER.fullmatch(t.text) and re.search(r"(?i)/s(?::|/|$)", t.text) is not None) or _RECURSE.match(t.text)
        for t in args
    )
    forced = any(re.fullmatch(r"(?i)-fo(?:r(?:c(?:e)?)?)?(?::\S*)?", t.text) for t in args)
    targets: List[Tok] = []
    i = 0
    while i < len(args):
        t = args[i]
        s = t.text
        ls = s.lower()
        if not t.quoted and (ls in _PS_PATH_FLAGS or re.match(r"(?i)^-(?:path|literalpath|pspath|lp|pa):", s)):
            val = s.split(":", 1)[1] if ":" in s[1:] and ls not in _PS_PATH_FLAGS else (args[i + 1].text if i + 1 < len(args) else "")
            if ls in _PS_PATH_FLAGS:
                i += 1
            for piece in val.split(","):
                if piece:
                    targets.append(Tok(piece, t.quoted))
        elif not t.quoted and ls in _PS_VALUE_FLAGS:
            i += 1
        elif not t.quoted and ((s.startswith("-") and len(s) > 1) or _SWITCH_CLUSTER.fullmatch(s)):
            pass
        elif s in (">", ">>", "<") or s.startswith(">"):
            i += 1
        else:
            for piece in s.split(","):
                if piece:
                    targets.append(Tok(piece, t.quoted))
        i += 1
    if not targets:
        if pipe_in and (recursive or forced):
            az.emit("fs-rm-dynamic-target", f"{toks[0].text} fed by a pipeline")
        return
    need: List[str] = []
    for t in targets:
        text, dyn = expand(az, t.text)
        if dyn:
            if recursive:
                az.emit("fs-rm-dynamic-target", t.text)
            continue
        if is_registry(text):
            az.emit("win-registry-delete", text)
            continue
        wild = bool(re.search(r"[*?]", ntpath.basename(text.replace("/", "\\"))))
        probe = text
        if wild:
            probe = ntpath.dirname(text.replace("/", "\\")) or text
        ap = norm_path(probe, az.cwd)
        if ap is None:
            continue
        kind = classify(ap, az.cwd, az.home)
        dir_delete = recursive or wild or name in ("del", "erase")
        if name in ("rd", "rmdir") and not recursive:
            continue
        if kind in ("catastrophic", "ancestor", "dotgit") and not dir_delete:
            continue
        if kind == "catastrophic":
            az.emit("fs-rm-catastrophic", ap)
        elif kind == "ancestor":
            az.emit("fs-rm-ancestor-of-cwd", ap)
        elif kind == "dotgit":
            az.emit("fs-rm-dot-git", ap)
        elif kind == "creds":
            az.emit("fs-rm-credentials-dir", ap)
        elif kind == "system":
            az.emit("fs-rm-system-path", ap)
        elif dir_delete or os.path.isfile(ap):
            if not wild:
                need.append(ap)
            else:
                pattern = norm_path(text, az.cwd) or ap
                matches = glob.glob(pattern) if os.sep == "\\" or not looks_windows(pattern) else []
                if len(matches) > 2000:
                    if recursive:
                        az.emit("fs-rm-dynamic-target", f"glob {t.text} matches more than 2000 paths")
                    continue
                need.extend(matches)
    seen: set = set()
    final: List[str] = []
    for p in need:
        if p in seen:
            continue
        seen.add(p)
        if not os.path.lexists(p) or _ignorable(az, p) or az._git_recoverable(p):
            continue
        final.append(p)
    if final:
        b, _f, exceeded = estimate_size(final, az.cfg.snapshot_max_mb * 1024 * 1024, az.cfg.snapshot_max_files)
        if exceeded:
            az.emit("fs-rm-too-large-to-snapshot", ", ".join(final)[:160])
        else:
            az.emit("fs-rm-snapshot", ", ".join(final)[:160], plan=SnapshotPlan("files", az.cwd, paths=final, est_bytes=b))


def _write_targets(name: str, toks: List[Tok]) -> List[str]:
    args = toks[1:]
    out: List[str] = []
    pos: List[str] = []
    i = 0
    while i < len(args):
        s = args[i].text
        ls = s.lower()
        if s in (">", ">>") and i + 1 < len(args):
            out.append(args[i + 1].text)
            i += 2
            continue
        if not args[i].quoted and ls in ("-path", "-filepath", "-literalpath", "-destination", "-newname") and i + 1 < len(args):
            out.append(args[i + 1].text)
            i += 2
            continue
        if not args[i].quoted and (s.startswith("-") or re.fullmatch(r"/[A-Za-z?](?::\S*)?", s)) and len(s) > 1:
            if ls in ("-value", "-inputobject", "-encoding", "-itemtype", "-name", "-width"):
                i += 1
            i += 1
            continue
        pos.append(s)
        i += 1
    if name in _WRITERS_COPY:
        if len(pos) >= 2:
            out.append(pos[-1])
    elif name in _WRITERS_PS and not out and pos:
        out.append(pos[0])
    return out


def _check_writes(az, name: str, toks: List[Tok]) -> None:
    redirects = [i for i, t in enumerate(toks) if t.text in (">", ">>")]
    if name not in _WRITERS_PS and name not in _WRITERS_COPY and not redirects:
        return
    for raw in _write_targets(name, toks):
        text, dyn = expand(az, raw)
        if dyn or not text:
            continue
        ap = norm_path(text, az.cwd)
        if ap is None:
            continue
        reason = protected_reason(ap, az.home, az_kneepad_dir())
        if reason:
            az.emit("fs-protected-path-write", f"{ap} ({reason})")


def az_kneepad_dir() -> str:
    from .util import kneepad_home

    return kneepad_home()


def _inner_from_ps(rest: List[Tok]) -> Tuple[Optional[str], Optional[str]]:
    """Return (command text, encoded command) for a powershell/pwsh invocation."""
    for i, t in enumerate(rest):
        if t.quoted:
            continue
        s = t.text.lower()
        if re.fullmatch(r"-(?:c|co|com|comm|comma|comman|command)", s):
            return " ".join(x.text for x in rest[i + 1:]), None
        if re.fullmatch(r"-e(?:c|nc|nco|ncod|ncode|ncoded|ncodedc|ncodedco|ncodedcom|ncodedcomm|ncodedcomma|ncodedcomman|ncodedcommand)?", s):
            return None, rest[i + 1].text if i + 1 < len(rest) else ""
        if s.startswith("-command:") or s.startswith("-c:"):
            return t.text.split(":", 1)[1], None
    return None, None


def _decode_ps(b64: str) -> Optional[str]:
    try:
        raw = base64.b64decode(b64 + "=" * (-len(b64) % 4), validate=False)
        txt = raw.decode("utf-16-le")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None
    if not txt or not all(ch.isprintable() or ch in "\r\n\t" for ch in txt):
        return None
    return txt


def _wrappers(az, name: str, toks: List[Tok], depth: int) -> bool:
    """Handle commands that run other commands. True when the command was fully delegated."""
    rest = toks[1:]
    if name in ("powershell", "pwsh", "powershell_ise"):
        inner, enc = _inner_from_ps(rest)
        if enc is not None:
            txt = _decode_ps(enc)
            if txt is None:
                az.emit("win-encoded-command", f"{toks[0].text} -EncodedCommand (could not decode)")
            else:
                az._walk(txt, depth + 1)
        elif inner:
            az._walk(inner, depth + 1)
        return False
    if name == "cmd":
        for i, t in enumerate(rest):
            m = re.fullmatch(r"(?i)/([ck])(.*)", t.text)
            if m:
                tail = ([m.group(2)] if m.group(2) else []) + [x.text for x in rest[i + 1:]]
                if tail:
                    az._walk(" ".join(tail), depth + 1)
                break
        return False
    if name == "wsl":
        skip = {"-d", "--distribution", "-u", "--user", "--cd", "--shell-type"}
        i = 0
        while i < len(rest):
            s = rest[i].text.lower()
            if s in skip:
                i += 2
                continue
            if s in ("-e", "--exec", "--", "-l", "--login"):
                i += 1
                continue
            if s.startswith("-"):
                i += 1
                continue
            break
        inner = " ".join(x.text for x in rest[i:])
        if inner:
            az._walk(inner, depth + 1)
        return False
    if name in ("iex", "invoke-expression"):
        inner = " ".join(x.text for x in rest)
        if inner:
            az._walk(inner, depth + 1)
        return False
    if name in ("start-process", "saps", "start"):
        files: List[str] = []
        argl = ""
        i = 0
        while i < len(rest):
            s = rest[i].text
            ls = s.lower()
            if ls in ("-argumentlist", "-args"):
                argl = rest[i + 1].text if i + 1 < len(rest) else ""
                i += 2
                continue
            if ls in ("-filepath", "-verb", "-workingdirectory", "-wd", "-windowstyle", "-credential"):
                if ls == "-filepath" and i + 1 < len(rest):
                    files.append(rest[i + 1].text)
                i += 2
                continue
            if s.startswith("-") or re.fullmatch(r"(?i)/(?:wait|b|min|max|low|normal|high|realtime|abovenormal|belownormal|separate|shared|node\s*\d*)", s):
                i += 1
                continue
            files.append(s)
            i += 1
        if files:
            az._walk((files[0] + " " + argl + " " + " ".join(files[1:])).strip(), depth + 1)
        return False
    if name == "call" and rest:
        az._walk(" ".join(x.text for x in rest), depth + 1)
        return False
    if name == "runas" and rest:
        az._walk(rest[-1].text, depth + 1)
        return False
    return False


def analyze(az, text: str, depth: int) -> None:
    """Run the Windows pass over one command string."""
    for toks, pipe_in in tokenize(text):
        if not toks:
            continue
        name = win_name(toks[0].text)
        if not name:
            continue
        marker = any(has_marker(t.text) for t in toks)
        _wrappers(az, name, toks, depth)
        pa = _native_pa(name, toks)
        for r in az._win_dsl:
            if match_argv(r, pa):
                az.emit(r.id, " ".join([toks[0].text] + pa.tokens)[:200])
        if name in DELETE_NAMES:
            ps_style = any(_RECURSE.match(t.text) for t in toks[1:])
            if name not in ("rm", "rmdir") or marker or ps_style:
                _delete(az, name, toks, pipe_in)
                continue
        _check_writes(az, name, toks)
        if marker and name not in DELETE_NAMES:
            words = [Word(text=t.text, raw=t.text, quoted=t.quoted) for t in toks]
            gp = parse_argv(words)
            if gp is not None:
                az._analyze_pa(gp, None, None, -1, depth)
