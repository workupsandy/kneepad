"""The analysis engine: turns a command into a decision.

``Analyzer`` walks a script (recursively through ``bash -c``, ``$(...)``, ``eval``,
scripts it can read, ``ssh host cmd`` and friends), matches every simple command
against the footgun database and the code handlers, and produces a ``Decision``:
allow, ask or deny, plus the snapshots to take first.

Design rules:
* Never execute the command, and never connect to anything.
* Anything that cannot be analysed (too deep, too large, unreadable SQL file) is
  surfaced as a finding rather than silently allowed.
* Heuristics may over-ask. They must not over-allow where the cost is data loss.
"""

from __future__ import annotations

import dataclasses
import fnmatch
import glob
import ntpath
import os
import re
import sys
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from . import braces, sqlscan, winshell
from .argvtools import INTERPRETERS, SHELLS, ParsedArgv, cmd_name, parse_argv, strip_wrappers
from .config import Config, stronger
from .rules import ACTION_RANK, Rule, load_default_rules, match_argv, REGEX_INPUT_CAP
from .shellparse import MAX_DEPTH, MAX_SRC, Cmd, Word, is_assignment, iter_nested, parse
from .snapshots import SnapshotError, SnapshotPlan, estimate_size, git, git_toplevel, list_git_clean_paths
from .util import redact, kneepad_home, user_home

DOWNLOADERS = frozenset({"curl", "wget", "fetch", "aria2c", "http", "https", "xh"})
SQL_CLIENTS = frozenset({
    "psql", "mysql", "mariadb", "sqlite3", "sqlcmd", "cockroach", "clickhouse-client", "clickhouse",
    "snowsql", "duckdb", "usql", "pgcli", "mycli", "litecli", "sqlplus", "trino", "presto", "cqlsh",
    "beeline", "spark-sql", "isql", "bq",
})
MONGO_CLIENTS = frozenset({"mongosh", "mongo"})
REDIS_CLIENTS = frozenset({"redis-cli", "valkey-cli", "keydb-cli"})
# Glob names that match (nearly) everything in a directory: *, .*, ?*, .[a-z]*
_MATCH_ALL_GLOB = re.compile(r"^(?:\.?[*?]+|\.\[[^\]]+\]\*)$")
PROTECTED_BRANCHES = frozenset({"main", "master", "trunk", "production", "prod", "release"})
SYSTEM_PREFIXES = ("/bin", "/sbin", "/usr", "/etc", "/lib", "/lib32", "/lib64", "/boot", "/sys",
                   "/proc", "/dev", "/var/lib", "/var/log", "/var/spool", "/opt", "/srv",
                   # macOS
                   "/System", "/Library", "/Applications", "/var/db", "/var/root", "/cores", "/private/etc",
                   "/private/var/db", "/private/var/root")
# Git Bash, MSYS2, Cygwin and WSL expose Windows drives as /c, /mnt/c and so on.
_MSYS_DRIVE = re.compile(r"(?i)^/(?:mnt/|cygdrive/)?[a-z]/(windows|program files(?: \(x86\))?|programdata|\$recycle\.bin|system volume information)(?:/|$)")
_MSYS_ROOT = re.compile(r"(?i)^/(?:mnt/|cygdrive/)?[a-z]$")
CRED_DIRS = (".ssh", ".aws", ".gnupg", ".kube", ".azure", ".config/gcloud", ".docker", ".config/gh", "Library/Keychains")
CRED_FILE_RE = re.compile(r"^(id_[a-z0-9_]+|credentials|authorized_keys|config|config\.json|.*\.pem|.*\.key|hosts\.yml|.*\.keychain(?:-db)?|.*\.p12|.*\.pfx)$")
PROTECTED_HOME_DIRS = (".ssh", ".aws", ".gnupg", ".kube", ".kneepad", "Library/Keychains", "Library/LaunchAgents")
PROTECTED_HOME_FILES = (
    ".netrc", ".npmrc", ".pypirc", ".bashrc", ".bash_profile", ".profile", ".zshrc", ".zprofile",
    ".zshenv", ".gitconfig", ".docker/config.json", ".claude/settings.json",
    ".claude/settings.local.json", ".config/fish/config.fish",
)
def _chmod_is_tightening(mode: str) -> bool:
    """True when a chmod mode cannot make a file writable by group or others."""
    if re.fullmatch(r"[0-7]{3,4}", mode):
        m = mode[-3:]
        return (int(m[1]) & 2) == 0 and (int(m[2]) & 2) == 0
    parts = mode.split(",")
    for part in parts:
        mm = re.fullmatch(r"([ugoa]*)([-+=])([rwxXst]*)", part)
        if not mm:
            return False
        who, op, perms = mm.groups()
        if op in "+=" and "w" in perms and (who == "" or set(who) & set("goa")):
            return False
    return True


HARMLESS_DEVICES = frozenset({"/dev/null", "/dev/zero", "/dev/full", "/dev/stdout", "/dev/stderr", "/dev/stdin",
                              "/dev/tty", "/dev/random", "/dev/urandom"})
# Only destructive infrastructure and data rules are escalated by a "production" marker.
PROD_FAMILIES = frozenset({"database", "kubernetes", "iac", "aws", "gcp", "azure", "digitalocean", "heroku", "fly",
                           "railway", "supabase", "vercel", "migrations", "docker"})
ENV_EXAMPLE_SUFFIXES = (".example", ".sample", ".template", ".dist")
BLOCK_DEVICE_RE = re.compile(r"^/dev/(?:sd[a-z]|hd[a-z]|vd[a-z]|xvd[a-z]|nvme\d|mmcblk\d|disk\d|rdisk\d|loop\d|md\d|dm-\d)")
SAFE_FIND_PATTERNS = [
    r"\*\.(?:pyc|pyo|o|class|tmp|swp|swo|orig|rej|log)", r"\*~", r"__pycache__", r"\.DS_Store",
    r"node_modules", r"\*\.egg-info", r"\.pytest_cache", r"\.mypy_cache",
]
RUNNERS = {
    "bundle": {"exec"}, "poetry": {"run"}, "pipenv": {"run"}, "uv": {"run"}, "pdm": {"run"},
    "rye": {"run"}, "pnpm": {"exec", "dlx"}, "yarn": {"exec", "dlx"}, "npm": {"exec"}, "bun": {"x"},
}
SQL_KIND_TO_RULE = {
    sqlscan.SQL_DROP_DATABASE: "sql-drop-database", sqlscan.SQL_DROP_TABLE: "sql-drop-table",
    sqlscan.SQL_TRUNCATE: "sql-truncate", sqlscan.SQL_DELETE_NO_WHERE: "sql-delete-no-where",
    sqlscan.SQL_UPDATE_NO_WHERE: "sql-update-no-where", sqlscan.SQL_DROP_COLUMN: "sql-drop-column",
    sqlscan.SQL_DROP_ROLE: "sql-drop-role",
}
MAX_SCRIPT_BYTES = 64 * 1024
_VAR_RE = re.compile(r"\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))")
_STRING_LITERAL_RE = re.compile(
    r'"""(.*?)"""|\'\'\'(.*?)\'\'\'|"((?:[^"\\\n]|\\.)*)"|\'((?:[^\'\\\n]|\\.)*)\'', re.S
)
_CODE_RM_RE = re.compile(r"\brm\s+-[a-zA-Z]*[rR][a-zA-Z]*\s+(?:--\s+)?(?:/|~|\$HOME)(?:\s|['\"]|$|\*|/)")
_CODE_RMTREE_RE = re.compile(r"""(?:shutil\.rmtree|rimraf|fs\.rmSync|rmtree)\(\s*['"](/|~)['"]""")


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    action: str
    why: str
    safer: str
    recipe: str = ""
    detail: str = ""
    reversible: str = "no"
    refs: List[str] = field(default_factory=list)
    plan: Optional[SnapshotPlan] = None
    note: str = ""

    def to_dict(self) -> dict:
        return {
            "rule": self.rule_id, "title": self.title, "severity": self.severity, "action": self.action,
            "detail": self.detail, "why": self.why, "safer": self.safer, "recipe": self.recipe,
            "reversible": self.reversible, "refs": self.refs, "note": self.note,
            "snapshot": self.plan.kind if self.plan else None,
        }


@dataclass
class Decision:
    action: str = "allow"
    findings: List[Finding] = field(default_factory=list)
    plans: List[SnapshotPlan] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    mode: str = "enforce"

    def to_dict(self) -> dict:
        return {
            "action": self.action, "mode": self.mode,
            "findings": [f.to_dict() for f in self.findings],
            "snapshots": [p.kind for p in self.plans], "notes": self.notes,
        }

    def reason(self, limit: int = 3) -> str:
        """Human-readable explanation shown to the user (ask) or to the agent (deny)."""
        top = [f for f in self.findings if f.action == self.action] or self.findings
        lines: List[str] = []
        for f in top[:limit]:
            lines.append(f"Kneepad [{f.severity}] {f.title} ({f.rule_id})")
            if f.detail:
                lines.append(f"  Matched: {redact(f.detail, 200)}")
            if f.note:
                lines.append(f"  Note: {f.note}")
            lines.append(f"  Why: {f.why}")
            lines.append(f"  Safer: {f.safer}")
            if f.recipe:
                lines.append(f"  Back up first: {f.recipe}")
        if len(top) > limit:
            lines.append(f"  (+{len(top) - limit} more findings. Run: kneepad check '<command>' for the full list.)")
        if self.action == "deny":
            lines.append("Blocked. If you are sure, run it yourself in a terminal. Do not retry or disguise the command.")
        return "\n".join(lines)


def _preview_flag(pa: ParsedArgv, flag: str, values: Tuple[str, ...] = ()) -> bool:
    """True if ``flag`` is on: bare, or ``flag=VALUE`` with a listed preview value, and never switched off again."""
    seen: List[str] = []
    for t in pa.tokens:
        if t == "--":
            break
        if t == flag or t.startswith(flag + "=") or t == "--no-" + flag[2:]:
            seen.append(t)
    allowed = {flag} | {f"{flag}={v}" for v in values}
    # Any off or unknown spelling anywhere (``=false``, ``=none``, ``--no-...``) means: do not treat it as a preview.
    return bool(seen) and all(t in allowed for t in seen)


# Options that take the next word as their value, so a flag written right after one is only text.
_GIT_PUSH_VALUE_OPTS = ("-o", "--push-option", "--repo", "--receive-pack", "--exec")
_HELM_VALUE_OPTS = ("--description",)


def _flag_used_as_value(pa: ParsedArgv, value_opts: Tuple[str, ...]) -> bool:
    return any(a in value_opts and b.startswith(("-n", "--dry-run")) for a, b in zip(pa.tokens, pa.tokens[1:]))


def _is_dry_run(pa: ParsedArgv) -> bool:
    """Commands whose own dry-run flag guarantees nothing is changed."""
    if pa.name == "git" and pa.pos[:1] == ["push"]:
        # git accepts shortened long options, so ``--no-dry`` also switches the preview off.
        if any(t.startswith("--no-d") for t in pa.tokens) or _flag_used_as_value(pa, _GIT_PUSH_VALUE_OPTS):
            return False
        return "-n" in pa.flags or _preview_flag(pa, "--dry-run")
    if pa.name == "helm" and pa.pos[:1] in (["uninstall"], ["delete"], ["un"], ["rollback"]):
        if _flag_used_as_value(pa, _HELM_VALUE_OPTS):
            return False
        return _preview_flag(pa, "--dry-run", ("true", "client", "server"))
    if pa.name == "aws":
        if pa.pos[:1] == ["s3"] and pa.pos[1:2] in (["rm"], ["mv"], ["sync"], ["cp"]):
            return _preview_flag(pa, "--dryrun")
        if pa.pos[:1] == ["ec2"]:
            return _preview_flag(pa, "--dry-run")
    return False


class Analyzer:
    def __init__(
        self,
        rules: Optional[List[Rule]] = None,
        config: Optional[Config] = None,
        cwd: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
        home: Optional[str] = None,
        platform: Optional[str] = None,
    ) -> None:
        self.rules = rules if rules is not None else load_default_rules()
        self.by_id: Dict[str, Rule] = {r.id: r for r in self.rules}
        self.cfg = config or Config()
        self.plat = platform or sys.platform
        c0 = cwd or os.getcwd()
        h0 = home or user_home()
        # Windows-shaped paths are normalised with ntpath even when we run elsewhere (tests, WSL, Git Bash).
        self.cwd = ntpath.normpath(c0) if winshell.looks_windows(c0) else os.path.abspath(c0)
        self.home = ntpath.normpath(h0) if winshell.looks_windows(h0) else os.path.normpath(h0)
        self.env = dict(env) if env is not None else dict(os.environ)
        self._dsl = [r for r in self.rules if not r.virtual and "raw_regex" not in r.match and r.family != "windows"]
        self._win_dsl = [r for r in self.rules if not r.virtual and "raw_regex" not in r.match and r.family == "windows"]
        self._raw = [r for r in self.rules if not r.virtual and "raw_regex" in r.match]
        self._reset()

    # ------------------------------------------------------------------ state
    def _reset(self) -> None:
        self.findings: List[Finding] = []
        self.notes: List[str] = []
        self.vars: Dict[str, str] = {}
        self._script_depth = 0
        self._seen: set = set()
        self._follow_cd = True
        self._cd_moved = False

    def emit(self, rule_id: str, detail: str = "", plan: Optional[SnapshotPlan] = None, note: str = "") -> None:
        r = self.by_id[rule_id]
        if rule_id in self.cfg.disable_rules and not r.no_override:
            return
        if self._script_depth > 0 and (r.severity in ("low", "medium") or plan is not None):
            self.notes.append(f"{rule_id} inside a followed script was not enforced (only high and critical findings are)")
            return
        action = r.action
        ov = self.cfg.action_overrides.get(rule_id)
        if ov and not r.no_override:
            action = ov
        esc = self.cfg.escalations.get(rule_id)
        if esc:
            action = stronger(action, esc)
        # The plan is part of the key: ``detail`` is truncated, and two different safety copies must never collapse into one.
        what = None if plan is None else (plan.kind, plan.cwd, plan.repo, tuple(plan.paths), tuple(plan.branches))
        key = (rule_id, detail, what)
        if key in self._seen:
            return
        self._seen.add(key)
        if plan is not None:
            plan.rule_id = rule_id
        self.findings.append(Finding(
            rule_id=r.id, title=r.title, severity=r.severity, action=action, why=r.why, safer=r.safer,
            recipe=r.recipe, detail=detail, reversible=r.reversible, refs=list(r.refs), plan=plan, note=note,
        ))

    # --------------------------------------------------------------- public API
    def analyze_shell(self, command: str) -> Decision:
        command = command.replace("\x00", "")  # a NUL ends the command for the shell; analyse the pessimistic reading
        self._reset()
        text = command.lstrip("\ufeff")  # editors sometimes prepend a BOM
        if len(text) > MAX_SRC:
            self.emit("analysis-limit-exceeded", f"input is {len(text)} bytes, limit {MAX_SRC}")
            text = text[:MAX_SRC]
        for r in self._raw:
            if re.search(r.match["raw_regex"], text):
                self.emit(r.id, text[:120])
        self._walk_command(text)
        return self._finish(text)

    def _tilde(self, path: str) -> str:
        """Expand a leading ~ with this analyser's own home (os.path.expanduser reads the process environment instead)."""
        if path == "~" or path.startswith(("~/", "~\\")):
            return self.home + path[1:]
        return os.path.expanduser(path) if path.startswith("~") else path

    def analyze_write_path(self, path: str) -> Decision:
        self._reset()
        abs_path = self._abs(self._tilde(path))
        reason = self._protected_reason(abs_path)
        if reason:
            self.emit("fs-protected-path-write", f"{abs_path} ({reason})")
        return self._finish(abs_path)

    def analyze_mcp(self, tool_name: str, tool_input: object) -> Decision:
        self._reset()
        strings: List[Tuple[str, str]] = []
        _collect_strings(tool_input, "", strings, [0])
        lname = tool_name.lower()
        if re.search(r"sql|query|database|(?<![a-z0-9])db(?![a-z0-9])|postgres|mysql|sqlite|supabase|neon|planetscale|snowflake|bigquery|execute", lname):
            for _k, s in strings:
                self._scan_sql_like(s)
        if re.search(r"shell|bash|terminal|run_command|exec|command", lname):
            for k, s in strings:
                if k.split(".")[-1].lower() in ("command", "cmd", "script", "code", "args", "input"):
                    self._walk_command(s[:MAX_SRC])
        if re.search(r"mongo", lname):
            for _k, s in strings:
                self._scan_mongo_like(s)
        if re.search(r"redis", lname):
            for _k, s in strings:
                self._scan_redis_like(s)
        return self._finish(" ".join(s for _k, s in strings)[:MAX_SRC])

    # ------------------------------------------------------------------ finish
    def _finish(self, raw_text: str) -> Decision:
        prod = False
        for pat in self.cfg.prod_markers:
            try:
                if re.search(pat, raw_text):
                    prod = True
                    break
            except re.error:
                continue
        for f in self.findings:
            r = self.by_id[f.rule_id]
            if prod and f.action == "ask" and f.severity in ("high", "critical") and r.family in PROD_FAMILIES:
                f.action = "deny"
                f.note = (f.note + " " if f.note else "") + "Escalated to deny: the command mentions production."
        for pat in self.cfg.allow_patterns:
            try:
                hit = re.search(pat, raw_text)
            except re.error:
                continue
            if hit:
                for f in self.findings:
                    if not self.by_id[f.rule_id].no_override and f.action != "allow":
                        f.action = "allow"
                        f.note = (f.note + " " if f.note else "") + f"Allowed by allow_patterns {pat!r}."
        action = "allow"
        for f in self.findings:
            action = stronger(action, f.action)
        plans: List[SnapshotPlan] = []
        seen_plans: set = set()
        if action in ("allow", "ask"):
            for f in self.findings:
                if f.plan is not None and f.action in ("allow", "ask"):
                    key = (f.plan.kind, f.plan.cwd, f.plan.repo, tuple(f.plan.paths), tuple(f.plan.branches))
                    if key not in seen_plans:
                        seen_plans.add(key)
                        plans.append(f.plan)
        return Decision(action=action, findings=self.findings, plans=plans, notes=self.notes, mode=self.cfg.mode)

    # ------------------------------------------------------------------- walk
    def _walk_command(self, src: str) -> None:
        """Analyse a command with ``cd`` followed, then, if that moved anything, again with ``cd`` ignored.

        Following ``cd`` is a guess: subshells, pipelines, ``popd``, ``cd -`` and branches that never run all leave
        the shell somewhere else. The results are combined, so a wrong guess can add a prompt or a safety copy
        but can never remove one that the hook's own directory calls for.
        """
        before = dict(self.vars)
        self._follow_cd, self._cd_moved = True, False
        self._walk(src, 0)
        if self._cd_moved:
            self.vars = before
            self._follow_cd = False
            self._walk(src, 0)
            self._follow_cd = True

    def _walk(self, src: str, depth: int) -> None:
        if depth > MAX_DEPTH:
            self.emit("analysis-limit-exceeded", f"nesting deeper than {MAX_DEPTH}")
            return
        cmds = parse(src)
        saved_cwd = self.cwd
        try:
            for idx in range(len(cmds)):
                self._cmd(cmds, idx, depth)
            for sub in iter_nested(cmds):
                self._walk(sub, depth + 1)
        finally:
            self.cwd = saved_cwd
        winshell.analyze(self, src, depth)

    def _cmd(self, cmds: List[Cmd], idx: int, depth: int) -> None:
        cmd = cmds[idx]
        for op, target in cmd.redirects:
            if op in (">", ">>", ">|", "&>", "&>>"):
                self._check_redirect(target)
        words = cmd.argv
        if not words:
            return
        if all(is_assignment(w.text) for w in words):
            self._record_assignments(words)
            return
        norm, meta = strip_wrappers(words)
        if meta.get("nested"):
            self._walk(meta["nested"], depth + 1)
            return
        if meta.get("query") or not norm:
            return
        name0 = cmd_name(norm[0].text)
        if name0 in ("cd", "pushd", "chdir") and self._follow_cd:
            self._track_cd(norm[1:])
            return
        if name0 in ("export", "declare", "local", "readonly", "typeset"):
            self._record_assignments(norm[1:])
            return
        pa = parse_argv(norm, meta)
        if pa is None:
            return
        self._analyze_pa(pa, cmd, cmds, idx, depth)

    def _analyze_words(self, words: List[Word], depth: int) -> None:
        if depth > MAX_DEPTH:
            self.emit("analysis-limit-exceeded", f"nesting deeper than {MAX_DEPTH}")
            return
        norm, meta = strip_wrappers(words)
        if meta.get("nested"):
            self._walk(meta["nested"], depth + 1)
            return
        if meta.get("query") or not norm:
            return
        pa = parse_argv(norm, meta)
        if pa is not None:
            self._analyze_pa(pa, None, None, -1, depth)

    def _track_cd(self, args: List[Word]) -> None:
        """A literal ``cd DIR`` or ``pushd DIR`` moves the directory later relative paths resolve against.

        Without this, ``cd ~ && rm -rf *`` was judged against the directory the agent started in.
        A dynamic or unknown target (``cd "$X"``, ``cd -``) leaves the directory unchanged.
        """
        target = None
        for w in args:
            if w.text == "--":
                continue
            if w.text.startswith("-") and len(w.text) > 1 and w.text != "-":
                continue
            target = w
            break
        if target is None:
            self._cd_moved = self._cd_moved or self.cwd != self.home
            self.cwd = self.home
            return
        text, dyn = self._expand_word(target)
        if dyn or text in ("", "-") or target.glob:
            return
        new = self._abs(text)
        if os.path.isdir(new) or self._classify(new) != "normal":
            self._cd_moved = self._cd_moved or new != self.cwd
            self.cwd = new

    def _record_assignments(self, words: List[Word]) -> None:
        for w in words:
            if is_assignment(w.text):
                name, val = w.text.split("=", 1)
                raw_val = w.raw.split("=", 1)[1] if "=" in w.raw else ""
                if raw_val == "~" or raw_val.startswith("~/"):  # bash expands an unquoted leading tilde in an assignment
                    val = self.home + val[1:]
                self.vars[name.rstrip("+")] = val

    # ---------------------------------------------------------- per-command
    def _analyze_pa(self, pa: ParsedArgv, cmd: Optional[Cmd], cmds: Optional[List[Cmd]], idx: int, depth: int) -> None:
        if len(pa.argstr) > REGEX_INPUT_CAP:
            self.emit("cmd-oversized", f"{pa.name}: {len(pa.argstr)} characters of arguments")
        # `tool --help` / `tool --version` as the first argument only prints text for every tool we know.
        # Only the first position is exempt: GNU dd, for one, honours --help solely as argv[1].
        if pa.tokens and pa.tokens[0] in ("--help", "--version") and pa.name not in SHELLS and pa.name not in ("sudo", "env", "xargs", "nohup", "time", "command", "exec"):
            return
        if _is_dry_run(pa):
            return
        for r in self._dsl:
            if match_argv(r, pa):
                self._emit_dsl(r, pa)
        name = pa.name
        if name in ("rm", "unlink"):
            self._h_rm(pa)
        elif name == "find":
            self._h_find(pa, depth)
        elif name == "git":
            self._h_git(pa)
        elif name in ("chmod", "chown", "chgrp"):
            self._h_chmod(pa)
        self._h_writers(pa)
        self._h_pipe_to_shell(pa, cmds, idx)
        stdin_texts, unreadable = self._stdin_texts(cmd, cmds, idx) if cmd is not None else ([], [])
        if name in SHELLS:
            self._h_shell(pa, stdin_texts, depth)
        elif name in ("eval",):
            self._walk(" ".join(pa.tokens), depth + 1)
        elif name in ("source", "."):
            if pa.pos:
                self._follow_script(pa.pos[0], depth)
        elif name == "osascript":
            self._h_osascript(pa, depth)
        elif name in INTERPRETERS:
            self._h_interpreter(pa, stdin_texts)
        elif name in SQL_CLIENTS or name in MONGO_CLIENTS or name in REDIS_CLIENTS:
            self._h_db(pa, stdin_texts, unreadable)
        elif ("/" in pa.raw0 or pa.raw0.startswith(".")) and name not in ("rm",) and pa.raw0 not in (".", ".."):
            self._follow_script(pa.raw0, depth)
        self._h_runners(pa, depth)

    def _emit_dsl(self, r: Rule, pa: ParsedArgv) -> None:
        detail = " ".join([pa.raw0] + pa.tokens)[:200]
        plan: Optional[SnapshotPlan] = None
        if r.snapshot != "none":
            ok, plan = self._make_plan(r, pa)
            if not ok:
                return
        self.emit(r.id, detail, plan=plan)

    def _make_plan(self, r: Rule, pa: ParsedArgv) -> Tuple[bool, Optional[SnapshotPlan]]:
        """Return (continue, plan). ``continue`` False means a blocking finding was already emitted."""
        cwd = self._git_cwd(pa)
        top = git_toplevel(cwd) if os.path.isdir(cwd) else None
        if top is None:
            # Not a repository: git itself will refuse to run, so there is nothing to protect.
            return True, None
        if r.snapshot == "git-stash":
            return True, SnapshotPlan("git-stash", cwd, repo=top)
        if r.snapshot == "git-branch":
            return True, SnapshotPlan("git-branch", cwd, repo=top, branches=list(pa.pos[1:]))
        if r.snapshot == "git-clean":
            try:
                after = pa.tokens[pa.tokens.index("clean") + 1:] if "clean" in pa.tokens else []
                paths = list_git_clean_paths(cwd, after)
            except (SnapshotError, OSError, ValueError) as exc:
                self.emit("snapshot-unavailable", f"git clean: {exc}")
                return False, None
            if not paths:
                return True, None
            b, _f, exceeded = estimate_size(paths, self.cfg.snapshot_max_mb * 1024 * 1024, self.cfg.snapshot_max_files)
            if exceeded:
                self.emit("fs-rm-too-large-to-snapshot", "git clean would delete more than the snapshot limit")
                return False, None
            return True, SnapshotPlan("git-clean", cwd, repo=top, paths=paths, est_bytes=b)
        return True, None

    def _git_cwd(self, pa: ParsedArgv) -> str:
        c = pa.flag_values.get("-C")
        if c:
            return self._abs(c)
        return self.cwd

    # ------------------------------------------------------------- expansion
    def _abs(self, path: str) -> str:
        if winshell.looks_windows(path) or winshell.looks_windows(self.cwd):
            n = winshell.norm_path(path, self.cwd)
            if n is not None:
                return n
        p = os.path.normpath(path if os.path.isabs(path) else os.path.join(self.cwd, path))
        if p.startswith("//"):  # POSIX normpath keeps exactly two leading slashes
            p = "/" + p.lstrip("/")
        return p

    def _lookup(self, name: str) -> Optional[str]:
        if name in self.vars:
            return self.vars[name]
        if name == "HOME":
            return self.home
        if name == "PWD":
            return self.cwd
        return None

    def _expand_text(self, text: str, depth: int = 0) -> Tuple[str, bool]:
        out: List[str] = []
        pos = 0
        dynamic = False
        for m in _VAR_RE.finditer(text):
            name = m.group(1) or m.group(2)
            val = self._lookup(name)
            out.append(text[pos:m.start()])
            if val is None:
                dynamic = True
                out.append(m.group(0))
            else:
                if "$" in val or "`" in val:
                    if depth < 3:
                        val, dyn = self._expand_text(val, depth + 1)
                        dynamic = dynamic or dyn
                    else:
                        dynamic = True
                out.append(val)
            pos = m.end()
        out.append(text[pos:])
        res = "".join(out)
        if "$" in res or "`" in res:
            dynamic = True
        return res, dynamic

    def _expand_word(self, w: Word) -> Tuple[str, bool]:
        text = w.text
        if w.raw.startswith("~") and (text == "~" or text.startswith("~/")):
            text = self.home + text[1:]
        if not w.has_var:
            return text, False
        return self._expand_text(text)

    # ---------------------------------------------------------------- rm
    def _ci(self, s: str) -> str:
        """Default macOS and Windows volumes are case-insensitive, so compare lower-cased."""
        return s.lower() if self.plat in ("darwin", "win32") else s

    def _classify(self, p: str) -> str:
        if winshell.looks_windows(p):
            return winshell.classify(p, self.cwd, self.home)
        if p == "/":
            return "catastrophic"

        # macOS keeps /etc, /var and /tmp under /private, and temp dirs, project dirs and sometimes homes
        # resolve there. Strip the prefix from the target, the home and the cwd alike, or they never compare equal.
        def unpriv(x: str) -> str:
            if x == "/private" or x.startswith("/private/"):
                return x[len("/private"):] or "/"
            return x

        p = unpriv(p)
        if p == "/":
            return "catastrophic"
        parts = [x for x in p.split("/") if x]
        if len(parts) == 1 or _MSYS_ROOT.match(p):
            return "catastrophic"
        q = self._ci(p)
        home_dir = unpriv(self.home)
        home = self._ci(home_dir)
        cwd = self._ci(unpriv(self.cwd))
        if q == home or (home != "/" and home.startswith(q + "/")):
            return "catastrophic"
        if cwd == q or cwd.startswith(q + "/"):
            return "ancestor"
        if os.path.basename(p) == ".git":
            return "dotgit"
        for d in CRED_DIRS:
            base = self._ci(os.path.join(home_dir, d))
            if q == base or (q.startswith(base + "/") and CRED_FILE_RE.match(os.path.basename(p))):
                return "creds"
        for pref in SYSTEM_PREFIXES:
            pr = self._ci(pref)
            if q == pr or q.startswith(pr + "/"):
                return "system"
        if _MSYS_DRIVE.match(p):
            return "system"
        if self.plat == "darwin" and q.startswith("/users/") and not (q == home or q.startswith(home + "/")):
            return "system"
        return "normal"

    def _ignorable(self, p: str) -> bool:
        parts = set(re.split(r"[\\/]", p)) if winshell.looks_windows(p) else set(p.split("/"))
        base = os.path.basename(p)
        return bool(parts & self.cfg.ignore_dirs) or base == ".DS_Store" or base.endswith(".pyc")

    def _git_recoverable(self, p: str) -> bool:
        """True when ``p`` is tracked by git with no local changes, so git can restore it."""
        d = p if os.path.isdir(p) and not os.path.islink(p) else os.path.dirname(p)
        top = git_toplevel(d)
        if not top:
            return False
        try:
            tracked = git(top, "ls-files", "--", p)
            if tracked.returncode != 0 or not tracked.stdout.strip():
                return False
            status = git(top, "status", "--porcelain", "--ignored", "--", p)
            return status.returncode == 0 and not status.stdout.strip()
        except Exception:
            return False

    def _h_rm(self, pa: ParsedArgv) -> None:
        recursive = bool({"-r", "-R", "--recursive"} & pa.flags)
        if "--no-preserve-root" in pa.flags:
            self.emit("fs-rm-catastrophic", "--no-preserve-root")
        if pa.meta.get("xargs"):
            self.emit("fs-rm-via-xargs", " ".join([pa.raw0] + pa.tokens)[:160])
        cands: List[str] = []
        for w in self._brace_words(pa.pos_words, recursive):
            text, dyn = self._expand_word(w)
            if dyn:
                if recursive:
                    self.emit("fs-rm-dynamic-target", w.raw or w.text)
                continue
            if text == "":
                continue
            paths = [text]
            if w.glob:
                pat = os.path.normpath(text if os.path.isabs(text) else os.path.join(self.cwd, text))
                if recursive and _MATCH_ALL_GLOB.match(os.path.basename(pat)) and self._classify(os.path.dirname(pat) or "/") == "catastrophic":
                    # `rm -rf ~/*`, `rm -rf /home/*`: whatever the glob matches today, the intent is to wipe the directory.
                    self.emit("fs-rm-catastrophic", w.raw or w.text)
                    continue
                matches = glob.glob(pat)
                if len(matches) > 2000:
                    if recursive:
                        self.emit("fs-rm-dynamic-target", f"glob {w.raw} matches more than 2000 paths")
                    continue
                paths = matches
                if recursive and text in (".*", "./.*"):
                    self.emit("fs-rm-ancestor-of-cwd", ".* can match .. on some systems")
            for p in paths:
                self._rm_one(p, recursive, cands)
        seen: set = set()
        need: List[str] = []
        for p in cands:
            if p in seen:
                continue
            seen.add(p)
            if not os.path.lexists(p) or self._ignorable(p) or self._git_recoverable(p):
                continue
            need.append(p)
        if need:
            b, _f, exceeded = estimate_size(need, self.cfg.snapshot_max_mb * 1024 * 1024, self.cfg.snapshot_max_files)
            if exceeded:
                self.emit("fs-rm-too-large-to-snapshot", ", ".join(need)[:160])
            else:
                self.emit("fs-rm-snapshot", ", ".join(need)[:160], plan=SnapshotPlan("files", self.cwd, paths=need, est_bytes=b))

    def _brace_words(self, words: List[Word], recursive: bool) -> List[Word]:
        """Expand unquoted ``{a,b}`` groups the way bash does before ``rm`` sees its arguments."""
        out: List[Word] = []
        for w in words:
            if w.quoted or not braces.has_brace(w.text):
                out.append(w)
                continue
            alts = braces.expand(w.text)
            if alts is None:
                if recursive:
                    self.emit("fs-rm-dynamic-target", f"brace expansion too large: {(w.raw or w.text)[:80]}")
                continue
            for a in alts:
                out.append(dataclasses.replace(w, text=a, raw=a, glob=w.glob or any(c in a for c in "*?[")))
        return out

    def _rm_one(self, p: str, recursive: bool, cands: List[str]) -> None:
        ap = self._abs(p)
        isdir = os.path.isdir(ap) and not os.path.islink(ap)
        kind = self._classify(ap)
        if kind in ("catastrophic", "ancestor", "dotgit") and not recursive and isdir:
            return  # rm refuses a directory without -r
        if kind == "catastrophic":
            self.emit("fs-rm-catastrophic", ap)
        elif kind == "ancestor":
            self.emit("fs-rm-ancestor-of-cwd", ap)
        elif kind == "dotgit":
            self.emit("fs-rm-dot-git", ap)
        elif kind == "creds":
            self.emit("fs-rm-credentials-dir", ap)
        elif kind == "system":
            self.emit("fs-rm-system-path", ap)
        else:
            cands.append(ap)

    # -------------------------------------------------------------- find
    def _h_find(self, pa: ParsedArgv, depth: int) -> None:
        toks = pa.tokens
        names: List[str] = []
        has_delete = False
        for i, t in enumerate(toks):
            if t in ("-name", "-iname", "-path", "-ipath", "-regex") and i + 1 < len(toks):
                names.append(toks[i + 1])
            if t == "-delete":
                has_delete = True
        safe = bool(names) and all(any(re.fullmatch(p, n) for p in SAFE_FIND_PATTERNS) for n in names)
        if has_delete and not safe:
            self.emit("fs-find-delete", " ".join(["find"] + toks)[:200])
        words = pa.words[1:]
        i = 0
        while i < len(toks):
            if toks[i] in ("-exec", "-execdir", "-ok", "-okdir"):
                j = i + 1
                while j < len(toks) and toks[j] not in (";", "+"):
                    j += 1
                payload = words[i + 1:j]
                if payload:
                    norm, _m = strip_wrappers(payload)
                    first = cmd_name(norm[0].text) if norm else ""
                    if first in ("rm", "shred", "unlink", "rmdir"):
                        if not safe:
                            self.emit("fs-find-delete", " ".join(["find"] + toks)[:200])
                    else:
                        self._analyze_words(payload, depth + 1)
                i = j
            i += 1

    # --------------------------------------------------------------- git
    def _h_git(self, pa: ParsedArgv) -> None:
        if not pa.pos or pa.pos[0] != "push":
            return
        force = bool({"--force", "-f"} & pa.flags) and not ({"--force-with-lease", "--force-if-includes"} & pa.flags)
        refspecs = pa.pos[2:]
        plus = [r for r in refspecs if r.startswith("+")]
        if plus:
            self.emit("git-push-plus-refspec", " ".join(plus)[:120])
        protected = set(PROTECTED_BRANCHES) | set(self.cfg.protected_branches)

        def is_protected(b: str) -> bool:
            return b in protected or b.startswith("release/")

        hit: List[str] = []
        for r in refspecs:
            spec = r.lstrip("+")
            dst = spec.split(":", 1)[1] if ":" in spec else spec
            dst = dst[len("refs/heads/"):] if dst.startswith("refs/heads/") else dst
            if (force or r.startswith("+")) and is_protected(dst):
                hit.append(dst)
        if force and not refspecs and "--all" not in pa.flags and "--mirror" not in pa.flags:
            try:
                r = git(self._git_cwd(pa), "symbolic-ref", "--short", "-q", "HEAD")
                cur = r.stdout.strip() if r.returncode == 0 else ""
            except Exception:
                cur = ""
            if cur and is_protected(cur):
                hit.append(cur)
        if hit:
            self.emit("git-force-push-protected-branch", ", ".join(sorted(set(hit))))

    # ------------------------------------------------------- chmod / chown
    def _h_chmod(self, pa: ParsedArgv) -> None:
        if not ({"-R", "--recursive"} & pa.flags):
            return
        targets = pa.pos_words[1:] if pa.pos_words else []
        for w in targets:
            text, dyn = self._expand_word(w)
            if dyn or text == "":
                continue
            ap = self._abs(text)
            if self._classify(ap) == "catastrophic" or ap == "/":
                self.emit("fs-chmod-chown-critical", ap)

    # ----------------------------------------------------- protected writes
    def _protected_reason(self, ap: str) -> Optional[str]:
        if winshell.looks_windows(ap):
            if any(self._config_path_hit(ap, pat) for pat in self.cfg.allow_write_paths):
                return None
            reason = winshell.protected_reason(ap, self.home, kneepad_home())
            if reason:
                return reason
            for pat in self.cfg.protected_paths:
                if self._config_path_hit(ap, pat):
                    return f"protected by config pattern {pat}"
            return None
        home = self.home
        if ap in HARMLESS_DEVICES or ap.startswith("/dev/fd/"):
            return None
        for pat in self.cfg.allow_write_paths:
            if self._config_path_hit(ap, pat):
                return None
        c = self._ci(ap)
        for rel in PROTECTED_HOME_DIRS:
            base = self._ci(os.path.join(home, rel))
            if c == base or c.startswith(base + "/"):
                return f"protected directory ~/{rel}"
        sb = self._ci(kneepad_home())
        if c == sb or c.startswith(sb + "/"):
            return "Kneepad's own state"
        for rel in PROTECTED_HOME_FILES:
            if c == self._ci(os.path.join(home, rel)):
                return f"protected file ~/{rel}"
        for pref in SYSTEM_PREFIXES:
            pr = self._ci(pref)
            if c == pr or c.startswith(pr + "/"):
                return "system path"
        parts = [x for x in ap.split("/") if x]
        for i in range(len(parts) - 1):
            pair = (parts[i], parts[i + 1])
            if pair in ((".git", "hooks"), (".git", "config"), (".github", "workflows")):
                return f"{pair[0]}/{pair[1]}"
            if parts[i] == ".claude" and parts[i + 1] in ("settings.json", "settings.local.json"):
                return "agent settings"
        base = os.path.basename(ap)
        if base == ".kneepad.toml":
            return "Kneepad project config"
        if re.match(r"^\.env(\.[A-Za-z0-9_-]+)?$", base) and not base.endswith(ENV_EXAMPLE_SUFFIXES):
            return "environment file with secrets"
        for pat in self.cfg.protected_paths:
            if self._config_path_hit(ap, pat):
                return f"protected by config pattern {pat}"
        return None

    def _config_path_hit(self, ap: str, pat: str) -> bool:
        """Does `ap` fall under a config path pattern? Compared literally and with symlinks resolved, because the
        working directory is usually reported resolved (macOS: /private/var/...) while a tool may name the same file
        through the alias (/var/...). Either spelling must hit."""
        if winshell.looks_windows(ap) or winshell.looks_windows(self.cwd):
            q = pat.replace("/", "\\")
            if q == "~" or q.startswith("~\\"):
                q = self.home.rstrip("\\") + q[1:]
            if not winshell.looks_windows(q):
                q = ntpath.join(self.cwd, q)
            q, a = ntpath.normcase(ntpath.normpath(q)), ntpath.normcase(ntpath.normpath(ap))
            return fnmatch.fnmatchcase(a, q) or a == q or a.startswith(q.rstrip("\\") + "\\")
        p = os.path.expanduser(pat)
        p = p if os.path.isabs(p) else os.path.join(self.cwd, p)
        aps = [ap]
        ps = [p]
        try:
            ra, rp = os.path.realpath(ap), os.path.realpath(p.rstrip("/") or "/")
            if ra != ap:
                aps.append(ra)
            if rp != p.rstrip("/"):
                ps.append(rp)
        except (OSError, ValueError):
            pass
        for a in aps:
            for q in ps:
                if fnmatch.fnmatch(a, q) or a == q or a.startswith(q.rstrip("/") + "/"):
                    return True
        return False

    def _check_write_word(self, w: Word, skip_system: bool = False) -> None:
        text, dyn = self._expand_word(w)
        if dyn or text == "":
            return
        ap = self._abs(text)
        reason = self._protected_reason(ap)
        if reason and not (skip_system and reason == "system path"):
            self.emit("fs-protected-path-write", f"{ap} ({reason})")

    def _check_redirect(self, target: Word) -> None:
        text, dyn = self._expand_word(target)
        if dyn or text == "":
            return
        if BLOCK_DEVICE_RE.match(text):
            self.emit("fs-redirect-to-block-device", text)
            return
        self._check_write_word(target)

    def _h_writers(self, pa: ParsedArgv) -> None:
        name = pa.name
        words: List[Word] = []
        if name == "tee":
            words = list(pa.pos_words)
        elif name in ("cp", "install", "ln", "rsync", "scp"):
            if pa.pos_words:
                words = [pa.pos_words[-1]]
        elif name in ("mv", "rm", "shred", "truncate", "unlink"):
            words = list(pa.pos_words)
        elif name == "sed":
            if any(f.startswith("-i") or f == "--in-place" for f in pa.flags) or any(t.startswith("-i") for t in pa.tokens):
                words = list(pa.pos_words)
        elif name in ("chmod", "chown", "chgrp"):
            words = list(pa.pos_words[1:])
            if name == "chmod" and pa.pos and _chmod_is_tightening(pa.pos[0]):
                words = []  # restricting permissions (e.g. 600, go-rwx) is routine hygiene
        elif name == "dd":
            for t, w in zip(pa.tokens, pa.words[1:]):
                if t.startswith("of="):
                    words.append(Word(text=t[3:], raw=t[3:]))
        elif name == "curl":
            for f in ("-o", "--output"):
                if f in pa.flag_values:
                    words.append(Word(text=pa.flag_values[f], raw=pa.flag_values[f]))
        elif name == "wget":
            for f in ("-O", "--output-document"):
                if f in pa.flag_values:
                    words.append(Word(text=pa.flag_values[f], raw=pa.flag_values[f]))
        for f in ("-t", "--target-directory"):
            if f in pa.flag_values and name in ("cp", "mv", "install", "ln"):
                words.append(Word(text=pa.flag_values[f], raw=pa.flag_values[f]))
        for w in words:
            if name == "dd" or not w.text.startswith("-"):
                self._check_write_word(w, skip_system=name in ("rm", "dd", "shred", "unlink"))

    # ----------------------------------------------------------- pipelines
    _APPLESCRIPT_SHELL = re.compile(r'(?is)do\s+shell\s+script\s+"((?:[^"\\]|\\.)*)"')
    _JXA_SHELL = re.compile(r"(?is)doShellScript\(\s*(?:\"((?:[^\"\\]|\\.)*)\"|'((?:[^'\\]|\\.)*)')")

    def _h_osascript(self, pa: ParsedArgv, depth: int) -> None:
        """AppleScript and JXA can run shell commands. Analyse the command strings we can see."""
        scripts: List[str] = []
        toks = pa.tokens
        for i, t in enumerate(toks):
            if t == "-e" and i + 1 < len(toks):
                scripts.append(toks[i + 1])
        text = "\n".join(scripts)
        for m in self._APPLESCRIPT_SHELL.finditer(text):
            self._walk(m.group(1).replace('\\"', '"').replace("\\\\", "\\"), depth + 1)
        for m in self._JXA_SHELL.finditer(text):
            self._walk((m.group(1) or m.group(2) or "").replace("\\\"", '"'), depth + 1)

    def _h_pipe_to_shell(self, pa: ParsedArgv, cmds: Optional[List[Cmd]], idx: int) -> None:
        name = pa.name
        is_shell = name in SHELLS
        is_interp = name in INTERPRETERS
        if cmds is not None and idx > 0 and cmds[idx].pipe_in and (is_shell or is_interp):
            has_c = any(re.fullmatch(r"-[A-Za-z]*c[A-Za-z]*", t) for t in pa.tokens) if is_shell else False
            reads_stdin = (not pa.pos) or pa.pos == ["-"] or "-s" in pa.flags
            if not has_c and reads_stdin:
                j = idx - 1
                while j >= 0:  # walk back through the whole pipeline, e.g. curl | tee f | sh
                    prev_norm, _m = strip_wrappers(cmds[j].argv)
                    if prev_norm and cmd_name(prev_norm[0].text) in DOWNLOADERS:
                        self.emit("net-pipe-to-shell", f"{prev_norm[0].text} ... | {name}")
                        break
                    if not cmds[j].pipe_in:
                        break
                    j -= 1
        if is_shell or name in ("eval", "source", "."):
            for w in pa.pos_words:
                for sub in w.subs:
                    for c in parse(sub):
                        n, _m = strip_wrappers(c.argv)
                        if n and cmd_name(n[0].text) in DOWNLOADERS:
                            self.emit("net-pipe-to-shell", f"{name} <(...{n[0].text}...)")
            for w in pa.words[1:]:
                for sub in w.subs:
                    for c in parse(sub):
                        n, _m = strip_wrappers(c.argv)
                        if n and cmd_name(n[0].text) in DOWNLOADERS:
                            self.emit("net-pipe-to-shell", f"{name} with output of {n[0].text}")

    # --------------------------------------------------------------- stdin
    def _read_text(self, path: str, limit: int = 2_000_000) -> Optional[str]:
        ap = self._abs(self._tilde(path))
        try:
            if not os.path.isfile(ap) or os.path.getsize(ap) > limit:
                return None
            with open(ap, "rb") as fh:
                data = fh.read(limit)
        except OSError:
            return None
        if b"\0" in data[:1024]:
            return None
        return data.decode("utf-8", errors="replace")

    def _stdin_texts(self, cmd: Optional[Cmd], cmds: Optional[List[Cmd]], idx: int) -> Tuple[List[str], List[str]]:
        texts: List[str] = []
        unreadable: List[str] = []
        if cmd is None:
            return texts, unreadable
        texts.extend(cmd.heredocs)
        for op, w in cmd.redirects:
            if op == "<<<":
                texts.append(w.text)
            elif op == "<":
                content = self._read_text(w.text)
                if content is None:
                    unreadable.append(w.text)
                else:
                    texts.append(content)
        if cmd.pipe_in and cmds is not None and idx > 0:
            prev = cmds[idx - 1]
            pn, _m = strip_wrappers(prev.argv)
            if pn:
                name = cmd_name(pn[0].text)
                if name in ("echo", "printf"):
                    texts.append(" ".join(w.text for w in pn[1:]))
                elif name == "cat":
                    for w in pn[1:]:
                        if not w.text.startswith("-"):
                            content = self._read_text(w.text)
                            if content is not None:
                                texts.append(content)
                    texts.extend(prev.heredocs)
        return texts, unreadable

    # ---------------------------------------------------- shells and scripts
    def _h_shell(self, pa: ParsedArgv, stdin_texts: List[str], depth: int) -> None:
        toks = pa.tokens
        payload: Optional[str] = None
        for i, t in enumerate(toks):
            if t.startswith("-") and not t.startswith("--") and "c" in t[1:] and t[1:].isalpha():
                if i + 1 < len(toks):
                    payload = toks[i + 1]
                break
            if not t.startswith("-"):
                break
        if payload is not None:
            self._walk(payload, depth + 1)
        elif pa.pos:
            self._follow_script(pa.pos[0], depth)
        for text in stdin_texts:
            self._walk(text, depth + 1)

    def _follow_script(self, path: str, depth: int) -> None:
        if depth + 1 > MAX_DEPTH:
            self.emit("analysis-limit-exceeded", f"nesting deeper than {MAX_DEPTH}")
            return
        ap = self._abs(self._tilde(path))
        try:
            if not os.path.isfile(ap) or os.path.getsize(ap) > MAX_SCRIPT_BYTES:
                return
            with open(ap, "rb") as fh:
                data = fh.read(MAX_SCRIPT_BYTES)
        except OSError:
            return
        if b"\0" in data[:1024]:
            return
        text = data.decode("utf-8", errors="replace")
        first = text.split("\n", 1)[0]
        if first.startswith("#!"):
            interp = cmd_name(first[2:].strip().split()[-1] if "env" in first else first[2:].strip().split()[0])
            if interp in INTERPRETERS:
                self._script_depth += 1
                try:
                    self._scan_code_text(text)
                finally:
                    self._script_depth -= 1
                return
        self._script_depth += 1
        try:
            self._walk(text, depth + 1)
        finally:
            self._script_depth -= 1

    # ---------------------------------------------------------- interpreters
    def _h_interpreter(self, pa: ParsedArgv, stdin_texts: List[str]) -> None:
        toks = pa.tokens
        code: List[str] = []
        for i, t in enumerate(toks):
            if t in ("-c", "-e", "-r", "--eval", "-p", "--print", "-E") and i + 1 < len(toks):
                code.append(toks[i + 1])
        code.extend(stdin_texts)
        if not code and pa.pos:
            script = self._read_text(pa.pos[0], MAX_SCRIPT_BYTES)
            if script is not None:
                self._script_depth += 1
                try:
                    self._scan_code_text(script)
                finally:
                    self._script_depth -= 1
        for c in code:
            self._scan_code_text(c)

    def _scan_code_text(self, text: str) -> None:
        text = text[:sqlscan.MAX_TEXT]
        for m in _STRING_LITERAL_RE.finditer(text):
            lit = next((g for g in m.groups() if g), "")
            if lit:
                self._scan_sql_like(lit)
                self._scan_redis_like(lit)
        self._scan_mongo_like(text)
        if _CODE_RM_RE.search(text) or _CODE_RMTREE_RE.search(text):
            self.emit("fs-rm-catastrophic", "code deletes / or ~")

    def _scan_sql_like(self, text: str) -> None:
        for kind, snippet in sqlscan.scan_sql(text):
            self.emit(SQL_KIND_TO_RULE[kind], snippet)

    def _scan_mongo_like(self, text: str) -> None:
        for kind, snippet in sqlscan.scan_mongo(text):
            self.emit(kind, snippet)

    def _scan_redis_like(self, text: str) -> None:
        for kind, snippet in sqlscan.scan_redis(text):
            self.emit(kind, snippet)

    # ------------------------------------------------------------ db clients
    def _h_db(self, pa: ParsedArgv, stdin_texts: List[str], unreadable: List[str]) -> None:
        name = pa.name
        texts = list(pa.tokens) + list(stdin_texts)
        files: List[str] = []
        if name in ("psql", "cqlsh", "sqlcmd", "usql", "isql"):
            for f in ("-f", "--file", "-i"):
                if f in pa.flag_values:
                    files.append(pa.flag_values[f])
        if name in ("mysql", "mariadb", "mongosh", "mongo", "duckdb", "sqlite3"):
            for t in pa.tokens:
                if t.startswith("--file="):
                    files.append(t.split("=", 1)[1])
        if name in MONGO_CLIENTS:
            files.extend(p for p in pa.pos if p.endswith(".js"))
        for f in files:
            content = self._read_text(f)
            if content is None:
                self.emit("sql-file-uninspectable", f)
            else:
                texts.append(content)
        for f in unreadable:
            self.emit("sql-file-uninspectable", f)
        for t in texts:
            if name in SQL_CLIENTS:
                self._scan_sql_like(t)
            elif name in MONGO_CLIENTS:
                self._scan_mongo_like(t)
            elif name in REDIS_CLIENTS:
                self._scan_redis_like(t)

    # --------------------------------------------------------------- runners
    def _h_runners(self, pa: ParsedArgv, depth: int) -> None:
        name = pa.name
        words = pa.words
        if name in RUNNERS and pa.pos and pa.pos[0] in RUNNERS[name]:
            for i, w in enumerate(words[1:], start=1):
                if w.text == pa.pos[0]:
                    self._analyze_words(words[i + 1:], depth + 1)
                    break
        elif name == "ssh" and len(pa.pos_idx) >= 1:
            rest = words[pa.pos_idx[0] + 1:]
            if rest:
                self._walk(" ".join(w.text for w in rest), depth + 1)
        elif name in ("docker", "podman", "docker-compose"):
            pos = pa.pos
            for i, p in enumerate(pos[:3]):
                if p in ("exec", "run") and len(pa.pos_idx) > i + 1:
                    rest = words[pa.pos_idx[i + 1] + 1:]
                    if rest:
                        self._analyze_words(rest, depth + 1)
                    break
            ep = pa.flag_values.get("--entrypoint")
            if ep:
                self._walk(ep, depth + 1)
        elif name == "kubectl" and pa.pos and pa.pos[0] in ("exec", "run", "debug"):
            for i, w in enumerate(words[1:], start=1):
                if w.text == "--":
                    self._analyze_words(words[i + 1:], depth + 1)
                    break
        elif name == "su":
            toks = pa.tokens
            for i, t in enumerate(toks):
                if t in ("-c", "--command") and i + 1 < len(toks):
                    self._walk(toks[i + 1], depth + 1)
                    break


def _collect_strings(obj: object, path: str, out: List[Tuple[str, str]], budget: List[int]) -> None:
    if budget[0] > MAX_SRC:
        return
    if isinstance(obj, str):
        budget[0] += len(obj)
        out.append((path, obj))
    elif isinstance(obj, dict):
        for k, v in obj.items():
            _collect_strings(v, f"{path}.{k}" if path else str(k), out, budget)
    elif isinstance(obj, (list, tuple)):
        for i, v in enumerate(obj):
            _collect_strings(v, f"{path}[{i}]", out, budget)
