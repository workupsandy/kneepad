"""Command-line interface."""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
from typing import List, Optional

from . import integrations
from . import __version__
from .adapters import ADAPTERS
from .audit import AuditLog
from .badge import make_badge
from .config import load_config
from .engine import Analyzer
from .hook import handle
from .integrations import TARGETS, install_target, uninstall_target
from .installer import InstallError, hook_command, install, is_installed, settings_path, uninstall
from .rules import load_default_rules, load_rules_text
from .snapshots import SnapshotError, SnapshotStore
from .util import kneepad_home, redact

EXIT_ALLOW, EXIT_ASK, EXIT_DENY = 0, 10, 20


def _print_decision(d, as_json: bool) -> None:
    if as_json:
        print(json.dumps(d.to_dict(), indent=2))
        return
    print(f"decision: {d.action.upper()}" + ("  (monitor mode: not enforced)" if d.mode == "monitor" else ""))
    if not d.findings:
        print("no findings")
    for f in d.findings:
        print(f"- [{f.severity}] {f.rule_id}: {f.title}  -> {f.action}")
        if f.detail:
            print(f"    matched: {f.detail}")
        if f.note:
            print(f"    note: {f.note}")
    if d.plans:
        print("snapshots that would be taken first: " + ", ".join(sorted({p.kind for p in d.plans})))
    for n in d.notes:
        print(f"note: {n}")


def cmd_check(args) -> int:
    cwd = args.cwd or os.getcwd()
    cfg = load_config(cwd)
    az = Analyzer(config=cfg, cwd=cwd)
    if args.tool == "Bash":
        d = az.analyze_shell(args.command)
    elif args.tool == "Write":
        d = az.analyze_write_path(args.command)
    else:
        d = az.analyze_mcp(args.tool, {"query": args.command, "command": args.command})
    _print_decision(d, args.json)
    for w in cfg.warnings:
        print(f"config warning: {w}", file=sys.stderr)
    return {"allow": EXIT_ALLOW, "ask": EXIT_ASK, "deny": EXIT_DENY}[d.action]


def _utf8_streams() -> None:
    """Agents send and expect UTF-8 JSON. Windows consoles default to a legacy code page."""
    for stream in (sys.stdin, sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError, OSError):
            pass


def cmd_hook(args) -> int:
    _utf8_streams()
    raw = sys.stdin.read()
    code, out = handle(raw, integration=args.target)
    if out:
        (sys.stderr if args.target == "generic" else sys.stdout).write(out + "\n")
    return code


def cmd_init(args) -> int:
    home = kneepad_home()
    log = AuditLog(home)
    log.ensure_key()
    log.append_if_empty("init", {"version": __version__})
    print(f"Kneepad state directory: {home}")
    targets = list(getattr(args, "target", None) or [])
    if "all" in targets:
        targets = list(TARGETS)
    for t in targets:
        try:
            res, tpath = install_target(t, args.scope, os.getcwd())
        except InstallError as exc:
            print(f"error ({t}): {exc}", file=sys.stderr)
            return 1
        print(f"{t} hook {res} in {tpath}")
    if args.claude_code:
        path = settings_path(args.scope, os.getcwd())
        try:
            result = install(path, hook_command())
        except InstallError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        print(f"Claude Code hook {result} in {path}")
        if result == "installed":
            print("Restart Claude Code (or open /hooks) for the change to take effect.")
    elif not targets:
        print("Next: kneepad init --claude-code   (add --scope project to install for this repository only)")
        print("Other agents: kneepad init --target cursor|gemini|codex|copilot|cline|all")
    print("Try it: kneepad check 'rm -rf /'")
    return 0


def cmd_uninstall(args) -> int:
    targets = list(getattr(args, "target", None) or [])
    if "all" in targets:
        targets = list(TARGETS)
    for t in targets:
        try:
            res, tpath = uninstall_target(t, args.scope, os.getcwd())
        except InstallError as exc:
            print(f"error ({t}): {exc}", file=sys.stderr)
            return 1
        print(f"{t}: {res}: {tpath}")
    if targets and not getattr(args, "claude_code", False):
        return 0
    path = settings_path(args.scope, os.getcwd())
    try:
        print(f"{uninstall(path)}: {path}")
    except InstallError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


def cmd_log(args) -> int:
    if args.n < 0:
        print("kneepad log: -n must be 0 or greater", file=sys.stderr)
        return 2
    entries = AuditLog().tail(args.n)
    if args.json:
        print(json.dumps(entries, indent=2))
        return 0
    for e in entries:
        d = e.get("data", {})
        extra = d.get("command") or d.get("path") or ""
        rules = ",".join(f["rule"] for f in d.get("findings", []))
        print(f"{e['seq']:>5} {e['ts']} {e['event']:<9} {d.get('action', ''):<6} {rules} {extra}"[:200])
    return 0


def cmd_verify(args) -> int:
    log = AuditLog()
    r = log.verify(anchor=args.anchor)
    if r.ok:
        print(f"OK: {r.count} entries, head seq {r.head_seq}, hash {r.head_hash}")
        print("signatures verified" if r.hmac_verified else "signatures NOT verified")
        for w in r.warnings:
            print(f"warning: {w}")
        if not args.anchor:
            print("note: this cannot detect deleted entries at the end of the log. Use `kneepad anchor` and `--anchor`.")
        return 0
    print(f"FAILED: {r.error}")
    return 1


def cmd_anchor(args) -> int:
    a = AuditLog().anchor()
    if not a:
        print("no verifiable log to anchor", file=sys.stderr)
        return 1
    print(a)
    print("Store this value somewhere the agent cannot write, then check with: kneepad verify --anchor " + a)
    return 0


def cmd_rules(args) -> int:
    if args.rules_cmd == "validate":
        try:
            with open(args.file, encoding="utf-8") as fh:
                rules = load_rules_text(fh.read())
        except (OSError, ValueError) as exc:
            print(f"INVALID: {exc}")
            return 1
        print(f"OK: {len(rules)} rules (structure and regexes only; the test suite runs each rule's examples)")
        return 0
    rules = load_default_rules()
    if args.rules_cmd == "list":
        for r in rules:
            if args.family and r.family != args.family:
                continue
            print(f"{r.id:<42} {r.severity:<8} {r.action:<5} {r.title}")
        return 0
    if args.rules_cmd == "show":
        for r in rules:
            if r.id == args.id:
                print(f"{r.id}: {r.title}\nfamily: {r.family}  severity: {r.severity}  action: {r.action}  reversible: {r.reversible}")
                print(f"\nWhy: {r.why}\n\nSafer: {r.safer}")
                if r.recipe:
                    print(f"\nBack up first: {r.recipe}")
                for u in r.refs:
                    print(f"ref: {u}")
                return 0
        print(f"no such rule: {args.id}", file=sys.stderr)
        return 1
    return 2


def cmd_snapshots(args) -> int:
    store = SnapshotStore()
    if args.snap_cmd == "list":
        for m in store.list():
            print(f"{m['id']}  {m['kind']:<10} {m.get('rule', ''):<28} {m['cwd']}")
        return 0
    if args.snap_cmd == "show":
        m = store.get(args.id)
        if not m:
            print("no such snapshot", file=sys.stderr)
            return 1
        print(json.dumps(m, indent=2))
        return 0
    if args.snap_cmd == "restore":
        try:
            for line in store.restore(args.id, force=args.force, to=args.to, apply=args.apply):
                print(line)
        except SnapshotError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        return 0
    if args.snap_cmd == "prune":
        removed = store.prune(older_than_days=args.older_than_days, max_total_mb=args.max_total_mb)
        print(f"removed {len(removed)} snapshots")
        return 0
    return 2


def _check_item(ok: Optional[bool], label: str, detail: str = "") -> str:
    tag = {True: "OK  ", False: "FAIL", None: "WARN"}[ok]
    return f"[{tag}] {label}" + (f": {detail}" if detail else "")


def run_doctor(cwd: str) -> List[tuple]:
    """Return a list of (status, label, detail). status is True, False or None (warning)."""
    items: List[tuple] = []
    home = kneepad_home()
    items.append((sys.version_info >= (3, 11), "Python >= 3.11", sys.version.split()[0]))
    try:
        rules = load_default_rules()
        items.append((True, "footgun database loads and validates", f"{len(rules)} rules"))
    except Exception as exc:
        items.append((False, "footgun database", str(exc)[:200]))
    win = sys.platform == "win32"
    if os.path.isdir(home) and win:
        items.append((None, "state directory is private", f"{home} (NTFS: protected by your user profile ACL, not checked)"))
    elif os.path.isdir(home):
        mode = stat.S_IMODE(os.stat(home).st_mode)
        items.append((mode & 0o077 == 0 or None, "state directory is private", f"{home} mode {oct(mode)}"))
    else:
        items.append((None, "state directory exists", f"{home} not created yet; run kneepad init"))
    log = AuditLog(home)
    if os.path.exists(log.key_path) and win:
        items.append((None, "audit key is private", "NTFS: protected by your user profile ACL, not checked"))
    elif os.path.exists(log.key_path):
        mode = stat.S_IMODE(os.stat(log.key_path).st_mode)
        items.append((mode & 0o077 == 0, "audit key is private", oct(mode)))
    else:
        items.append((None, "audit key", "missing; run kneepad init"))
    r = log.verify()
    items.append((r.ok, "audit log verifies", f"{r.count} entries" if r.ok else r.error))
    user_ok = is_installed(settings_path("user", cwd))
    proj_ok = is_installed(settings_path("project", cwd))
    others = []
    for t in integrations.TARGETS:
        for scope in ("user", "project"):
            try:
                if integrations.is_target_installed(t, scope, cwd):
                    others.append((t, scope))
                    break
            except Exception:
                continue
    claude_ok = user_ok or proj_ok
    any_ok = claude_ok or bool(others)
    items.append((True if claude_ok else (None if any_ok else False), "Claude Code hook installed",
                  "user" if user_ok else ("project" if proj_ok else "not installed" if any_ok else "not found; run kneepad init --claude-code")))
    for t, scope in others:
        items.append((True, f"{t} hook installed", scope))
    items.append((True if subprocess.run(["git", "--version"], capture_output=True).returncode == 0 else None,
                  "git available (needed for git snapshots)", ""))
    cfg = load_config(cwd)
    for w in cfg.warnings:
        items.append((None, "config warning", w))
    items.append((True if cfg.mode == "enforce" else None, "mode", cfg.mode))
    return items


def cmd_doctor(args) -> int:
    items = run_doctor(os.getcwd())
    for status, label, detail in items:
        print(_check_item(status, label, detail))
    return 1 if any(s is False for s, _l, _d in items) else 0


def cmd_badge(args) -> int:
    if not args.force:
        items = run_doctor(os.getcwd())
        hook = any(s is True for s, l, _d in items if l.endswith("hook installed"))
        log_ok = next(s for s, l, _d in items if l == "audit log verifies")
        if not (hook and log_ok):
            print("Refusing to create a 'protected by kneepad' badge: the hook is not installed or the audit log "
                  "does not verify. Run `kneepad doctor`. (Use --force to override.)", file=sys.stderr)
            return 1
    out = args.out
    try:
        with open(out, "w", encoding="utf-8") as fh:
            fh.write(make_badge())
    except OSError as exc:
        print(f"kneepad badge: cannot write {out}: {exc}", file=sys.stderr)
        return 1
    print(f"wrote {out}")
    print(f"Markdown:  ![Protected by Kneepad](./{os.path.basename(out)})")
    return 0


def _default_real_shell() -> str:
    if sys.platform == "win32":
        return shutil.which("bash") or shutil.which("sh") or "bash"
    for cand in ("/bin/bash", "/usr/bin/bash", "/bin/sh"):
        if os.path.exists(cand):
            return cand
    return "/bin/sh"


def _shell_command_arg(argv: List[str]) -> Optional[str]:
    """Return the command string of a `sh -c STRING` style invocation, or None when there is none.

    Handles clustered short options (-ec, -xc, -lc, -euc), separate options before -c (-l -c, -o pipefail -c),
    and long options (--norc). Stops at the first non-option word, which a shell treats as a script path.
    """
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--":
            return None
        if a in ("-o", "+o", "-O", "+O", "--rcfile", "--init-file"):
            i += 2
            continue
        if a.startswith("--"):
            i += 1
            continue
        if re.fullmatch(r"[-+][A-Za-z]+", a):
            if a[0] == "-" and "c" in a:
                return argv[i + 1] if i + 1 < len(argv) else None
            i += 1
            continue
        return None
    return None


def _vet_command(text: str, tool: str, interactive_ask: bool) -> int:
    """Shared by `run` and `shell`: analyse, snapshot, log, and return 0 to proceed or 126 to refuse.

    Every outcome is written to the audit log, including refusals. A failure to write the log is reported on
    stderr instead of being swallowed.
    """
    cfg = load_config(os.getcwd())
    d = Analyzer(config=cfg, cwd=os.getcwd()).analyze_shell(text)
    refused = False
    if d.action in ("deny", "ask") and cfg.mode != "monitor":
        print(d.reason(), file=sys.stderr)
        if d.action == "deny":
            refused = True
        elif interactive_ask and sys.stdin.isatty():
            refused = input("Run it anyway? [y/N] ").strip().lower() != "y"
        else:
            print("Not a terminal, so Kneepad cannot ask. Refusing." if interactive_ask else "Kneepad blocked this command.",
                  file=sys.stderr)
            refused = True
    snaps: List[str] = []
    if not refused and d.plans:
        try:
            store = SnapshotStore()
            for p in d.plans:
                sid = store.create(p)["id"]
                snaps.append(sid)
                print(f"kneepad: snapshot {sid}", file=sys.stderr)
        except SnapshotError as exc:
            print(f"kneepad: snapshot failed ({exc}); refusing to run.", file=sys.stderr)
            refused = True
    try:
        AuditLog().append("decision", {
            "tool": tool, "action": d.action, "mode": cfg.mode, "refused": refused, "cwd": os.getcwd(),
            "command": redact(text, 2000), "snapshots": snaps,
            "findings": [{"rule": f.rule_id, "severity": f.severity, "action": f.action, "detail": redact(f.detail, 300)}
                         for f in d.findings]})
    except Exception as exc:
        print(f"kneepad: warning: could not write the audit log ({type(exc).__name__}: {exc}). "
              "Continuing, but this decision is not recorded.", file=sys.stderr)
    return 126 if refused else 0


def cmd_shell(args) -> int:
    """Drop-in for $SHELL: `kneepad shell -c "cmd"` checks the command, then runs it with the real shell.

    Works with any agent that executes commands through $SHELL -c (set SHELL to the wrapper path).
    """
    real = os.environ.get("KNEEPAD_REAL_SHELL") or _default_real_shell()
    argv = list(args.argv)
    if argv and argv[0] == "--":
        argv = argv[1:]
    cmd_text = _shell_command_arg(argv)
    if cmd_text is not None and _vet_command(cmd_text, "shell", interactive_ask=False) != 0:
        return 126
    if sys.platform == "win32":  # os.execv on Windows detaches and loses the exit code
        try:
            return subprocess.call([real] + argv)
        except OSError as exc:
            print(f"kneepad shell: cannot run {real}: {exc}", file=sys.stderr)
            return 127
    os.execv(real, [real] + argv)
    return 127  # pragma: no cover


def cmd_run(args) -> int:
    argv = args.argv
    if argv and argv[0] in ("-h", "--help"):
        print("usage: kneepad run [--] COMMAND [ARGS...]\n\nAnalyse COMMAND with Kneepad and run it only if it is allowed.\n"
              "Exit codes: the command's own exit code; 126 when Kneepad refuses; 127 when the program is not found.")
        return 0
    if argv and argv[0] == "--":
        argv = argv[1:]
    if not argv:
        print("usage: kneepad run [--] COMMAND [ARGS...]", file=sys.stderr)
        return 2
    text = subprocess.list2cmdline(argv) if sys.platform == "win32" else shlex.join(argv)
    if _vet_command(text, "run", interactive_ask=True) != 0:
        return 126
    try:
        return subprocess.call(argv)
    except FileNotFoundError:
        print(f"kneepad run: command not found: {argv[0]}", file=sys.stderr)
        return 127
    except OSError as exc:
        print(f"kneepad run: cannot execute {argv[0]}: {exc}", file=sys.stderr)
        return 126


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="kneepad", description="A kneepad for AI coding agents.")
    p.add_argument("--version", action="version", version=f"kneepad {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("init", help="create state, key and optionally install the Claude Code hook")
    s.add_argument("--claude-code", action="store_true", help="install the Claude Code PreToolUse hook")
    s.add_argument("--target", action="append", choices=list(TARGETS) + ["all"], help="also install for another agent (repeatable)")
    s.add_argument("--scope", choices=["user", "project"], default="user", help="user: your home directory (default); project: this repository only")
    s.set_defaults(func=cmd_init)

    s = sub.add_parser("uninstall", help="remove the Claude Code hook (or --target another agent)")
    s.add_argument("--claude-code", action="store_true", help="also remove the Claude Code hook when --target is given")
    s.add_argument("--target", action="append", choices=list(TARGETS) + ["all"], help="agent to remove the hook from (repeatable)")
    s.add_argument("--scope", choices=["user", "project"], default="user", help="user: your home directory (default); project: this repository only")
    s.set_defaults(func=cmd_uninstall)

    s = sub.add_parser("hook", help="run as a hook (reads JSON on stdin)")
    s.add_argument("target", choices=sorted(ADAPTERS))
    s.set_defaults(func=cmd_hook)

    s = sub.add_parser("check", help="dry-run a command and show the decision")
    s.add_argument("command")
    s.add_argument("--cwd")
    s.add_argument("--tool", default="Bash", help="Bash (default), Write, or an mcp__ tool name")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_check)

    s = sub.add_parser("shell", help="shell wrapper for agents that run commands through $SHELL -c (all arguments go to the real shell, so --help shows the shell's help)")
    s.add_argument("argv", nargs=argparse.REMAINDER)
    s.set_defaults(func=cmd_shell)

    s = sub.add_parser("run", help="analyse a command and, if allowed, run it")
    s.add_argument("argv", nargs=argparse.REMAINDER)
    s.set_defaults(func=cmd_run)

    s = sub.add_parser("log", help="show recent audit log entries")
    s.add_argument("-n", type=int, default=20)
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_log)

    s = sub.add_parser("verify", help="verify the audit log hash chain and signatures")
    s.add_argument("--anchor", help="SEQ:HASH recorded earlier with `kneepad anchor`")
    s.set_defaults(func=cmd_verify)

    s = sub.add_parser("anchor", help="print the current head of the log to store externally")
    s.set_defaults(func=cmd_anchor)

    s = sub.add_parser("rules", help="browse and validate the footgun database")
    rs = s.add_subparsers(dest="rules_cmd", required=True)
    r = rs.add_parser("list")
    r.add_argument("--family")
    r = rs.add_parser("show")
    r.add_argument("id")
    r = rs.add_parser("validate")
    r.add_argument("file")
    s.set_defaults(func=cmd_rules)

    s = sub.add_parser("snapshots", help="list, show, restore or prune safety snapshots")
    ss = s.add_subparsers(dest="snap_cmd", required=True)
    ss.add_parser("list")
    x = ss.add_parser("show")
    x.add_argument("id")
    x = ss.add_parser("restore")
    x.add_argument("id")
    x.add_argument("--force", action="store_true")
    x.add_argument("--to")
    x.add_argument("--apply", action="store_true", help="for git snapshots: apply saved changes")
    x = ss.add_parser("prune")
    x.add_argument("--older-than-days", type=float)
    x.add_argument("--max-total-mb", type=int)
    s.set_defaults(func=cmd_snapshots)

    s = sub.add_parser("doctor", help="check the installation")
    s.set_defaults(func=cmd_doctor)

    s = sub.add_parser("badge", help="write the 'protected by kneepad' badge (only if actually protected)")
    s.add_argument("--out", default="kneepad-badge.svg")
    s.add_argument("--force", action="store_true")
    s.set_defaults(func=cmd_badge)
    return p


def shell_main() -> int:
    """Entry point for `kneepad-shell`: a drop-in value for $SHELL."""
    return main(["shell"] + sys.argv[1:])


def _flush_std(rc: int) -> int:
    """Flush stdout and stderr inside main() so a reader that went away (`kneepad rules list | head -1`) is handled here.

    A broken pipe caught earlier still leaves the final partial buffer pending; the interpreter would then fail to flush it
    at exit and print "Exception ignored ... BrokenPipeError" with exit status 120. Pointing the descriptor at /dev/null
    (the recipe from the Python documentation) makes that exit-time flush harmless."""
    for stream in (sys.stdout, sys.stderr):
        if stream is None:
            continue
        try:
            stream.flush()
        except BrokenPipeError:
            try:
                os.dup2(os.open(os.devnull, os.O_WRONLY), stream.fileno())
            except (OSError, ValueError, AttributeError):
                pass
        except (OSError, ValueError):
            pass
    return rc


def main(argv: Optional[List[str]] = None) -> int:
    return _flush_std(_main(argv))


def _main(argv: Optional[List[str]] = None) -> int:
    raw = list(sys.argv[1:] if argv is None else argv)
    # `shell` and `run` forward arbitrary arguments (including -c and other dash options) to another
    # program, which argparse cannot express with REMAINDER when the first token starts with a dash.
    if raw and raw[0] in ("shell", "run"):
        ns = argparse.Namespace(argv=raw[1:])
        try:
            return int((cmd_shell if raw[0] == "shell" else cmd_run)(ns))
        except KeyboardInterrupt:
            return 130
    args = build_parser().parse_args(raw)
    try:
        return int(args.func(args))
    except KeyboardInterrupt:
        return 130
    except BrokenPipeError:
        return 0
    except OSError as exc:
        print(f"kneepad: error: {exc}", file=sys.stderr)
        return 1
