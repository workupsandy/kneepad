#!/usr/bin/env python3
"""End-to-end smoke test for an installed Kneepad: run the hook command the installer wrote.

Works on Linux, macOS and Windows. It installs the hooks into a throwaway home, then executes the
exact command strings found in the written config files through the operating system shell (the way
an agent would), feeds them agent-shaped JSON and checks the decisions.

Run after `pip install kneepad` (or a built wheel):  python tools/smoke_hook.py
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile

IS_WIN = sys.platform == "win32"
FAILS = []


def check(ok, label, detail=""):
    print(("ok    " if ok else "FAIL  ") + label + ((" :: " + detail) if detail and not ok else ""))
    if not ok:
        FAILS.append(label)


def run_hook(command, payload, env, cwd):
    p = subprocess.run(command, shell=True, input=json.dumps(payload).encode("utf-8"), capture_output=True, env=env, cwd=cwd, timeout=60)
    return p.returncode, p.stdout.decode("utf-8", "replace"), p.stderr.decode("utf-8", "replace")


def main():
    tmp = tempfile.mkdtemp(prefix="kneepad smoke ")  # a space in the path on purpose
    home = os.path.join(tmp, "home dir")
    proj = os.path.join(tmp, "proj")
    os.makedirs(home)
    os.makedirs(proj)
    env = dict(os.environ, HOME=home, USERPROFILE=home, KNEEPAD_HOME=os.path.join(home, ".kneepad"))
    env.pop("KNEEPAD_MODE", None)
    exe = shutil.which("kneepad")
    base = [exe] if exe else [sys.executable, "-m", "kneepad"]

    def sp(*args):
        return subprocess.run(base + list(args), capture_output=True, env=env, cwd=proj, timeout=120)

    check(sp("--version").returncode == 0, "kneepad --version")
    r = sp("init", "--claude-code", "--target", "cursor", "--target", "gemini", "--target", "codex", "--target", "copilot")
    check(r.returncode == 0, "init installs hooks", r.stderr.decode("utf-8", "replace")[:300])

    claude = json.load(open(os.path.join(home, ".claude", "settings.json"), encoding="utf-8"))
    cmd = claude["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
    print("claude hook command:", cmd)

    def decision(out):
        try:
            return json.loads(out)["hookSpecificOutput"]["permissionDecision"]
        except (ValueError, KeyError, TypeError):
            return None

    def bash(c):
        return {"tool_name": "Bash", "tool_input": {"command": c}, "cwd": proj, "hook_event_name": "PreToolUse"}

    code, out, err = run_hook(cmd, bash("rm -rf /"), env, proj)
    check(decision(out) == "deny", "claude hook denies rm -rf /", f"code={code} out={out[:200]} err={err[:200]}")
    code, out, err = run_hook(cmd, bash("echo hello"), env, proj)
    check(decision(out) is None, "claude hook is silent on a harmless command", f"code={code} out={out[:200]} err={err[:200]}")
    code, out, err = run_hook(cmd, bash("terraform destroy -auto-approve"), env, proj)
    check(decision(out) in ("ask", "deny"), "claude hook gates terraform destroy", out[:200])
    code, out, err = run_hook(cmd, bash("echo caf\u00e9 \u65e5\u672c && echo ok"), env, proj)
    check(decision(out) is None, "claude hook handles non-ASCII input", f"code={code} out={out[:200]} err={err[:200]}")
    if IS_WIN:
        code, out, err = run_hook(cmd, bash("Remove-Item -Recurse -Force C:\\Windows"), env, proj)
        check(decision(out) == "deny", "claude hook denies Remove-Item on C:\\Windows", out[:200])
        code, out, err = run_hook(cmd, bash("rd /s /q C:\\"), env, proj)
        check(decision(out) == "deny", "claude hook denies rd /s /q C:\\", out[:200])
    if sys.platform == "darwin":
        code, out, err = run_hook(cmd, bash("diskutil eraseDisk APFS Mac disk2"), env, proj)
        check(decision(out) == "deny", "claude hook denies diskutil eraseDisk", out[:200])

    cur = json.load(open(os.path.join(home, ".cursor", "hooks.json"), encoding="utf-8"))
    ccmd = cur["hooks"]["beforeShellExecution"][0]["command"]
    code, out, err = run_hook(ccmd, {"command": "rm -rf /", "cwd": proj}, env, proj)
    try:
        perm = json.loads(out).get("permission")
    except ValueError:
        perm = None
    check(perm == "deny" or code == 2, "cursor hook denies rm -rf /", f"code={code} out={out[:200]}")

    check(sp("verify").returncode == 0, "audit log verifies after hook runs")
    check(sp("doctor").returncode in (0, 1), "doctor runs")
    check(sp("check", "terraform destroy").returncode == 10, "kneepad check exit code for ask is 10")
    check(sp("check", "ls").returncode == 0, "kneepad check exit code for allow is 0")

    shutil.rmtree(tmp, ignore_errors=True)
    print()
    print("smoke test " + ("FAILED: " + ", ".join(FAILS) if FAILS else "passed"))
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
