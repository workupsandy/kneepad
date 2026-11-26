"""Install and remove Kneepad in each supported agent's own configuration, safely.

All edits are additive and reversible: other settings are preserved, invalid files are refused,
writes are atomic, and a backup is kept. Only entries whose command contains "kneepad hook" are
ever touched on uninstall.
"""

from __future__ import annotations

import os
import shutil
import stat
import sys
from typing import Callable, Dict, List, Optional, Tuple

from .installer import InstallError, _load, _write_atomic
from .util import is_windows, quote_exe


def _exe() -> str:
    exe = shutil.which("kneepad")
    return quote_exe(exe) if exe else f"{quote_exe(sys.executable)} -m kneepad"


def cmd_for(target: str) -> str:
    return f"{_exe()} hook {target}"


def _ours(entry: object) -> bool:
    if not isinstance(entry, dict):
        return False
    c = str(entry.get("command", "")) + str(entry.get("bash", "")) + str(entry.get("powershell", ""))
    return "kneepad" in c and " hook " in f" {c} "


def _backup(path: str) -> None:
    if os.path.exists(path):
        shutil.copy2(path, path + ".kneepad-bak")


# ---------------------------------------------------------------- flat lists: Cursor, Copilot
def _flat_install(path: str, events: Dict[str, dict], top: Dict[str, object]) -> str:
    data = _load(path)
    for k, v in top.items():
        data.setdefault(k, v)
    hooks = data.setdefault("hooks", {})
    if not isinstance(hooks, dict):
        raise InstallError(f"'hooks' in {path} is not an object; refusing to modify it")
    changed = False
    for ev, entry in events.items():
        lst = hooks.setdefault(ev, [])
        if not isinstance(lst, list):
            raise InstallError(f"'hooks.{ev}' in {path} is not a list; refusing to modify it")
        if not any(_ours(e) for e in lst):
            lst.append(entry)
            changed = True
    if not changed:
        return "already-installed"
    _backup(path)
    _write_atomic(path, data)
    return "installed"


def _flat_uninstall(path: str) -> str:
    if not os.path.exists(path):
        return "not-installed"
    data = _load(path)
    hooks = data.get("hooks")
    if not isinstance(hooks, dict):
        return "not-installed"
    changed = False
    for ev in list(hooks):
        lst = hooks[ev]
        if isinstance(lst, list):
            kept = [e for e in lst if not _ours(e)]
            if len(kept) != len(lst):
                changed = True
                if kept:
                    hooks[ev] = kept
                else:
                    del hooks[ev]
    if not changed:
        return "not-installed"
    _backup(path)
    _write_atomic(path, data)
    return "removed"


def _flat_is_installed(path: str) -> bool:
    try:
        data = _load(path)
    except InstallError:
        return False
    hooks = data.get("hooks")
    return isinstance(hooks, dict) and any(isinstance(v, list) and any(_ours(e) for e in v) for v in hooks.values())


# ---------------------------------------------------------------- nested: Gemini, Codex
def _nested_install(path: str, event: str, matcher: str, hook: dict) -> str:
    data = _load(path)
    hooks = data.setdefault("hooks", {})
    if not isinstance(hooks, dict):
        raise InstallError(f"'hooks' in {path} is not an object; refusing to modify it")
    lst = hooks.setdefault(event, [])
    if not isinstance(lst, list):
        raise InstallError(f"'hooks.{event}' in {path} is not a list; refusing to modify it")
    for g in lst:
        if isinstance(g, dict) and isinstance(g.get("hooks"), list) and any(_ours(h) for h in g["hooks"]):
            return "already-installed"
    lst.append({"matcher": matcher, "hooks": [hook]})
    _backup(path)
    _write_atomic(path, data)
    return "installed"


def _nested_uninstall(path: str, event: str) -> str:
    if not os.path.exists(path):
        return "not-installed"
    data = _load(path)
    hooks = data.get("hooks")
    lst = hooks.get(event) if isinstance(hooks, dict) else None
    if not isinstance(lst, list):
        return "not-installed"
    changed = False
    new = []
    for g in lst:
        if isinstance(g, dict) and isinstance(g.get("hooks"), list):
            kept = [h for h in g["hooks"] if not _ours(h)]
            if len(kept) != len(g["hooks"]):
                changed = True
            if kept:
                g = dict(g)
                g["hooks"] = kept
                new.append(g)
        else:
            new.append(g)
    if not changed:
        return "not-installed"
    if new:
        hooks[event] = new
    else:
        del hooks[event]
    _backup(path)
    _write_atomic(path, data)
    return "removed"


def _nested_is_installed(path: str, event: str) -> bool:
    try:
        data = _load(path)
    except InstallError:
        return False
    hooks = data.get("hooks")
    lst = hooks.get(event) if isinstance(hooks, dict) else None
    return isinstance(lst, list) and any(
        isinstance(g, dict) and isinstance(g.get("hooks"), list) and any(_ours(h) for h in g["hooks"]) for g in lst)


# ---------------------------------------------------------------- Cline: script file
CLINE_MARK = "# kneepad-managed hook"


def _cline_script() -> str:
    return f"#!/usr/bin/env bash\n{CLINE_MARK}\nexec {cmd_for('cline')}\n"


# ---------------------------------------------------------------- targets
def path_for(target: str, scope: str, cwd: str) -> str:
    home = os.path.expanduser("~")
    proj = os.path.abspath(cwd)
    if target == "cursor":
        return os.path.join(home if scope == "user" else proj, ".cursor", "hooks.json")
    if target == "gemini":
        return os.path.join(home if scope == "user" else proj, ".gemini", "settings.json")
    if target == "codex":
        return os.path.join(home if scope == "user" else proj, ".codex", "hooks.json")
    if target == "copilot":
        return os.path.join(home, ".copilot", "hooks", "kneepad.json") if scope == "user" else os.path.join(proj, ".github", "hooks", "kneepad.json")
    if target == "cline":
        base = os.path.join(home, "Documents", "Cline", "Hooks") if scope == "user" else os.path.join(proj, ".clinerules", "hooks")
        return os.path.join(base, "PreToolUse")
    raise InstallError(f"no installer for {target!r}")


def install_target(target: str, scope: str, cwd: str) -> Tuple[str, str]:
    path = path_for(target, scope, cwd)
    c = cmd_for(target)
    if target == "cursor":
        entry = {"command": c, "failClosed": True}
        r = _flat_install(path, {"beforeShellExecution": entry, "beforeMCPExecution": entry}, {"version": 1})
    elif target == "copilot":
        entry = {"type": "command", "bash": c, "timeoutSec": 30}
        if is_windows():
            entry["powershell"] = c
        r = _flat_install(path, {"preToolUse": entry}, {"version": 1})
    elif target == "gemini":
        r = _nested_install(path, "BeforeTool", ".*", {"name": "kneepad", "type": "command", "command": c, "timeout": 30000})
    elif target == "codex":
        r = _nested_install(path, "PreToolUse", ".*", {"type": "command", "command": c, "timeout": 30})
    elif target == "cline":
        if is_windows():
            raise InstallError("Cline's hooks are documented for macOS and Linux only; Kneepad does not install them on Windows")
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                if CLINE_MARK in fh.read():
                    return "already-installed", path
            raise InstallError(f"{path} already exists and is not managed by Kneepad; refusing to overwrite it")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(_cline_script())
        os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        r = "installed"
    else:
        raise InstallError(f"no installer for {target!r}")
    return r, path


def uninstall_target(target: str, scope: str, cwd: str) -> Tuple[str, str]:
    path = path_for(target, scope, cwd)
    if target in ("cursor", "copilot"):
        return _flat_uninstall(path), path
    if target == "gemini":
        return _nested_uninstall(path, "BeforeTool"), path
    if target == "codex":
        return _nested_uninstall(path, "PreToolUse"), path
    if target == "cline":
        if not os.path.exists(path):
            return "not-installed", path
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            if CLINE_MARK not in fh.read():
                return "not-installed", path
        os.unlink(path)
        return "removed", path
    raise InstallError(f"no installer for {target!r}")


def is_target_installed(target: str, scope: str, cwd: str) -> bool:
    path = path_for(target, scope, cwd)
    if target in ("cursor", "copilot"):
        return _flat_is_installed(path)
    if target == "gemini":
        return _nested_is_installed(path, "BeforeTool")
    if target == "codex":
        return _nested_is_installed(path, "PreToolUse")
    if target == "cline":
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                return CLINE_MARK in fh.read()
        except OSError:
            return False
    return False


TARGETS = ("cursor", "gemini", "codex", "copilot", "cline")
