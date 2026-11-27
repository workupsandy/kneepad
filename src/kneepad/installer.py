"""Register or remove the Kneepad hook in Claude Code settings, safely."""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
from typing import List

from .util import is_kneepad_hook_command, quote_exe

MATCHER = "Bash|Write|Edit|MultiEdit|NotebookEdit|mcp__.*"


class InstallError(Exception):
    pass


def hook_command() -> str:
    exe = shutil.which("kneepad")
    if exe:
        return f"{quote_exe(exe)} hook claude"
    return f"{quote_exe(sys.executable)} -m kneepad hook claude"


def settings_path(scope: str, cwd: str) -> str:
    if scope == "user":
        return os.path.join(os.path.expanduser("~"), ".claude", "settings.json")
    if scope == "project":
        return os.path.join(os.path.abspath(cwd), ".claude", "settings.json")
    raise InstallError(f"unknown scope {scope!r}")


def _is_ours(handler: object) -> bool:
    if not isinstance(handler, dict):
        return False
    cmd = str(handler.get("command", ""))
    return is_kneepad_hook_command(cmd)


def _load(path: str) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            text = fh.read()
    except FileNotFoundError:
        return {}
    if not text.strip():
        return {}
    try:
        data = json.loads(text)
    except ValueError as exc:
        raise InstallError(f"{path} is not valid JSON ({exc}); refusing to modify it") from exc
    if not isinstance(data, dict):
        raise InstallError(f"{path} is not a JSON object; refusing to modify it")
    return data


def _write_atomic(path: str, data: dict) -> None:
    d = os.path.dirname(path) or "."
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".kneepad-", suffix=".tmp", dir=d)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
            fh.write("\n")
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _groups(data: dict) -> List[dict]:
    hooks = data.get("hooks")
    if not isinstance(hooks, dict):
        return []
    pre = hooks.get("PreToolUse")
    return [g for g in pre if isinstance(g, dict)] if isinstance(pre, list) else []


def is_installed(path: str) -> bool:
    try:
        data = _load(path)
    except InstallError:
        return False
    return any(_is_ours(h) for g in _groups(data) for h in (g.get("hooks") or []) if isinstance(g.get("hooks"), list))


def install(path: str, command: str) -> str:
    data = _load(path)
    if is_installed(path):
        return "already-installed"
    hooks = data.setdefault("hooks", {})
    if not isinstance(hooks, dict):
        raise InstallError(f"'hooks' in {path} is not an object; refusing to modify it")
    pre = hooks.setdefault("PreToolUse", [])
    if not isinstance(pre, list):
        raise InstallError(f"'hooks.PreToolUse' in {path} is not a list; refusing to modify it")
    pre.append({"matcher": MATCHER, "hooks": [{"type": "command", "command": command}]})
    if os.path.exists(path):
        shutil.copy2(path, path + ".kneepad-bak")
    _write_atomic(path, data)
    return "installed"


def uninstall(path: str) -> str:
    if not os.path.exists(path):
        return "not-installed"
    data = _load(path)
    pre = (data.get("hooks") or {}).get("PreToolUse") if isinstance(data.get("hooks"), dict) else None
    if not isinstance(pre, list):
        return "not-installed"
    changed = False
    new_pre = []
    for g in pre:
        if isinstance(g, dict) and isinstance(g.get("hooks"), list):
            kept = [h for h in g["hooks"] if not _is_ours(h)]
            if len(kept) != len(g["hooks"]):
                changed = True
            if kept:
                g = dict(g)
                g["hooks"] = kept
                new_pre.append(g)
        else:
            new_pre.append(g)
    if not changed:
        return "not-installed"
    shutil.copy2(path, path + ".kneepad-bak")
    data["hooks"]["PreToolUse"] = new_pre
    if not new_pre:
        del data["hooks"]["PreToolUse"]
    if not data["hooks"]:
        del data["hooks"]
    _write_atomic(path, data)
    return "removed"
