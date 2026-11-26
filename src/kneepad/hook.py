"""Claude Code PreToolUse hook.

Contract (verified against the Claude Code hooks documentation):
* stdin: a JSON object with ``tool_name``, ``tool_input``, ``cwd``, ``hook_event_name``...
* to block:  print {"hookSpecificOutput": {"hookEventName": "PreToolUse",
  "permissionDecision": "deny", "permissionDecisionReason": "..."}} and exit 0.
* to ask the user: same shape with "ask".
* to stay out of the way: print NOTHING and exit 0.

Kneepad never prints "allow". An "allow" from a hook skips Claude Code's own
permission prompts, which would silently approve commands the user would
otherwise have been asked about. Silence means "no opinion", and the normal
permission flow continues.

Failure mode: if anything inside Kneepad breaks, it answers "ask" rather than
staying silent, so a bug can never quietly turn into an allow.
"""

from __future__ import annotations

import json
import os
from typing import Dict, List, Optional, Tuple

from .adapters import Adapter, get_adapter
from .audit import AuditLog
from .config import load_config
from .engine import Analyzer, Decision, Finding
from .snapshots import SnapshotError, SnapshotStore
from .util import redact, kneepad_home

MAX_STDIN = 8_000_000


def _out(action: str, reason: str) -> str:
    return json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": action,
            "permissionDecisionReason": reason,
        }
    })


def _log(audit: AuditLog, payload: dict, tool: str, decision: Decision, snaps: List[str], extra: Optional[dict] = None) -> None:
    data = {
        "tool": tool,
        "action": decision.action,
        "mode": decision.mode,
        "cwd": str(payload.get("cwd", "")),
        "session": str(payload.get("session_id", ""))[:64],
        "tool_use_id": str(payload.get("tool_use_id", ""))[:64],
        "findings": [
            {"rule": f.rule_id, "severity": f.severity, "action": f.action, "detail": redact(f.detail, 300)}
            for f in decision.findings
        ],
        "snapshots": snaps,
    }
    if tool == "Bash":
        data["command"] = redact(str((payload.get("tool_input") or {}).get("command", "")))
    elif "file_path" in (payload.get("tool_input") or {}):
        data["path"] = redact(str(payload["tool_input"]["file_path"]), 500)
    if extra:
        data.update(extra)
    try:
        audit.append("decision", data)
    except Exception:
        pass  # logging must never change the decision


def _normalised(parsed) -> dict:
    tin = dict(parsed.tin) if isinstance(parsed.tin, dict) else {}
    if parsed.kind == "write" and "file_path" not in tin:
        for k in ("path", "filePath", "notebook_path", "target_file", "filename"):
            if isinstance(tin.get(k), str):
                tin["file_path"] = tin[k]
                break
    return {"cwd": parsed.cwd, "session_id": parsed.session, "tool_use_id": parsed.use_id, "tool_input": tin}


def handle(stdin_text: str, home: Optional[str] = None, integration: str = "claude") -> Tuple[int, str]:
    """Process one hook invocation. Returns (exit_code, stdout_text)."""
    home = home or kneepad_home()
    ad: Adapter = get_adapter(integration)
    audit = AuditLog(home)

    def out(action: str, reason: str) -> Tuple[int, str]:
        return ad.render(action, reason)

    try:
        if len(stdin_text) > MAX_STDIN:
            return out("ask", "Kneepad: the tool input is too large to analyse. Confirm manually.")
        try:
            payload = json.loads(stdin_text.lstrip("\ufeff"))
        except ValueError:
            return out("ask", "Kneepad could not parse the hook input, so it could not check this action. Confirm manually.")
        if not isinstance(payload, dict):
            return out("ask", "Kneepad received unexpected hook input. Confirm manually.")
        if not ad.event_ok(payload):
            return 0, ""
        parsed = ad.parse(payload)
        if parsed.kind is None:
            return ad.render("allow", "") if ad.requires_explicit_allow else (0, "")
        tin = parsed.tin if isinstance(parsed.tin, dict) else {}
        cwd = parsed.cwd
        if not cwd or not os.path.isdir(cwd):
            cwd = os.getcwd()
        cfg = load_config(cwd, home)
        az = Analyzer(config=cfg, cwd=cwd)
        if parsed.kind == "bash":
            cmd = tin.get("command", "")
            decision = az.analyze_shell(cmd if isinstance(cmd, str) else json.dumps(cmd))
            tool = "Bash"
        elif parsed.kind == "write":
            path = tin.get("file_path") or tin.get("path") or tin.get("filePath") or tin.get("notebook_path") or tin.get("target_file")
            if not isinstance(path, str) or not path:
                return ad.render("allow", "") if ad.requires_explicit_allow else (0, "")
            decision = az.analyze_write_path(path)
            tool = parsed.tool or "Write"
        else:
            decision = az.analyze_mcp(parsed.tool, tin)
            tool = parsed.tool
        if not decision.findings:
            return ad.render("allow", "") if ad.requires_explicit_allow else (0, "")

        snap_ids: List[str] = []
        if decision.plans:
            store = SnapshotStore(home)
            try:
                for plan in decision.plans:
                    snap_ids.append(store.create(plan)["id"])
                store.prune(max_total_mb=cfg.snapshot_total_mb)
            except SnapshotError as exc:
                rule = az.by_id["snapshot-unavailable"]
                decision.findings.append(Finding(
                    rule_id=rule.id, title="safety snapshot could not be taken", severity="medium", action="ask",
                    why=f"Kneepad tried to copy what this command would delete, and failed: {exc}",
                    safer="Back up what you need manually, then confirm.", detail=str(exc)[:160],
                ))
                decision.action = "ask"

        norm = _normalised(parsed)
        _log(audit, norm, "Bash" if parsed.kind == "bash" else tool, decision, snap_ids, {"integration": integration})
        if cfg.mode == "monitor":
            return ad.render("allow", "") if ad.requires_explicit_allow else (0, "")
        if decision.action == "allow":
            # Snapshot (if any) is already taken; the command proceeds through the agent's normal flow.
            return ad.render("allow", "") if ad.requires_explicit_allow else (0, "")
        reason = decision.reason()
        if snap_ids and decision.action == "ask":
            reason += f"\nA safety snapshot was taken first: kneepad snapshots show {snap_ids[0]}"
        for w in cfg.warnings[:2]:
            reason += f"\nConfig warning: {w}"
        return out(decision.action, reason)
    except Exception as exc:  # fail to "ask" (or deny where there is no ask), never to silent allow
        try:
            audit.append("error", {"error": type(exc).__name__, "message": redact(str(exc), 300)})
        except Exception:
            pass
        return out("ask", f"Kneepad hit an internal error ({type(exc).__name__}) and could not check this action. Confirm manually.")
