"""Adapters: translate each agent's hook protocol to and from Kneepad's decisions.

Every contract below was taken from the vendor's public documentation (see docs/INTEGRATIONS.md
for links and the date checked). They are tested against the documented payloads. They have NOT
been exercised inside every vendor application, which is why docs/INTEGRATIONS.md labels each
integration's verification level.

Common rules:
* A protocol that has no "ask" answer maps ask to deny, because failing open would be worse.
* A protocol that requires an explicit "allow" answer gets one only when Kneepad has no objection.
* A Claude-style protocol (Claude Code, Codex) stays silent on allow so the user's own permission
  prompts keep working.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Optional, Tuple

WRITE_TOOLS = {
    "write", "edit", "multiedit", "notebookedit", "write_file", "replace", "create", "str_replace_editor",
    "str_replace_based_edit_tool", "write_to_file", "replace_in_file", "insert_content", "apply_diff", "edit_file",
    "create_file",
}
SHELL_TOOLS = {"bash", "run_shell_command", "execute_command", "shell", "powershell", "launch-process", "run_terminal_cmd"}


@dataclass
class Parsed:
    kind: Optional[str]  # "bash" | "write" | "mcp" | None (not our business)
    tool: str = ""
    tin: Dict[str, Any] = field(default_factory=dict)
    cwd: str = ""
    session: str = ""
    use_id: str = ""


def _dict(v: Any) -> Dict[str, Any]:
    if isinstance(v, dict):
        return v
    if isinstance(v, str):
        try:
            d = json.loads(v)
            return d if isinstance(d, dict) else {}
        except ValueError:
            return {}
    return {}


def _classify(tool: str, tin: Dict[str, Any]) -> Optional[str]:
    t = tool.lower()
    if t in SHELL_TOOLS or (t.startswith("bash") and "command" in tin):
        return "bash"
    if t in WRITE_TOOLS:
        return "write"
    if t.startswith("mcp") or "__" in t:
        return "mcp"
    return None


def _path_of(tin: Dict[str, Any]) -> str:
    for k in ("file_path", "path", "filePath", "notebook_path", "target_file", "filename"):
        if isinstance(tin.get(k), str) and tin[k]:
            return tin[k]
    return ""


class Adapter:
    name = "base"
    supports_ask = True
    requires_explicit_allow = False

    def parse(self, payload: Dict[str, Any]) -> Parsed:  # pragma: no cover - interface
        raise NotImplementedError

    def render(self, action: str, reason: str) -> Tuple[int, str]:  # pragma: no cover - interface
        raise NotImplementedError

    def event_ok(self, payload: Dict[str, Any]) -> bool:
        return True

    def effective(self, action: str) -> str:
        if action == "ask" and not self.supports_ask:
            return "deny"
        return action


class ClaudeAdapter(Adapter):
    """Claude Code. Also the shape OpenAI Codex documents for PreToolUse."""

    name = "claude"

    def event_ok(self, payload):
        return payload.get("hook_event_name", "PreToolUse") == "PreToolUse"

    def parse(self, payload):
        tool = str(payload.get("tool_name", ""))
        tin = _dict(payload.get("tool_input"))
        kind = _classify(tool, tin)
        if tool == "apply_patch":
            kind = None
        return Parsed(kind, tool, tin, str(payload.get("cwd") or ""), str(payload.get("session_id", "")), str(payload.get("tool_use_id", "")))

    def render(self, action, reason):
        if action == "allow":
            return 0, ""
        return 0, json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse",
                                                     "permissionDecision": self.effective(action),
                                                     "permissionDecisionReason": reason}})


class CodexAdapter(ClaudeAdapter):
    """Codex documents PreToolUse with Claude-shaped input and output, but 'ask' is not supported yet."""

    name = "codex"
    supports_ask = False


class CopilotAdapter(Adapter):
    """GitHub Copilot CLI. Accepts the camelCase payload and the PascalCase/VS Code-compatible payload."""

    name = "copilot"

    def event_ok(self, payload):
        ev = payload.get("hook_event_name")
        return ev in (None, "PreToolUse", "preToolUse")

    def parse(self, payload):
        if "toolName" in payload or "toolArgs" in payload:
            tool = str(payload.get("toolName", ""))
            tin = _dict(payload.get("toolArgs"))
            sess = str(payload.get("sessionId", ""))
        else:
            tool = str(payload.get("tool_name", ""))
            tin = _dict(payload.get("tool_input"))
            sess = str(payload.get("session_id", ""))
        return Parsed(_classify(tool, tin), tool, tin, str(payload.get("cwd") or ""), sess)

    def render(self, action, reason):
        if action == "allow":
            return 0, ""
        return 0, json.dumps({"permissionDecision": self.effective(action), "permissionDecisionReason": reason})


class CursorAdapter(Adapter):
    """Cursor hooks: beforeShellExecution, beforeMCPExecution, preToolUse.

    Cursor requires an explicit permission field in every response. Cursor's docs accept
    permission "ask" for beforeShellExecution and beforeMCPExecution, but a user report on Cursor's
    forum (sandbox mode, 2026-03) shows the command running anyway after "ask". An unenforced "ask"
    would fail open, so Kneepad maps ask to deny for Cursor. Revisit when Cursor documents the fix.
    """

    name = "cursor"
    supports_ask = False
    requires_explicit_allow = True

    def parse(self, payload):
        ev = str(payload.get("hook_event_name", ""))
        cwd = str(payload.get("cwd") or "")
        if not cwd:
            roots = payload.get("workspace_roots")
            if isinstance(roots, list) and roots and isinstance(roots[0], str):
                cwd = roots[0]
        sess = str(payload.get("conversation_id") or payload.get("session_id") or "")
        if ev == "beforeShellExecution" or ("command" in payload and "tool_name" not in payload):
            return Parsed("bash", "Bash", {"command": payload.get("command", "")}, cwd, sess)
        tool = str(payload.get("tool_name", ""))
        tin = _dict(payload.get("tool_input"))
        if ev == "beforeMCPExecution":
            return Parsed("mcp", tool if tool.startswith("mcp") else f"mcp__{tool}", tin, cwd, sess)
        if ev == "beforeReadFile":
            return Parsed(None, tool, tin, cwd, sess)
        return Parsed(_classify(tool, tin), tool, tin, cwd, sess)

    def render(self, action, reason):
        eff = self.effective(action)
        if eff == "allow":
            return 0, json.dumps({"permission": "allow"})
        return 2, json.dumps({"permission": "deny", "user_message": reason, "agent_message": reason})


class GeminiAdapter(Adapter):
    """Gemini CLI BeforeTool. stdout must be only the JSON object; there is no 'ask'."""

    name = "gemini"
    supports_ask = False
    requires_explicit_allow = True

    def event_ok(self, payload):
        return payload.get("hook_event_name", "BeforeTool") == "BeforeTool"

    def parse(self, payload):
        tool = str(payload.get("tool_name", ""))
        tin = _dict(payload.get("tool_input"))
        kind = _classify(tool, tin)
        if kind is None and tool.startswith("mcp"):
            kind = "mcp"
        return Parsed(kind, tool, tin, str(payload.get("cwd") or ""), str(payload.get("session_id", "")))

    def render(self, action, reason):
        if self.effective(action) == "allow":
            return 0, json.dumps({"decision": "allow"})
        return 0, json.dumps({"decision": "deny", "reason": reason})


class ClineAdapter(Adapter):
    """Cline PreToolUse hook: input under 'preToolUse', output {cancel, errorMessage}."""

    name = "cline"
    supports_ask = False
    requires_explicit_allow = True

    def event_ok(self, payload):
        return str(payload.get("hookName", "PreToolUse")).lower() == "pretooluse"

    def parse(self, payload):
        body = payload.get("preToolUse")
        body = body if isinstance(body, dict) else {}
        tool = str(body.get("toolName", ""))
        params = _dict(body.get("parameters"))
        roots = payload.get("workspaceRoots")
        cwd = roots[0] if isinstance(roots, list) and roots and isinstance(roots[0], str) else ""
        kind = _classify(tool, params)
        if tool == "use_mcp_tool":
            kind = "mcp"
            tool = f"mcp__{params.get('server_name', 'server')}__{params.get('tool_name', 'tool')}"
            params = _dict(params.get("arguments")) or params
        return Parsed(kind, tool, params, cwd, str(payload.get("taskId", "")))

    def render(self, action, reason):
        if self.effective(action) == "allow":
            return 0, json.dumps({"cancel": False})
        return 0, json.dumps({"cancel": True, "errorMessage": reason})


class GenericAdapter(Adapter):
    """For any tool that can run a command and honour exit code 2.

    stdin: {"command": "...", "cwd": "..."} (or {"tool": "write", "path": "..."}). Exit 2 blocks;
    the reason goes to stderr (returned here as stdout text, printed to stderr by the CLI).
    """

    name = "generic"
    supports_ask = False

    def parse(self, payload):
        if isinstance(payload.get("command"), str):
            return Parsed("bash", "Bash", {"command": payload["command"]}, str(payload.get("cwd") or ""), str(payload.get("session", "")))
        path = _path_of(payload)
        if path:
            return Parsed("write", "Write", {"file_path": path}, str(payload.get("cwd") or ""))
        return Parsed(None)

    def render(self, action, reason):
        if self.effective(action) == "allow":
            return 0, ""
        return 2, reason


ADAPTERS: Dict[str, Callable[[], Adapter]] = {
    "claude": ClaudeAdapter,
    "codex": CodexAdapter,
    "copilot": CopilotAdapter,
    "cursor": CursorAdapter,
    "gemini": GeminiAdapter,
    "cline": ClineAdapter,
    "generic": GenericAdapter,
}


def get_adapter(name: str) -> Adapter:
    try:
        return ADAPTERS[name]()
    except KeyError:
        raise ValueError(f"unknown integration {name!r}; choose from {', '.join(sorted(ADAPTERS))}") from None
