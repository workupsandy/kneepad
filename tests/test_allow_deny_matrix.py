"""ALLOW, ASK and DENY behaviour across every hook protocol, plus engine regressions found by the QA corpus probe.

Every adapter is driven through hook.handle() with a payload in that vendor's documented shape, for a command that must
be allowed, one that must be asked about, one that must be denied, a protected write, a harmless write, an MCP call,
a tool Kneepad does not handle, and malformed input.
"""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from kneepad.adapters import ADAPTERS  # noqa: E402
from kneepad.config import Config  # noqa: E402
from kneepad.engine import Analyzer  # noqa: E402
from kneepad.hook import handle  # noqa: E402

ALLOW_CMD = "ls -la"
ASK_CMD = "terraform destroy"
DENY_CMD = "rm -rf /"


class Env:
    def __init__(self):
        self.home = tempfile.mkdtemp()
        self.work = tempfile.mkdtemp()
        self.state = tempfile.mkdtemp()
        self._saved = {k: os.environ.get(k) for k in ("HOME", "USERPROFILE", "KNEEPAD_HOME", "KNEEPAD_MODE")}
        os.environ["HOME"] = os.environ["USERPROFILE"] = self.home
        os.environ["KNEEPAD_HOME"] = self.state
        os.environ.pop("KNEEPAD_MODE", None)

    def close(self):
        for k, v in self._saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def payload(adapter, kind, value, cwd):
    """Build a vendor-shaped payload. kind: bash | write | mcp | other."""
    if adapter in ("claude", "codex"):
        base = {"hook_event_name": "PreToolUse", "cwd": cwd, "session_id": "s", "tool_use_id": "t"}
        if kind == "bash":
            return {**base, "tool_name": "Bash", "tool_input": {"command": value}}
        if kind == "write":
            return {**base, "tool_name": "Write", "tool_input": {"file_path": value, "content": "x"}}
        if kind == "mcp":
            return {**base, "tool_name": "mcp__db__query", "tool_input": {"sql": value}}
        return {**base, "tool_name": "Read", "tool_input": {"file_path": value}}
    if adapter == "copilot":
        if kind == "bash":
            return {"toolName": "bash", "toolArgs": json.dumps({"command": value}), "cwd": cwd}
        if kind == "write":
            return {"toolName": "edit", "toolArgs": json.dumps({"path": value}), "cwd": cwd}
        if kind == "mcp":
            return {"toolName": "mcp__db__query", "toolArgs": json.dumps({"sql": value}), "cwd": cwd}
        return {"toolName": "view", "toolArgs": json.dumps({"path": value}), "cwd": cwd}
    if adapter == "cursor":
        if kind == "bash":
            return {"hook_event_name": "beforeShellExecution", "command": value, "cwd": cwd}
        if kind == "write":
            return {"hook_event_name": "preToolUse", "tool_name": "Write", "tool_input": {"file_path": value}, "cwd": cwd}
        if kind == "mcp":
            return {"hook_event_name": "beforeMCPExecution", "tool_name": "db__query", "tool_input": {"sql": value}, "cwd": cwd}
        return {"hook_event_name": "beforeReadFile", "tool_name": "Read", "tool_input": {"file_path": value}, "cwd": cwd}
    if adapter == "gemini":
        base = {"hook_event_name": "BeforeTool", "cwd": cwd}
        if kind == "bash":
            return {**base, "tool_name": "run_shell_command", "tool_input": {"command": value}}
        if kind == "write":
            return {**base, "tool_name": "write_file", "tool_input": {"file_path": value}}
        if kind == "mcp":
            return {**base, "tool_name": "mcp_db_query", "tool_input": {"sql": value}}
        return {**base, "tool_name": "read_file", "tool_input": {"file_path": value}}
    if adapter == "cline":
        base = {"hookName": "PreToolUse", "workspaceRoots": [cwd]}
        if kind == "bash":
            return {**base, "preToolUse": {"toolName": "execute_command", "parameters": {"command": value}}}
        if kind == "write":
            return {**base, "preToolUse": {"toolName": "write_to_file", "parameters": {"path": value}}}
        if kind == "mcp":
            return {**base, "preToolUse": {"toolName": "use_mcp_tool", "parameters": {"server_name": "db", "tool_name": "query", "arguments": {"sql": value}}}}
        return {**base, "preToolUse": {"toolName": "read_file", "parameters": {"path": value}}}
    if adapter == "generic":
        if kind == "bash":
            return {"command": value, "cwd": cwd}
        if kind == "write":
            return {"tool": "write", "path": value}
        return {"nothing": True}
    raise AssertionError(adapter)


def decision(adapter, code, out):
    """Normalise a vendor response to allow / ask / deny."""
    if adapter in ("claude", "codex"):
        if not out.strip():
            return "allow"
        return json.loads(out)["hookSpecificOutput"]["permissionDecision"]
    if adapter == "copilot":
        if not out.strip():
            return "allow"
        return json.loads(out)["permissionDecision"]
    if adapter == "cursor":
        return json.loads(out)["permission"]
    if adapter == "gemini":
        return json.loads(out)["decision"]
    if adapter == "cline":
        return "deny" if json.loads(out)["cancel"] else "allow"
    if adapter == "generic":
        return "deny" if code == 2 else "allow"
    raise AssertionError(adapter)


class TestEveryAdapterAllowAskDeny(unittest.TestCase):
    def setUp(self):
        self.e = Env()

    def tearDown(self):
        self.e.close()

    def run_one(self, adapter, kind, value):
        p = payload(adapter, kind, value, self.e.work)
        code, out = handle(json.dumps(p), home=self.e.state, integration=adapter)
        return decision(adapter, code, out), code, out

    def test_allow(self):
        for a in sorted(ADAPTERS):
            with self.subTest(adapter=a):
                self.assertEqual(self.run_one(a, "bash", ALLOW_CMD)[0], "allow")

    def test_ask_or_deny_where_no_ask_exists(self):
        for a in sorted(ADAPTERS):
            with self.subTest(adapter=a):
                d = self.run_one(a, "bash", ASK_CMD)[0]
                if ADAPTERS[a].supports_ask:
                    self.assertEqual(d, "ask")
                else:
                    self.assertEqual(d, "deny")  # never silently allowed because the vendor has no ask

    def test_deny(self):
        for a in sorted(ADAPTERS):
            with self.subTest(adapter=a):
                self.assertEqual(self.run_one(a, "bash", DENY_CMD)[0], "deny")

    def test_protected_write_is_stopped_and_plain_write_allowed(self):
        protected = os.path.join(self.e.home, ".ssh", "authorized_keys")
        plain = os.path.join(self.e.work, "src", "a.py")
        for a in sorted(ADAPTERS):
            with self.subTest(adapter=a):
                self.assertIn(self.run_one(a, "write", protected)[0], ("ask", "deny"))
                self.assertEqual(self.run_one(a, "write", plain)[0], "allow")

    def test_mcp_and_unknown_tools(self):
        for a in sorted(ADAPTERS):
            with self.subTest(adapter=a):
                self.assertEqual(self.run_one(a, "mcp", "SELECT 1")[0], "allow")
                if a != "generic":  # the generic protocol has no MCP concept
                    self.assertIn(self.run_one(a, "mcp", "DROP TABLE users")[0], ("ask", "deny"))
                self.assertEqual(self.run_one(a, "other", os.path.join(self.e.work, "f"))[0], "allow")

    def test_malformed_input_never_allows(self):
        for a in sorted(ADAPTERS):
            for raw in ("", "   ", "{not json", "[1,2]", "null", '"str"', "42", "\x00\x00", "{" * 5000):
                with self.subTest(adapter=a, raw=raw[:12]):
                    code, out = handle(raw, home=self.e.state, integration=a)
                    d = decision(a, code, out) if (out or code) else "allow"
                    self.assertNotEqual(d, "allow", f"{a} treated {raw[:20]!r} as allowed")

    def test_oversized_input_asks(self):
        raw = json.dumps(payload("claude", "bash", "echo " + "x" * 9_000_000, self.e.work))
        code, out = handle(raw, home=self.e.state, integration="claude")
        self.assertEqual(decision("claude", code, out), "ask")

    def test_monitor_mode_allows_but_still_logs(self):
        os.environ["KNEEPAD_MODE"] = "monitor"
        for a in sorted(ADAPTERS):
            with self.subTest(adapter=a):
                self.assertEqual(self.run_one(a, "bash", DENY_CMD)[0], "allow")
        from kneepad.audit import AuditLog
        entries = [e for e in AuditLog(self.e.state).read_all() if e["event"] == "decision"]
        self.assertGreaterEqual(len(entries), len(ADAPTERS))
        self.assertTrue(all(e["data"]["mode"] == "monitor" for e in entries))

    def test_wrong_event_is_ignored(self):
        p = payload("claude", "bash", DENY_CMD, self.e.work)
        p["hook_event_name"] = "PostToolUse"
        code, out = handle(json.dumps(p), home=self.e.state, integration="claude")
        self.assertEqual(out.strip(), "")
        p = payload("gemini", "bash", DENY_CMD, self.e.work)
        p["hook_event_name"] = "AfterTool"
        code, out = handle(json.dumps(p), home=self.e.state, integration="gemini")
        self.assertEqual((code, out.strip()), (0, ""))  # not Kneepad's event: no opinion, exit 0

    def test_string_encoded_tool_input(self):
        p = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": json.dumps({"command": DENY_CMD}), "cwd": self.e.work}
        code, out = handle(json.dumps(p), home=self.e.state, integration="claude")
        self.assertEqual(decision("claude", code, out), "deny")

    def test_every_path_key_is_understood_for_writes(self):
        protected = os.path.join(self.e.home, ".ssh", "id_rsa")
        for key in ("file_path", "path", "filePath", "notebook_path", "target_file"):
            p = {"hook_event_name": "PreToolUse", "tool_name": "Write", "tool_input": {key: protected}, "cwd": self.e.work}
            code, out = handle(json.dumps(p), home=self.e.state, integration="claude")
            with self.subTest(key=key):
                self.assertIn(decision("claude", code, out), ("ask", "deny"))

    def test_write_with_no_path_is_allowed_not_crash(self):
        p = {"hook_event_name": "PreToolUse", "tool_name": "Write", "tool_input": {"content": "x"}, "cwd": self.e.work}
        code, out = handle(json.dumps(p), home=self.e.state, integration="claude")
        self.assertEqual(decision("claude", code, out), "allow")

    def test_cursor_workspace_roots_and_conversation_id(self):
        p = {"hook_event_name": "beforeShellExecution", "command": DENY_CMD, "workspace_roots": [self.e.work], "conversation_id": "c1"}
        code, out = handle(json.dumps(p), home=self.e.state, integration="cursor")
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(out)["permission"], "deny")

    def test_copilot_pascal_case_payload(self):
        p = {"hook_event_name": "PreToolUse", "tool_name": "bash", "tool_input": {"command": DENY_CMD}, "cwd": self.e.work}
        code, out = handle(json.dumps(p), home=self.e.state, integration="copilot")
        self.assertEqual(decision("copilot", code, out), "deny")

    def test_audit_records_every_non_trivial_decision_once(self):
        from kneepad.audit import AuditLog
        for a in sorted(ADAPTERS):
            self.run_one(a, "bash", DENY_CMD)
        log = AuditLog(self.e.state)
        self.assertTrue(log.verify().ok)
        self.assertEqual(len([e for e in log.read_all() if e["event"] == "decision"]), len(ADAPTERS))


class TestEngineQaRegressions(unittest.TestCase):
    """Found by the 420-command allow/deny probe (tools/qa_probe corpus)."""

    def setUp(self):
        self.e = Env()
        self.az = Analyzer(config=Config(), cwd=self.e.work)

    def tearDown(self):
        self.e.close()

    def action(self, cmd):
        return self.az.analyze_shell(cmd).action

    def test_wiping_a_directory_with_a_match_all_glob_is_catastrophic_even_if_it_matches_nothing_today(self):
        for cmd in ("rm -rf ~/*", "rm -rf $HOME/*", "rm -rf ~/.[a-z]*", "rm -rf ~/.*", "rm -rf /home/*", "rm -rf /*", "rm -rf ~/?*"):
            with self.subTest(cmd=cmd):
                self.assertEqual(self.action(cmd), "deny")

    def test_ordinary_globs_are_not_blocked(self):
        for cmd in ("rm -rf ~/*.log", "rm -rf ~/proj/*", "rm -rf build/*", "rm -f ~/*", "ls ~/*", "echo ~/*"):
            with self.subTest(cmd=cmd):
                self.assertEqual(self.action(cmd), "allow")

    def test_tilde_in_assignment_is_expanded(self):
        self.assertEqual(self.action("x=~; rm -rf $x"), "deny")
        self.assertEqual(self.action("x=~/; rm -rf $x"), "deny")
        self.assertEqual(self.action("x=~/proj; rm -rf $x"), "allow")
        self.assertEqual(self.action('x="~"; rm -rf $x'), "allow")  # quoted tilde is a literal directory name

    def test_busybox_and_toybox_are_unwrapped(self):
        self.assertEqual(self.action("busybox rm -rf /"), "deny")
        self.assertEqual(self.action("toybox rm -rf ~"), "deny")
        self.assertEqual(self.action("busybox ls"), "allow")
        self.assertEqual(self.action("busybox"), "allow")

    def test_mcp_server_named_db_is_scanned_for_sql(self):
        for name in ("mcp__db__run", "mcp__db__q", "mcp__my_db__exec", "mcp__db"):
            with self.subTest(name=name):
                self.assertIn(self.az.analyze_mcp(name, {"sql": "DROP TABLE users"}).action, ("ask", "deny"))
        self.assertEqual(self.az.analyze_mcp("mcp__dbus__ping", {"sql": "DROP TABLE users"}).action, "allow")

    def test_unlink_is_treated_like_rm(self):
        self.assertIn(self.action("unlink /etc/passwd"), ("ask", "deny"))
        self.assertEqual(self.action("unlink somefile.txt"), "allow")


if __name__ == "__main__":
    unittest.main()
