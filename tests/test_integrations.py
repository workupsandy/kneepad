"""Adapter payloads, installers, shell wrapper and Python API.

Payload shapes come from each vendor's public hook documentation (docs/INTEGRATIONS.md). These tests
prove Kneepad honours those documented contracts. They do not prove the vendor apps behave as documented.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest

from helpers import IsolatedCase, ROOT, SRC  # noqa: F401

from kneepad import hook, integrations
from kneepad.api import KneepadBlocked, check_command, check_mcp, check_write, guard

BAD = "terraform destroy -auto-approve"
OK = "ls -la"
ASKY = "helm uninstall my-release"


def payload(target: str, command: str, cwd: str) -> str:
    if target == "claude":
        return json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": command}, "cwd": cwd, "session_id": "s"})
    if target == "codex":
        return json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": command}, "cwd": cwd, "session_id": "s"})
    if target == "cursor":
        return json.dumps({"hook_event_name": "beforeShellExecution", "command": command, "cwd": cwd, "conversation_id": "c"})
    if target == "gemini":
        return json.dumps({"hook_event_name": "BeforeTool", "tool_name": "run_shell_command", "tool_input": {"command": command}, "cwd": cwd, "session_id": "s"})
    if target == "copilot":
        return json.dumps({"toolName": "bash", "toolArgs": json.dumps({"command": command}), "cwd": cwd})
    if target == "cline":
        return json.dumps({"hookName": "PreToolUse", "preToolUse": {"toolName": "execute_command", "parameters": {"command": command}}, "workspaceRoots": [cwd]})
    if target == "generic":
        return json.dumps({"command": command, "cwd": cwd})
    raise AssertionError(target)


class TestAdapters(IsolatedCase):
    def run_hook(self, target, command):
        return hook.handle(payload(target, command, self.proj), home=self.sb_home, integration=target)

    def test_every_target_blocks_a_catastrophic_command(self):
        for t in ("claude", "codex", "cursor", "gemini", "copilot", "cline", "generic"):
            with self.subTest(target=t):
                code, out = self.run_hook(t, BAD)
                if t == "generic":
                    self.assertEqual(code, 2)
                elif t == "cursor":
                    self.assertEqual(code, 2)
                    self.assertEqual(json.loads(out)["permission"], "deny")
                elif t == "gemini":
                    self.assertEqual(json.loads(out)["decision"], "deny")
                elif t == "cline":
                    j = json.loads(out)
                    self.assertTrue(j["cancel"])
                    self.assertTrue(j["errorMessage"])
                else:  # claude, codex, copilot use permissionDecision
                    j = json.loads(out)
                    pd = j.get("hookSpecificOutput", j)
                    self.assertEqual(pd["permissionDecision"], "deny")

    def test_benign_command_is_never_blocked(self):
        for t in ("claude", "codex", "cursor", "gemini", "copilot", "cline", "generic"):
            with self.subTest(target=t):
                code, out = self.run_hook(t, OK)
                self.assertEqual(code, 0)
                if t == "cursor":
                    self.assertEqual(json.loads(out)["permission"], "allow")  # explicit allow required
                elif t == "gemini":
                    self.assertEqual(json.loads(out)["decision"], "allow")
                elif t == "cline":
                    self.assertFalse(json.loads(out)["cancel"])
                elif t in ("claude", "codex", "generic"):
                    self.assertNotIn('"deny"', out)
                    self.assertNotIn('"ask"', out)

    def test_ask_maps_to_deny_where_the_protocol_has_no_ask(self):
        for t in ("codex", "cursor", "gemini", "cline"):
            with self.subTest(target=t):
                code, out = self.run_hook(t, ASKY)
                blob = out.lower()
                self.assertTrue('"deny"' in blob or '"cancel": true' in blob or '"cancel":true' in blob, out)

    def test_claude_keeps_ask(self):
        code, out = self.run_hook("claude", ASKY)
        self.assertEqual(json.loads(out)["hookSpecificOutput"]["permissionDecision"], "ask")

    def test_garbage_input_never_means_allow(self):
        # Malformed JSON must never produce an explicit allow, for any adapter.
        for t in ("claude", "codex", "cursor", "gemini", "copilot", "cline", "generic"):
            with self.subTest(target=t):
                code, out = hook.handle("{not json", home=self.sb_home, integration=t)
                compact = out.replace(" ", "")
                self.assertNotIn('"allow"', compact)
                self.assertNotIn('"cancel":false', compact)
                self.assertTrue(code != 0 or out.strip() != "", "silent success on garbage input")

    def test_non_shell_tools_are_ignored(self):
        p = json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Read", "tool_input": {"file_path": "/etc/hostname"}, "cwd": self.proj})
        code, out = hook.handle(p, home=self.sb_home, integration="claude")
        self.assertEqual(code, 0)
        self.assertNotIn("deny", out)

    def test_unknown_integration_is_rejected(self):
        with self.assertRaises(Exception):
            hook.handle("{}", home=self.sb_home, integration="nope")

    def test_audit_records_the_integration(self):
        self.run_hook("gemini", BAD)
        log = os.path.join(self.sb_home, "audit.jsonl")
        self.assertTrue(os.path.exists(log))
        self.assertIn('"integration":"gemini"', open(log).read())


class TestInstallers(IsolatedCase):
    def test_install_uninstall_roundtrip_every_target(self):
        for t in integrations.TARGETS:
            with self.subTest(target=t):
                r, path = integrations.install_target(t, "project", self.proj)
                self.assertEqual(r, "installed")
                self.assertTrue(integrations.is_target_installed(t, "project", self.proj))
                r2, _ = integrations.install_target(t, "project", self.proj)
                self.assertIn(r2, ("already-installed", "installed"))
                if path.endswith(".json"):
                    json.load(open(path))  # still valid JSON
                r3, _ = integrations.uninstall_target(t, "project", self.proj)
                self.assertEqual(r3, "removed")
                self.assertFalse(integrations.is_target_installed(t, "project", self.proj))

    def test_install_is_idempotent_no_duplicate_hooks(self):
        for t in ("cursor", "gemini", "codex", "copilot"):
            with self.subTest(target=t):
                integrations.install_target(t, "project", self.proj)
                path = integrations.path_for(t, "project", self.proj)
                once = open(path).read()
                integrations.install_target(t, "project", self.proj)
                self.assertEqual(open(path).read(), once)
                self.assertGreaterEqual(once.count(integrations.cmd_for(t)), 1)
                integrations.uninstall_target(t, "project", self.proj)

    def test_existing_settings_are_preserved(self):
        path = integrations.path_for("gemini", "project", self.proj)
        os.makedirs(os.path.dirname(path))
        json.dump({"theme": "dark", "mcpServers": {"x": {"command": "y"}}}, open(path, "w"))
        integrations.install_target("gemini", "project", self.proj)
        d = json.load(open(path))
        self.assertEqual(d["theme"], "dark")
        self.assertIn("x", d["mcpServers"])
        integrations.uninstall_target("gemini", "project", self.proj)
        d = json.load(open(path))
        self.assertEqual(d["theme"], "dark")
        self.assertNotIn("kneepad", json.dumps(d))

    def test_foreign_hooks_survive_install_and_uninstall(self):
        path = integrations.path_for("cursor", "project", self.proj)
        os.makedirs(os.path.dirname(path))
        json.dump({"version": 1, "hooks": {"beforeShellExecution": [{"command": "./mine.sh"}]}}, open(path, "w"))
        integrations.install_target("cursor", "project", self.proj)
        integrations.uninstall_target("cursor", "project", self.proj)
        d = json.load(open(path))
        self.assertEqual(d["hooks"]["beforeShellExecution"], [{"command": "./mine.sh"}])

    def test_invalid_json_is_refused_and_left_untouched(self):
        path = integrations.path_for("codex", "project", self.proj)
        os.makedirs(os.path.dirname(path))
        open(path, "w").write("{broken")
        with self.assertRaises(integrations.InstallError):
            integrations.install_target("codex", "project", self.proj)
        self.assertEqual(open(path).read(), "{broken")

    def test_cline_refuses_to_overwrite_a_foreign_hook(self):
        path = integrations.path_for("cline", "project", self.proj)
        os.makedirs(os.path.dirname(path))
        open(path, "w").write("#!/bin/sh\necho mine\n")
        with self.assertRaises(integrations.InstallError):
            integrations.install_target("cline", "project", self.proj)
        self.assertIn("mine", open(path).read())
        r, _ = integrations.uninstall_target("cline", "project", self.proj)
        self.assertEqual(r, "not-installed")
        self.assertTrue(os.path.exists(path))

    def test_cline_script_is_executable(self):
        _, path = integrations.install_target("cline", "project", self.proj)
        self.assertTrue(os.access(path, os.X_OK))


class TestShellWrapperAndApi(IsolatedCase):
    def sh(self, command):
        env = dict(os.environ, PYTHONPATH=SRC, KNEEPAD_REAL_SHELL="/bin/sh")
        return subprocess.run([sys.executable, "-m", "kneepad", "shell", "-c", command], cwd=self.proj, env=env, capture_output=True, text=True, timeout=60)

    def test_wrapper_blocks_with_126(self):
        r = self.sh(BAD)
        self.assertEqual(r.returncode, 126)
        self.assertIn("Kneepad", r.stderr)

    def test_wrapper_runs_safe_commands_and_passes_exit_status(self):
        r = self.sh("echo hello")
        self.assertEqual((r.returncode, r.stdout.strip()), (0, "hello"))
        self.assertEqual(self.sh("exit 7").returncode, 7)

    def test_shell_main_entry_point_passes_dash_c(self):
        env = dict(os.environ, PYTHONPATH=SRC, KNEEPAD_REAL_SHELL="/bin/sh")
        code = "import sys; from kneepad.cli import shell_main; sys.argv=['kneepad-shell','-c','echo ok']; sys.exit(shell_main())"
        r = subprocess.run([sys.executable, "-c", code], cwd=self.proj, env=env, capture_output=True, text=True, timeout=60)
        self.assertEqual((r.returncode, r.stdout.strip()), (0, "ok"))
        code = code.replace("echo ok", BAD)
        r = subprocess.run([sys.executable, "-c", code], cwd=self.proj, env=env, capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 126)

    def test_api_check_and_guard(self):
        self.assertEqual(check_command(OK, cwd=self.proj).action, "allow")
        self.assertEqual(check_command(BAD, cwd=self.proj).action, "deny")
        self.assertEqual(check_write("/etc/passwd", cwd=self.proj).action != "allow", True)
        self.assertIn(check_mcp("shell__run", {"command": BAD}, cwd=self.proj).action, ("deny", "ask"))

        @guard
        def run(command):
            return "ran"

        self.assertEqual(run(OK), "ran")
        with self.assertRaises(KneepadBlocked):
            run(BAD)


if __name__ == "__main__":
    unittest.main()


class TestDoctorAndBadgeWithOtherAgents(IsolatedCase):
    def test_doctor_reports_other_agent_hooks_and_badge_accepts_them(self):
        from kneepad import cli
        integrations.install_target("cursor", "project", self.proj)
        items = cli.run_doctor(self.proj)
        labels = {l: s for s, l, _d in items}
        self.assertIs(labels.get("cursor hook installed"), True)
        self.assertIsNot(labels.get("Claude Code hook installed"), True)
        self.assertFalse(any(s is False for s, l, _d in items if l.endswith("hook installed")))

    def test_doctor_fails_when_no_hook_anywhere(self):
        from kneepad import cli
        items = cli.run_doctor(self.proj)
        self.assertIs(dict((l, s) for s, l, _d in items)["Claude Code hook installed"], False)
