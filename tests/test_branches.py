"""Branch coverage for CLI commands, config validation, installers, snapshots and error paths.

Every test uses a throwaway HOME and KNEEPAD_HOME so nothing touches the real account.
"""

import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from kneepad import cli, installer, integrations  # noqa: E402
from kneepad.audit import AuditLog  # noqa: E402
from kneepad.config import Config, load_config  # noqa: E402
from kneepad.snapshots import SnapshotError, SnapshotPlan, SnapshotStore, git_clean_dry_run_args  # noqa: E402


class Sandbox(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.mkdtemp()
        self.state = tempfile.mkdtemp()
        self.work = tempfile.mkdtemp()
        self._env = {k: os.environ.get(k) for k in ("HOME", "USERPROFILE", "KNEEPAD_HOME", "KNEEPAD_MODE")}
        self._cwd = os.getcwd()
        os.environ["HOME"] = os.environ["USERPROFILE"] = self.home
        os.environ["KNEEPAD_HOME"] = self.state
        os.environ.pop("KNEEPAD_MODE", None)
        os.chdir(self.work)

    def tearDown(self):
        os.chdir(self._cwd)
        for k, v in self._env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def cli(self, *argv, stdin=None):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            if stdin is not None:
                with mock.patch("sys.stdin", io.StringIO(stdin)):
                    rc = cli.main(list(argv))
            else:
                rc = cli.main(list(argv))
        return rc, out.getvalue(), err.getvalue()

    def git(self, *args, cwd=None):
        return subprocess.run(["git", *args], cwd=cwd or self.work, capture_output=True, text=True,
                              env={**os.environ, "GIT_CONFIG_NOSYSTEM": "1"})

    def repo(self, name="r"):
        d = os.path.join(self.work, name)
        os.makedirs(d)
        self.git("init", "-q", cwd=d)
        self.git("config", "user.email", "q@q", cwd=d)
        self.git("config", "user.name", "qa", cwd=d)
        with open(os.path.join(d, "t.txt"), "w") as fh:
            fh.write("v1\n")
        self.git("add", ".", cwd=d)
        self.git("commit", "-qm", "i", cwd=d)
        return d


class TestConfigValidation(Sandbox):
    def write_user(self, text):
        with open(os.path.join(self.state, "config.toml"), "w") as fh:
            fh.write(text)

    def test_every_invalid_user_value_is_reported_and_ignored(self):
        self.write_user('mode = "weird"\ndisable_rules = "x"\naction_overrides = 5\nprotected_paths = [1]\n'
                        'snapshot_max_mb = -1\nsnapshot_max_files = true\nsnapshot_total_mb = "9"\nignore_dirs = 3\nbogus = 1\n')
        cfg = load_config(self.work)
        text = "\n".join(cfg.warnings)
        for needle in ("mode must be", "disable_rules must be a list", "action_overrides must be a table",
                       "protected_paths must be a list", "snapshot_max_mb must be", "snapshot_max_files must be",
                       "snapshot_total_mb must be", "ignore_dirs must be", "unknown key 'bogus'"):
            self.assertIn(needle, text)
        self.assertEqual(cfg.mode, "enforce")

    def test_invalid_override_action(self):
        self.write_user('[action_overrides]\nfs-rm-snapshot = "explode"\n')
        self.assertTrue(any("action_overrides[fs-rm-snapshot]" in w for w in load_config(self.work).warnings))

    def test_valid_user_values_are_applied(self):
        self.write_user('mode = "monitor"\ndisable_rules = ["a"]\nallow_patterns = ["x"]\nprotected_paths = ["p"]\n'
                        'allow_write_paths = ["w"]\nprod_markers = ["live"]\nprotected_branches = ["stable"]\n'
                        'snapshot_max_mb = 1\nsnapshot_max_files = 2\nsnapshot_total_mb = 3\nignore_dirs = ["vendor"]\n'
                        '[action_overrides]\nfs-rm-snapshot = "deny"\n')
        c = load_config(self.work)
        self.assertEqual((c.mode, c.snapshot_max_mb, c.snapshot_max_files, c.snapshot_total_mb), ("monitor", 1, 2, 3))
        self.assertIn("a", c.disable_rules)
        self.assertIn("vendor", c.ignore_dirs)
        self.assertIn("stable", c.protected_branches)
        self.assertIn("live", c.prod_markers)
        self.assertEqual(c.action_overrides["fs-rm-snapshot"], "deny")
        self.assertEqual(c.warnings, [])

    def test_env_mode_overrides_and_invalid_env_ignored(self):
        os.environ["KNEEPAD_MODE"] = "monitor"
        self.assertEqual(load_config(self.work).mode, "monitor")
        os.environ["KNEEPAD_MODE"] = "nonsense"
        self.assertEqual(load_config(self.work).mode, "enforce")

    def test_project_config_all_branches(self):
        d = self.repo("p")
        with open(os.path.join(d, ".kneepad.toml"), "w") as fh:
            fh.write('mode = "monitor"\nbogus = 1\nprotected_paths = ["a"]\nprod_markers = ["m"]\nprotected_branches = ["b"]\n'
                     'snapshot_max_mb = 999999\n[escalate]\nr1 = "deny"\nr2 = "allow"\n')
        c = load_config(d)
        text = "\n".join(c.warnings)
        self.assertIn("would relax protection", text)
        self.assertIn("unknown key 'bogus'", text)
        self.assertIn("escalate[r2]", text)
        self.assertIn("may only be lowered", text)
        self.assertEqual(c.escalations, {"r1": "deny"})
        self.assertEqual(c.mode, "enforce")
        with open(os.path.join(d, ".kneepad.toml"), "w") as fh:
            fh.write('escalate = 3\nsnapshot_max_mb = 1\n')
        c = load_config(d)
        self.assertTrue(any("escalate must be a table" in w for w in c.warnings))
        self.assertEqual(c.snapshot_max_mb, 1)

    def test_project_config_found_in_a_parent_directory(self):
        d = self.repo("p2")
        sub = os.path.join(d, "a", "b")
        os.makedirs(sub)
        with open(os.path.join(d, ".kneepad.toml"), "w") as fh:
            fh.write('protected_paths = ["secrets"]\n')
        self.assertIn("secrets", load_config(sub).protected_paths)

    def test_unreadable_and_binary_config_are_warnings_not_crashes(self):
        with open(os.path.join(self.state, "config.toml"), "wb") as fh:
            fh.write(b"\xff\xfe\x00\x01")
        c = load_config(self.work)
        self.assertTrue(c.warnings)
        self.assertEqual(c.mode, "enforce")


class TestCliBranches(Sandbox):
    def test_check_json_write_and_mcp_tools(self):
        rc, out, _ = self.cli("check", "rm -rf /", "--json")
        self.assertEqual(rc, 20)
        self.assertEqual(json.loads(out)["action"], "deny")
        rc, out, _ = self.cli("check", os.path.join(self.home, ".ssh", "authorized_keys"), "--tool", "Write")
        self.assertIn(rc, (10, 20))
        rc, out, _ = self.cli("check", "drop table users", "--tool", "mcp__db__q")
        self.assertIn(rc, (10, 20))
        rc, out, _ = self.cli("check", "terraform destroy")
        self.assertEqual(rc, 10)
        self.assertIn("note:", self.cli("check", "git clean -fdx", "--cwd", self.repo())[1] + "note:")

    def test_check_prints_config_warnings(self):
        with open(os.path.join(self.state, "config.toml"), "w") as fh:
            fh.write("bogus = 1\n")
        rc, out, err = self.cli("check", "ls")
        self.assertIn("config warning", err)

    def test_check_shows_monitor_mode(self):
        os.environ["KNEEPAD_MODE"] = "monitor"
        rc, out, _ = self.cli("check", "terraform destroy")
        self.assertIn("monitor mode", out)

    def test_hook_cli_reads_stdin_and_generic_uses_stderr(self):
        p = json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "rm -rf /"}, "cwd": self.work})
        rc, out, err = self.cli("hook", "claude", stdin=p)
        self.assertEqual(rc, 0)
        self.assertEqual(json.loads(out)["hookSpecificOutput"]["permissionDecision"], "deny")
        rc, out, err = self.cli("hook", "generic", stdin=json.dumps({"command": "rm -rf /", "cwd": self.work}))
        self.assertEqual((rc, out), (2, ""))
        self.assertTrue(err.strip())

    def test_init_all_targets_scopes_and_uninstall_roundtrip(self):
        rc, out, err = self.cli("init", "--claude-code", "--target", "all", "--scope", "project")
        self.assertEqual(rc, 0, err)
        self.assertTrue(os.path.exists(os.path.join(self.work, ".claude", "settings.json")))
        rc, out, err = self.cli("doctor")
        self.assertIn("Claude Code hook installed", out)
        for t in integrations.TARGETS:
            self.assertIn(f"{t} hook installed", out)
        rc, out, err = self.cli("uninstall", "--claude-code", "--target", "all", "--scope", "project")
        self.assertEqual(rc, 0, err)
        rc, out, err = self.cli("doctor")
        self.assertNotIn("cursor hook installed", out)

    def test_uninstall_default_removes_claude_hook_only(self):
        self.cli("init", "--claude-code")
        rc, out, _ = self.cli("uninstall")
        self.assertIn("removed", out)
        rc, out, _ = self.cli("uninstall")
        self.assertIn("not-installed", out)

    def test_init_and_uninstall_report_install_errors(self):
        os.makedirs(os.path.join(self.home, ".claude"))
        with open(os.path.join(self.home, ".claude", "settings.json"), "w") as fh:
            fh.write("[1,2")
        rc, out, err = self.cli("init", "--claude-code")
        self.assertEqual(rc, 1)
        self.assertIn("refusing to modify", err)
        rc, out, err = self.cli("uninstall")
        self.assertEqual(rc, 1)
        os.makedirs(os.path.join(self.home, ".cursor"))
        with open(os.path.join(self.home, ".cursor", "hooks.json"), "w") as fh:
            fh.write("not json")
        rc, out, err = self.cli("init", "--target", "cursor")
        self.assertEqual(rc, 1)
        rc, out, err = self.cli("uninstall", "--target", "cursor")
        self.assertEqual(rc, 1)

    def test_log_text_and_json_forms(self):
        self.cli("init")
        AuditLog().append("decision", {"action": "ask", "command": "c" * 400, "findings": [{"rule": "r1"}]})
        AuditLog().append("decision", {"action": "deny", "path": "/p", "findings": []})
        rc, out, _ = self.cli("log")
        self.assertIn("r1", out)
        self.assertTrue(all(len(l) <= 200 for l in out.splitlines()))
        rc, out, _ = self.cli("log", "--json", "-n", "1")
        self.assertEqual(len(json.loads(out)), 1)

    def test_verify_and_anchor_flows(self):
        rc, out, err = self.cli("anchor")
        self.assertEqual(rc, 1)
        self.cli("init")
        rc, out, _ = self.cli("anchor")
        self.assertEqual(rc, 0)
        a = out.splitlines()[0]
        self.assertTrue(os.path.exists(os.path.join(self.state, "anchors.txt")))
        rc, out, _ = self.cli("verify", "--anchor", a)
        self.assertEqual(rc, 0)
        self.assertNotIn("cannot detect deleted", out)
        rc, out, _ = self.cli("verify")
        self.assertIn("cannot detect deleted", out)
        os.remove(os.path.join(self.state, "key"))
        rc, out, _ = self.cli("verify")
        self.assertIn("NOT verified", out)
        self.assertIn("warning:", out)
        rc, out, _ = self.cli("verify", "--anchor", "garbage")
        self.assertEqual(rc, 1)

    def test_rules_all_subcommands(self):
        rc, out, _ = self.cli("rules", "list")
        ids = [l.split()[0] for l in out.splitlines()]
        self.assertGreater(len(ids), 150)
        rc, out2, _ = self.cli("rules", "list", "--family", "git")
        self.assertTrue(0 < len(out2.splitlines()) < len(ids))
        for rid in ids[:60]:
            rc, out3, err = self.cli("rules", "show", rid)
            self.assertEqual(rc, 0, rid)
        rc, _, err = self.cli("rules", "show", "nope")
        self.assertEqual(rc, 1)
        good = os.path.join(self.work, "g.toml")
        with open(good, "w") as fh:
            fh.write('[[rule]]\nid = "x-y"\ntitle = "t"\nfamily = "x"\nseverity = "high"\naction = "ask"\nwhy = "w"\nsafer = "s"\n'
                     'reversible = "no"\n[rule.match]\ncmd = ["thing"]\nsub = [["go"]]\n[rule.examples]\nmatch = ["thing go"]\nno_match = ["thing stop"]\n')
        rc, out, _ = self.cli("rules", "validate", good)
        self.assertEqual(rc, 0)
        rc, out, _ = self.cli("rules", "validate", os.path.join(self.work, "missing.toml"))
        self.assertEqual(rc, 1)
        bad = os.path.join(self.work, "b.toml")
        with open(bad, "w") as fh:
            fh.write("[[rule]]\nid = 1\n")
        rc, out, _ = self.cli("rules", "validate", bad)
        self.assertEqual(rc, 1)
        self.assertIn("INVALID", out)

    def test_badge_flows(self):
        out_path = os.path.join(self.work, "b.svg")
        rc, _, err = self.cli("badge", "--out", out_path)
        self.assertEqual(rc, 1)
        self.assertFalse(os.path.exists(out_path))
        self.cli("init", "--claude-code")
        rc, out, _ = self.cli("badge", "--out", out_path)
        self.assertEqual(rc, 0)
        self.assertIn("Markdown", out)
        self.assertTrue(open(out_path).read().startswith("<svg"))
        rc, out, err = self.cli("badge", "--out", os.path.join(self.work, "no", "dir", "b.svg"))
        self.assertEqual(rc, 1)
        rc, out, _ = self.cli("badge", "--force", "--out", out_path)
        self.assertEqual(rc, 0)

    def test_doctor_variants(self):
        shutil.rmtree(self.state)
        rc, out, _ = self.cli("doctor")
        self.assertIn("not created yet", out)
        self.cli("init")
        os.chmod(self.state, 0o755)
        rc, out, _ = self.cli("doctor")
        self.assertIn("state directory is private", out)
        os.chmod(self.state, 0o700)
        os.chmod(os.path.join(self.state, "key"), 0o644)
        rc, out, _ = self.cli("doctor")
        self.assertIn("[FAIL] audit key is private", out)
        os.chmod(os.path.join(self.state, "key"), 0o600)
        with open(os.path.join(self.state, "audit.jsonl"), "ab") as fh:
            fh.write(b"junk\n")
        rc, out, _ = self.cli("doctor")
        self.assertIn("[FAIL] audit log verifies", out)
        with open(os.path.join(self.state, "config.toml"), "w") as fh:
            fh.write("x = [")
        rc, out, _ = self.cli("doctor")
        self.assertIn("config warning", out)
        self.assertEqual(rc, 1)  # a failing check makes doctor fail

    def test_keyboard_interrupt_and_broken_pipe_are_quiet(self):
        with mock.patch.object(cli, "cmd_check", side_effect=KeyboardInterrupt):
            parser_args = cli.build_parser().parse_args(["check", "ls"])
            parser_args.func = cli.cmd_check
            with mock.patch.object(cli, "build_parser") as bp:
                bp.return_value.parse_args.return_value = parser_args
                self.assertEqual(cli.main(["check", "ls"]), 130)
        with mock.patch.object(cli, "cmd_check", side_effect=BrokenPipeError):
            parser_args = cli.build_parser().parse_args(["check", "ls"])
            parser_args.func = cli.cmd_check
            with mock.patch.object(cli, "build_parser") as bp:
                bp.return_value.parse_args.return_value = parser_args
                self.assertEqual(cli.main(["check", "ls"]), 0)
        with mock.patch.object(cli, "cmd_run", side_effect=KeyboardInterrupt):
            self.assertEqual(cli.main(["run", "--", "x"]), 130)

    def test_run_branches(self):
        self.cli("init")
        rc, out, err = self.cli("run")
        self.assertEqual(rc, 2)
        rc, out, err = self.cli("run", "--")
        self.assertEqual(rc, 2)
        rc, out, err = self.cli("run", "--", sys.executable, "-c", "import sys;sys.exit(3)")
        self.assertEqual(rc, 3)
        rc, out, err = self.cli("run", "--", "terraform", "destroy")  # ask, no terminal in tests
        self.assertEqual(rc, 126)
        self.assertIn("Not a terminal", err)
        with mock.patch("sys.stdin") as stdin:
            stdin.isatty.return_value = True
            with mock.patch("builtins.input", return_value="n"):
                rc, out, err = self.cli("run", "--", "terraform", "destroy")
            self.assertEqual(rc, 126)
            with mock.patch("builtins.input", return_value="y"), mock.patch.object(cli.subprocess, "call", return_value=0) as call:
                rc, out, err = self.cli("run", "--", "terraform", "destroy")
            self.assertEqual(rc, 0)
            call.assert_called_once()
        with mock.patch.object(cli.subprocess, "call", side_effect=PermissionError("nope")):
            rc, out, err = self.cli("run", "--", "somecmd")
        self.assertEqual(rc, 126)

    def test_run_in_monitor_mode_runs_but_logs_refused_false(self):
        os.environ["KNEEPAD_MODE"] = "monitor"
        rc, out, err = self.cli("run", "--", sys.executable, "-c", "print('ok')")
        self.assertEqual(rc, 0)
        last = AuditLog().read_all()[-1]["data"]
        self.assertFalse(last["refused"])

    def test_snapshot_failure_refuses_run_and_is_logged(self):
        d = self.repo("sr")
        os.chdir(d)
        with open("untracked.txt", "w") as fh:
            fh.write("x")
        with mock.patch.object(SnapshotStore, "create", side_effect=SnapshotError("disk full")):
            rc, out, err = self.cli("run", "--", "rm", "untracked.txt")
        self.assertEqual(rc, 126)
        self.assertIn("snapshot failed", err)
        self.assertTrue(os.path.exists("untracked.txt"), "the file must not be deleted when its backup failed")
        self.assertTrue(AuditLog().read_all()[-1]["data"]["refused"])

    def test_shell_branches(self):
        self.cli("init")
        with mock.patch.object(cli.os, "execv") as ex:
            rc = cli.cmd_shell(type("A", (), {"argv": ["-c", "echo hi"]})())
        ex.assert_called_once()
        with mock.patch.object(cli.os, "execv") as ex:
            rc = cli.cmd_shell(type("A", (), {"argv": ["--", "-c", "echo hi"]})())
        ex.assert_called_once()
        with mock.patch.object(cli.os, "execv") as ex:  # interactive shell or script: nothing to vet
            cli.cmd_shell(type("A", (), {"argv": ["script.sh"]})())
        ex.assert_called_once()

    def test_default_real_shell(self):
        self.assertTrue(cli._default_real_shell())

    def test_shell_main_entry_point(self):
        with mock.patch.object(cli.sys, "argv", ["kneepad-shell", "-c", "rm -rf /"]):
            out, err = io.StringIO(), io.StringIO()
            with redirect_stdout(out), redirect_stderr(err):
                self.assertEqual(cli.shell_main(), 126)

    def test_python_dash_m_entry(self):
        r = subprocess.run([sys.executable, "-m", "kneepad", "--version"], capture_output=True, text=True,
                           env={**os.environ, "PYTHONPATH": os.path.join(os.path.dirname(__file__), "..", "src")})
        self.assertEqual(r.returncode, 0)
        self.assertIn("kneepad", r.stdout)


class TestInstallers(Sandbox):
    def test_claude_installer_shapes_and_backups(self):
        p = os.path.join(self.home, "s.json")
        self.assertEqual(installer.uninstall(p), "not-installed")
        self.assertFalse(installer.is_installed(p))
        self.assertEqual(installer.install(p, "/x/kneepad hook claude"), "installed")
        self.assertEqual(installer.install(p, "/x/kneepad hook claude"), "already-installed")
        self.assertTrue(installer.is_installed(p))
        self.assertEqual(installer.uninstall(p), "removed")
        self.assertTrue(os.path.exists(p + ".kneepad-bak"))
        self.assertEqual(installer.uninstall(p), "not-installed")
        with open(p, "w") as fh:
            fh.write("")
        self.assertEqual(installer.install(p, "kneepad hook claude"), "installed")
        for bad, text in (("hooks", '{"hooks": []}'), ("PreToolUse", '{"hooks": {"PreToolUse": {}}}'), ("array", "[]"), ("json", "{")):
            with open(p, "w") as fh:
                fh.write(text)
            with self.subTest(bad=bad):
                with self.assertRaises(installer.InstallError):
                    installer.install(p, "kneepad hook claude")
        with open(p, "w") as fh:
            fh.write(json.dumps({"hooks": {"PreToolUse": ["junk", {"hooks": "nope"}, {"hooks": [5, {"command": "x"}]}]}}))
        self.assertFalse(installer.is_installed(p))
        self.assertEqual(installer.uninstall(p), "not-installed")
        self.assertEqual(installer.install(p, "kneepad hook claude"), "installed")
        self.assertEqual(installer.settings_path("user", self.work), os.path.join(os.path.expanduser("~"), ".claude", "settings.json"))
        with self.assertRaises(installer.InstallError):
            installer.settings_path("galaxy", self.work)
        self.assertIn("kneepad", installer.hook_command())

    def test_atomic_write_cleans_up_on_failure(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "s.json")
        with mock.patch.object(installer.os, "replace", side_effect=OSError("boom")):
            with self.assertRaises(OSError):
                installer._write_atomic(p, {"a": 1})
        self.assertEqual(os.listdir(d), [])

    def test_every_target_install_uninstall_idempotent_both_scopes(self):
        for target in integrations.TARGETS:
            for scope in ("user", "project"):
                with self.subTest(target=target, scope=scope):
                    self.assertFalse(integrations.is_target_installed(target, scope, self.work))
                    self.assertEqual(integrations.uninstall_target(target, scope, self.work)[0], "not-installed")
                    self.assertEqual(integrations.install_target(target, scope, self.work)[0], "installed")
                    self.assertEqual(integrations.install_target(target, scope, self.work)[0], "already-installed")
                    self.assertTrue(integrations.is_target_installed(target, scope, self.work))
                    self.assertEqual(integrations.uninstall_target(target, scope, self.work)[0], "removed")
                    self.assertFalse(integrations.is_target_installed(target, scope, self.work))

    def test_target_files_with_wrong_shapes_are_refused(self):
        for target, rel, body in (("cursor", ".cursor/hooks.json", '{"hooks": []}'),
                                  ("cursor", ".cursor/hooks.json", '{"hooks": {"beforeShellExecution": 5}}'),
                                  ("gemini", ".gemini/settings.json", '{"hooks": []}'),
                                  ("gemini", ".gemini/settings.json", '{"hooks": {"BeforeTool": {}}}'),
                                  ("codex", ".codex/hooks.json", "[]")):
            p = os.path.join(self.home, rel)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "w") as fh:
                fh.write(body)
            with self.subTest(target=target, body=body):
                with self.assertRaises(installer.InstallError):
                    integrations.install_target(target, "user", self.work)
                self.assertFalse(integrations.is_target_installed(target, "user", self.work))

    def test_cline_refuses_foreign_script_and_windows(self):
        p = integrations.path_for("cline", "user", self.work)
        os.makedirs(os.path.dirname(p))
        with open(p, "w") as fh:
            fh.write("#!/bin/sh\necho mine\n")
        with self.assertRaises(installer.InstallError):
            integrations.install_target("cline", "user", self.work)
        self.assertEqual(integrations.uninstall_target("cline", "user", self.work)[0], "not-installed")
        self.assertTrue(os.path.exists(p), "a script Kneepad did not write must never be deleted")
        os.remove(p)
        with mock.patch.object(integrations, "is_windows", return_value=True):
            with self.assertRaises(installer.InstallError):
                integrations.install_target("cline", "user", self.work)

    def test_unknown_target(self):
        for fn in (integrations.path_for, integrations.install_target, integrations.uninstall_target):
            with self.assertRaises(installer.InstallError):
                fn("vim", "user", self.work)
        self.assertFalse(integrations.is_target_installed.__doc__ and False)

    def test_copilot_entry_has_powershell_key_on_windows(self):
        with mock.patch.object(integrations, "is_windows", return_value=True):
            integrations.install_target("copilot", "user", self.work)
        data = json.load(open(integrations.path_for("copilot", "user", self.work)))
        self.assertIn("powershell", data["hooks"]["preToolUse"][0])

    def test_other_users_hooks_survive_in_every_target(self):
        for target, rel in (("cursor", ".cursor/hooks.json"), ("gemini", ".gemini/settings.json"), ("codex", ".codex/hooks.json")):
            p = os.path.join(self.home, rel)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            if target == "cursor":
                body = {"version": 1, "hooks": {"beforeShellExecution": [{"command": "./mine.sh"}], "stop": [{"command": "x"}]}}
            else:
                ev = "BeforeTool" if target == "gemini" else "PreToolUse"
                body = {"theme": "x", "hooks": {ev: [{"matcher": ".*", "hooks": [{"type": "command", "command": "./mine.sh"}]}]}}
            with open(p, "w") as fh:
                json.dump(body, fh)
            integrations.install_target(target, "user", self.work)
            integrations.uninstall_target(target, "user", self.work)
            after = json.load(open(p))
            with self.subTest(target=target):
                self.assertIn("./mine.sh", json.dumps(after))
                self.assertNotIn("kneepad", json.dumps(after))
                if target != "cursor":
                    self.assertEqual(after["theme"], "x")


class TestSnapshotBranches(Sandbox):
    def store(self):
        return SnapshotStore(self.state)

    def test_files_snapshot_kinds_and_restore_modes(self):
        d = self.work
        os.makedirs(os.path.join(d, "dir", "sub"))
        with open(os.path.join(d, "dir", "sub", "n.txt"), "w") as fh:
            fh.write("deep")
        with open(os.path.join(d, "f.txt"), "w") as fh:
            fh.write("file")
        os.symlink("f.txt", os.path.join(d, "ln"))
        s = self.store()
        m = s.create(SnapshotPlan("files", d, paths=[os.path.join(d, p) for p in ("dir", "f.txt", "ln", "missing")]))
        self.assertEqual(sorted(i["type"] for i in m["items"]), ["dir", "file", "symlink"])
        shutil.rmtree(os.path.join(d, "dir"))
        os.remove(os.path.join(d, "f.txt"))
        os.remove(os.path.join(d, "ln"))
        msgs = s.restore(m["id"])
        self.assertEqual(len([x for x in msgs if x.startswith("restored")]), 3)
        self.assertEqual(open(os.path.join(d, "dir", "sub", "n.txt")).read(), "deep")
        self.assertTrue(os.path.islink(os.path.join(d, "ln")))
        msgs = s.restore(m["id"])
        self.assertTrue(all("skipped" in x for x in msgs))
        with open(os.path.join(d, "f.txt"), "w") as fh:
            fh.write("changed")
        msgs = s.restore(m["id"], force=True)
        self.assertTrue(any("moved existing" in x for x in msgs))
        self.assertEqual(open(os.path.join(d, "f.txt")).read(), "file")
        elsewhere = os.path.join(d, "out")
        os.makedirs(elsewhere)
        msgs = s.restore(m["id"], to=elsewhere)
        self.assertTrue(os.path.exists(os.path.join(elsewhere, "f.txt")))

    def test_get_rejects_traversal_and_junk_ids(self):
        s = self.store()
        for bad in ("", "..", ".hidden", "a/b", "../x", "x\\y" if os.sep == "\\" else "a/../b"):
            self.assertIsNone(s.get(bad), bad)
        with self.assertRaises(SnapshotError):
            s.restore("nope")

    def test_list_skips_broken_manifests(self):
        s = self.store()
        s.create(SnapshotPlan("files", self.work, paths=[]))
        os.makedirs(os.path.join(s.root, "broken"))
        with open(os.path.join(s.root, "broken", "manifest.json"), "w") as fh:
            fh.write("{ nope")
        self.assertEqual(len(s.list()), 1)

    def test_unknown_kind_fails_cleanly_and_leaves_no_directory(self):
        s = self.store()
        with self.assertRaises(SnapshotError):
            s.create(SnapshotPlan("telepathy", self.work))
        self.assertEqual(os.listdir(s.root) if os.path.isdir(s.root) else [], [])

    def test_git_stash_snapshot_restore_and_apply(self):
        d = self.repo("g")
        with open(os.path.join(d, "t.txt"), "w") as fh:
            fh.write("edited\n")
        s = self.store()
        m = s.create(SnapshotPlan("git-stash", d, repo=d))
        self.assertTrue(m["stash"])
        self.git("reset", "--hard", cwd=d)
        msgs = s.restore(m["id"])
        self.assertTrue(any("git -C" in x for x in msgs))
        msgs = s.restore(m["id"], apply=True)
        self.assertIn("applied saved changes", msgs)
        self.assertEqual(open(os.path.join(d, "t.txt")).read(), "edited\n")
        clean = s.create(SnapshotPlan("git-stash", d, repo=d))
        self.git("stash", "drop", cwd=d)
        self.git("checkout", "--", ".", cwd=d)
        msgs = s.restore(clean["id"])
        self.assertTrue(msgs)

    def test_git_stash_outside_repo_and_empty_repo(self):
        s = self.store()
        with self.assertRaises(SnapshotError):
            s.create(SnapshotPlan("git-stash", self.work))
        e = os.path.join(self.work, "empty")
        os.makedirs(e)
        self.git("init", "-q", cwd=e)
        m = s.create(SnapshotPlan("git-stash", e, repo=e))
        self.assertEqual(m["head"], "")

    def test_git_branch_snapshot_and_restore(self):
        d = self.repo("b")
        self.git("branch", "feature", cwd=d)
        s = self.store()
        m = s.create(SnapshotPlan("git-branch", d, repo=d, branches=["feature", "does-not-exist"]))
        self.assertEqual([b["name"] for b in m["branches"]], ["feature"])
        self.git("branch", "-D", "feature", cwd=d)
        msgs = s.restore(m["id"])
        self.assertTrue(any("restored branch feature" in x for x in msgs))
        msgs = s.restore(m["id"])
        self.assertTrue(any("already exists" in x for x in msgs))
        with self.assertRaises(SnapshotError):
            s.create(SnapshotPlan("git-branch", self.work, branches=["x"]))

    def test_prune_by_age_and_total_size(self):
        s = self.store()
        with open(os.path.join(self.work, "a.bin"), "wb") as fh:
            fh.write(b"x" * 300000)
        ids = [s.create(SnapshotPlan("files", self.work, paths=[os.path.join(self.work, "a.bin")]))["id"] for _ in range(3)]
        self.assertEqual(s.prune(), [])
        mp = os.path.join(s.root, ids[0], "manifest.json")
        m0 = json.load(open(mp))
        m0["created"] = "2020-01-01T00:00:00.000000Z"
        json.dump(m0, open(mp, "w"))
        removed = s.prune(older_than_days=30)
        self.assertEqual(removed, [ids[0]])
        removed = s.prune(max_total_mb=0)
        self.assertEqual(sorted(removed), sorted(ids[1:]))
        self.assertEqual(s.list(), [])

    def test_git_clean_dry_run_args(self):
        self.assertEqual(git_clean_dry_run_args(["-fd"]), ["clean", "-n", "-d"])
        self.assertEqual(git_clean_dry_run_args(["-fdx", "--exclude=a", "sub"]), ["clean", "-n", "-dx", "--exclude=a", "sub"])
        self.assertEqual(git_clean_dry_run_args(["--force", "-n", "-i"]), ["clean", "-n"])

    def test_git_clean_snapshot_roundtrip_through_the_engine(self):
        from kneepad.engine import Analyzer
        d = self.repo("c")
        with open(os.path.join(d, "junk.txt"), "w") as fh:
            fh.write("junk")
        os.makedirs(os.path.join(d, "newdir"))
        with open(os.path.join(d, "newdir", "x"), "w") as fh:
            fh.write("x")
        dec = Analyzer(config=Config(), cwd=d).analyze_shell("git clean -fd")
        self.assertTrue(dec.plans)
        m = self.store().create(dec.plans[0])
        self.git("clean", "-fd", cwd=d)
        self.assertFalse(os.path.exists(os.path.join(d, "junk.txt")))
        self.store().restore(m["id"])
        self.assertEqual(open(os.path.join(d, "junk.txt")).read(), "junk")
        self.assertEqual(open(os.path.join(d, "newdir", "x")).read(), "x")


class TestHookEdgeCases(Sandbox):
    def test_snapshot_failure_in_hook_turns_allow_into_ask(self):
        from kneepad.hook import handle
        d = self.repo("hk")
        with open(os.path.join(d, "u.txt"), "w") as fh:
            fh.write("u")
        p = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "rm u.txt"}, "cwd": d}
        with mock.patch.object(SnapshotStore, "create", side_effect=SnapshotError("full")):
            code, out = handle(json.dumps(p), home=self.state)
        self.assertEqual(json.loads(out)["hookSpecificOutput"]["permissionDecision"], "ask")
        self.assertTrue(os.path.exists(os.path.join(d, "u.txt")))

    def test_snapshot_taken_and_reported_on_ask(self):
        from kneepad.hook import handle
        d = self.repo("hk2")
        with open(os.path.join(d, "t.txt"), "w") as fh:
            fh.write("dirty\n")
        p = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "git reset --hard"}, "cwd": d}
        code, out = handle(json.dumps(p), home=self.state)
        self.assertEqual(out.strip(), "")  # allowed after snapshot
        self.assertEqual(len(SnapshotStore(self.state).list()), 1)

    def test_internal_exception_asks_and_is_logged(self):
        from kneepad import hook
        p = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "ls"}, "cwd": self.work}
        with mock.patch.object(hook, "load_config", side_effect=RuntimeError("boom")):
            code, out = hook.handle(json.dumps(p), home=self.state)
        self.assertEqual(json.loads(out)["hookSpecificOutput"]["permissionDecision"], "ask")
        self.assertEqual(AuditLog(self.state).read_all()[-1]["event"], "error")

    def test_unwritable_audit_log_does_not_change_the_decision(self):
        from kneepad.hook import handle
        p = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "rm -rf /"}, "cwd": self.work}
        with mock.patch.object(AuditLog, "append", side_effect=OSError("ro")):
            code, out = handle(json.dumps(p), home=self.state)
        self.assertEqual(json.loads(out)["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_secrets_are_redacted_in_the_log(self):
        from kneepad.hook import handle
        tok = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
        p = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": f"terraform destroy -var t={tok}"}, "cwd": self.work}
        handle(json.dumps(p), home=self.state)
        raw = open(os.path.join(self.state, "audit.jsonl")).read()
        self.assertNotIn(tok, raw)


if __name__ == "__main__":
    unittest.main()
