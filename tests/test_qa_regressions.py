"""Regression tests for defects found by the end-to-end QA harness (tools/qa_e2e.py)."""

import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from kneepad import api, cli, integrations  # noqa: E402
from kneepad.audit import AuditLog  # noqa: E402
from kneepad.config import Config  # noqa: E402
from kneepad.engine import Analyzer  # noqa: E402


def run_cli(*argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        rc = cli.main(list(argv))
    return rc, out.getvalue(), err.getvalue()


class TestShellCommandArg(unittest.TestCase):
    def test_forms(self):
        f = cli._shell_command_arg
        self.assertEqual(f(["-c", "x"]), "x")
        self.assertEqual(f(["-lc", "x"]), "x")
        self.assertEqual(f(["-ec", "x"]), "x")
        self.assertEqual(f(["-euc", "x"]), "x")
        self.assertEqual(f(["-xc", "x"]), "x")
        self.assertEqual(f(["-l", "-c", "x"]), "x")
        self.assertEqual(f(["--norc", "-c", "x"]), "x")
        self.assertEqual(f(["-o", "pipefail", "-c", "x"]), "x")
        self.assertEqual(f(["-c", "x", "arg0"]), "x")
        self.assertIsNone(f(["script.sh", "-c", "x"]))
        self.assertIsNone(f(["-c"]))
        self.assertIsNone(f([]))
        self.assertIsNone(f(["-l"]))


class TestRunShellAuditAndSnapshots(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.mkdtemp()
        self.work = tempfile.mkdtemp()
        self.old = (os.environ.get("KNEEPAD_HOME"), os.getcwd())
        os.environ["KNEEPAD_HOME"] = self.home
        os.chdir(self.work)

    def tearDown(self):
        os.chdir(self.old[1])
        if self.old[0] is None:
            del os.environ["KNEEPAD_HOME"]
        else:
            os.environ["KNEEPAD_HOME"] = self.old[0]

    def entries(self):
        return AuditLog(self.home).read_all()

    def test_blocked_commands_are_logged(self):
        for argv in (["run", "--", "rm", "-rf", "/"], ["shell", "-c", "rm -rf /"]):
            rc, _, _ = run_cli(*argv)
            self.assertEqual(rc, 126)
        tools = [(e["data"]["tool"], e["data"]["refused"]) for e in self.entries()]
        self.assertEqual(tools, [("run", True), ("shell", True)])

    def test_shell_takes_snapshot_before_allowed_delete(self):
        open("gone.txt", "w").write("precious")
        from kneepad.snapshots import SnapshotStore
        before = len(SnapshotStore(self.home).list())
        cmd = "exit 0"  # the vetting step is what is under test, not the shell
        d = Analyzer(config=Config(), cwd=self.work).analyze_shell("rm gone.txt")
        self.assertTrue(d.plans, "precondition: this delete plans a snapshot")
        rc = cli._vet_command("rm gone.txt", "shell", interactive_ask=False)
        self.assertEqual(rc, 0)
        self.assertEqual(len(SnapshotStore(self.home).list()), before + 1)
        last = self.entries()[-1]["data"]
        self.assertEqual(last["tool"], "shell")
        self.assertEqual(len(last["snapshots"]), 1)

    def test_log_failure_is_reported(self):
        from unittest import mock
        with mock.patch.object(AuditLog, "append", side_effect=OSError("disk full")):
            err = io.StringIO()
            with redirect_stderr(err):
                rc = cli._vet_command("echo hi", "run", interactive_ask=True)
        self.assertEqual(rc, 0)
        self.assertIn("could not write the audit log", err.getvalue())


class TestRun(unittest.TestCase):
    def test_missing_program_is_clean(self):
        rc, out, err = run_cli("run", "--", "kneepad-no-such-program-xyz")
        self.assertEqual(rc, 127)
        self.assertNotIn("Traceback", err)
        self.assertIn("not found", err)

    def test_help(self):
        rc, out, err = run_cli("run", "--help")
        self.assertEqual(rc, 0)
        self.assertIn("usage: kneepad run", out)


class TestLog(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.log = AuditLog(self.d)
        for i in range(5):
            self.log.append("decision", {"i": i})

    def test_tail_zero_and_positive(self):
        self.assertEqual(self.log.tail(0), [])
        self.assertEqual(len(self.log.tail(2)), 2)
        self.assertEqual(len(self.log.tail(50)), 5)

    def test_cli_negative(self):
        os.environ["KNEEPAD_HOME"] = self.d
        try:
            rc, out, err = run_cli("log", "-n", "-1")
            self.assertEqual(rc, 2)
            rc, out, err = run_cli("log", "-n", "0")
            self.assertEqual((rc, out.strip()), (0, ""))
        finally:
            del os.environ["KNEEPAD_HOME"]


class TestOwnership(unittest.TestCase):
    def test_ours(self):
        o = integrations._ours
        self.assertTrue(o({"command": "/usr/local/bin/kneepad hook claude"}))
        self.assertTrue(o({"command": '"C:/Python/Scripts/kneepad.exe" hook claude'}))
        self.assertTrue(o({"command": "'/opt/py/bin/python' -m kneepad hook claude"}))
        self.assertTrue(o({"bash": "kneepad hook copilot"}))
        self.assertFalse(o({"command": "my-kneepad-notify hook start"}))
        self.assertFalse(o({"command": "echo kneepad is great; git hook run"}))
        self.assertFalse(o({"command": "kneepadx hook claude"}))
        self.assertFalse(o("kneepad hook claude"))


class TestClaudeInstallerOwnership(unittest.TestCase):
    def test_unrelated_hook_survives_uninstall(self):
        from kneepad import installer
        d = tempfile.mkdtemp()
        path = os.path.join(d, "settings.json")
        cmd = "/usr/bin/kneepad hook claude"
        installer.install(path, cmd)
        data = json.load(open(path))
        data["hooks"]["PreToolUse"].append({"matcher": "Bash", "hooks": [{"type": "command", "command": "my-kneepad-notify hook start"}]})
        json.dump(data, open(path, "w"))
        installer.uninstall(path)
        left = json.load(open(path))["hooks"]["PreToolUse"]
        cmds = [h["command"] for g in left for h in g["hooks"]]
        self.assertEqual(cmds, ["my-kneepad-notify hook start"])


class TestProtectedDirectory(unittest.TestCase):
    def test_dir_pattern_covers_children(self):
        cwd = tempfile.mkdtemp()
        cfg = Config()
        cfg.protected_paths = ["secrets"]
        a = Analyzer(config=cfg, cwd=cwd)
        self.assertIsNotNone(a._protected_reason(os.path.join(cwd, "secrets", "a.txt")))
        self.assertIsNotNone(a._protected_reason(os.path.join(cwd, "secrets", "deep", "b")))
        self.assertIsNone(a._protected_reason(os.path.join(cwd, "secretsX", "a.txt")))
        self.assertIsNone(a._protected_reason(os.path.join(cwd, "src", "a.txt")))


class TestGuardMisuse(unittest.TestCase):
    def test_string_instead_of_function(self):
        with self.assertRaises(TypeError):
            api.guard("rm -rf ~")


class TestStatePathIsFile(unittest.TestCase):
    def test_init_fails_cleanly(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "state")
        open(p, "w").write("x")
        os.environ["KNEEPAD_HOME"] = p
        try:
            rc, out, err = run_cli("init")
            self.assertEqual(rc, 1)
            self.assertIn("kneepad: error", err)
        finally:
            del os.environ["KNEEPAD_HOME"]


class TestBadgeUnwritable(unittest.TestCase):
    def test_clean_error(self):
        d = tempfile.mkdtemp()
        os.environ["KNEEPAD_HOME"] = d
        try:
            rc, out, err = run_cli("badge", "--force", "--out", os.path.join(d, "no", "dir", "b.svg"))
            self.assertEqual(rc, 1)
            self.assertNotIn("Traceback", err)
        finally:
            del os.environ["KNEEPAD_HOME"]


class TestLastLinePortable(unittest.TestCase):
    def test_no_pread(self):
        import inspect
        from kneepad import audit
        self.assertNotIn("os.pread(", inspect.getsource(audit))


if __name__ == "__main__":
    unittest.main()
