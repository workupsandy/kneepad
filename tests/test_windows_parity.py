"""Windows behaviour that can be checked on any platform: path classification with 8.3 short names, Git Bash style commands,
config path patterns on Windows paths, and copy-based audit rotation (WinError 32 on a real Windows runner)."""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from kneepad import audit, winshell  # noqa: E402
from kneepad.config import Config  # noqa: E402
from kneepad.engine import Analyzer  # noqa: E402

HOME = r"C:\Users\runneradmin"
SHORT_CWD = r"C:\Users\RUNNER~1\AppData\Local\Temp\tmpab\sr"


def _az(cwd, **kw):
    cfg = Config()
    for k, v in kw.items():
        setattr(cfg, k, v)
    return Analyzer(config=cfg, cwd=cwd, home=HOME)


class ShortNames(unittest.TestCase):
    def test_unshort_maps_short_profile_to_home(self):
        self.assertEqual(winshell._unshort(r"c:\users\runner~1\appdata", HOME.lower()), r"c:\users\runneradmin\appdata")

    def test_unshort_ignores_a_different_user(self):
        p = r"c:\users\bob~1\appdata"
        self.assertEqual(winshell._unshort(p, HOME.lower()), p)

    def test_unshort_ignores_non_users_paths(self):
        p = r"c:\progra~1\x"
        self.assertEqual(winshell._unshort(p, HOME.lower()), p)

    def test_everyday_rm_in_short_name_cwd_is_allowed(self):
        for c in ("rm file.txt", "rm -f build.log", "rm -rf node_modules", "rm -rf __pycache__", "rm -rf dist build"):
            d = _az(SHORT_CWD).analyze_shell(c)
            self.assertEqual(d.action, "allow", (c, d.findings))

    def test_cwd_outside_home_is_still_a_normal_project_dir(self):
        d = _az(r"C:\work\proj").analyze_shell("rm -rf node_modules")
        self.assertEqual(d.action, "allow", d.findings)

    def test_system_cwd_keeps_protection(self):
        d = _az(r"C:\Windows\System32").analyze_shell("rm somefile.dll")
        self.assertNotEqual(d.action, "allow")

    def test_other_users_profile_is_still_system(self):
        d = _az(r"C:\work\proj").analyze_shell(r"rm -rf C:\Users\bob\Documents")
        self.assertNotEqual(d.action, "allow")


class GitBashStyle(unittest.TestCase):
    def test_posix_system_paths_are_stopped(self):
        for c in ("unlink /etc/passwd", "rm -rf /var/lib", "rm -rf /usr/local"):
            self.assertNotEqual(_az(r"C:\Users\runneradmin\proj").analyze_shell(c).action, "allow", c)

    def test_shell_startup_files_are_protected(self):
        for c in ("echo x >> ~/.bashrc", "echo x >> ~/.bash_profile", "echo x >> ~/.zshrc"):
            self.assertNotEqual(_az(r"C:\Users\runneradmin\proj").analyze_shell(c).action, "allow", c)

    def test_git_hooks_workflows_and_env_are_protected(self):
        for path in (r"C:\Users\runneradmin\proj\.git\hooks\pre-commit", r"C:\Users\runneradmin\proj\.github\workflows\ci.yml",
                     r"C:\Users\runneradmin\proj\.env"):
            self.assertNotEqual(_az(r"C:\Users\runneradmin\proj").analyze_write_path(path).action, "allow", path)

    def test_env_example_is_not_protected(self):
        d = _az(r"C:\Users\runneradmin\proj").analyze_write_path(r"C:\Users\runneradmin\proj\.env.example")
        self.assertEqual(d.action, "allow", d.findings)


class ConfigPatternsOnWindows(unittest.TestCase):
    def test_protected_pattern_relative_to_cwd(self):
        az = _az(r"C:\Users\runneradmin\proj", protected_paths=["secrets"])
        self.assertNotEqual(az.analyze_write_path(r"C:\Users\runneradmin\proj\secrets\a.txt").action, "allow")
        self.assertNotEqual(az.analyze_write_path(r"c:/users/RUNNERADMIN/proj/SECRETS/a.txt").action, "allow")

    def test_protected_pattern_does_not_overreach(self):
        az = _az(r"C:\Users\runneradmin\proj", protected_paths=["secrets"])
        self.assertEqual(az.analyze_write_path(r"C:\Users\runneradmin\proj\src\a.txt").action, "allow")

    def test_glob_pattern(self):
        az = _az(r"C:\Users\runneradmin\proj", protected_paths=["*.pem"])
        self.assertNotEqual(az.analyze_write_path(r"C:\Users\runneradmin\proj\id.pem").action, "allow")

    def test_allow_write_paths_wins_over_builtin(self):
        az = _az(r"C:\Users\runneradmin\proj", allow_write_paths=[".env"])
        self.assertEqual(az.analyze_write_path(r"C:\Users\runneradmin\proj\.env").action, "allow")


class CopyRotation(unittest.TestCase):
    """Run the whole torn-tail scenario through the copy path that Windows uses."""

    def setUp(self):
        self.old = audit._COPY_ROTATION
        audit._COPY_ROTATION = True
        self.home = tempfile.mkdtemp()
        self.log = audit.AuditLog(self.home)

    def tearDown(self):
        audit._COPY_ROTATION = self.old

    def test_torn_tail_is_set_aside_and_chain_restarts(self):
        for i in range(3):
            self.log.append("t", {"i": i})
        with open(self.log.path, "ab") as fh:
            fh.write(b'{"v":1,"seq":4,"ts"')  # crash mid-write
        before = open(self.log.path, "rb").read()
        e = self.log.append("after", {})
        self.assertEqual(e["seq"], 1)
        self.assertEqual(e["data"].get("note"), "previous log was corrupt and was set aside")
        kept = [f for f in os.listdir(self.home) if ".corrupt-" in f]
        self.assertEqual(len(kept), 1)
        self.assertEqual(open(os.path.join(self.home, kept[0]), "rb").read(), before)
        self.assertTrue(self.log.verify().ok)
        for line in open(self.log.path, "rb").read().splitlines():
            json.loads(line)

    def test_two_rotations_do_not_overwrite_each_other(self):
        for _ in range(2):
            self.log.append("t", {})
            with open(self.log.path, "ab") as fh:
                fh.write(b"garbage-without-newline")
            self.log.append("after", {})
        self.assertEqual(len([f for f in os.listdir(self.home) if ".corrupt-" in f]), 2)


if __name__ == "__main__":
    unittest.main()


class RunQuoting(unittest.TestCase):
    """`kneepad run -- rm -rf C:\\Users\\me\\proj` was analysed through subprocess.list2cmdline, which leaves backslashes bare;
    the shell parser read them as escapes, mangled the path and ALLOWED the command (RUN-003 on Windows CI)."""

    def test_backslash_path_is_denied_when_quoted_like_run_does(self):
        import shlex
        home = r"C:\Users\RUNNER~1\AppData\Local\Temp\tmpa\sbhome"
        az = Analyzer(config=Config(), cwd=home + r"\..\work", home=home)
        d = az.analyze_shell(shlex.join(["rm", "-rf", home]))
        self.assertEqual(d.action, "deny", d.findings)

    def test_run_builds_its_analysed_text_with_posix_quoting(self):
        import inspect
        from kneepad import cli
        src = inspect.getsource(cli)
        self.assertNotIn("list2cmdline(argv)", src)

    def test_tilde_uses_the_analysers_own_home(self):
        az = _az(r"C:\Users\runneradmin\proj")
        self.assertNotEqual(az.analyze_write_path("~/.npmrc").action, "allow")
        self.assertNotEqual(az.analyze_write_path("~\\.ssh\\id_rsa").action, "allow")


class SettingsSharingRetry(unittest.TestCase):
    """On Windows a second `init` could not replace or read settings.json while the first held it open (Errno 13)."""

    def setUp(self):
        from kneepad import installer
        self.inst = installer
        self.old = installer._RETRY_SHARING
        installer._RETRY_SHARING = True
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, ".claude", "settings.json")

    def tearDown(self):
        self.inst._RETRY_SHARING = self.old

    def test_replace_is_retried_until_the_other_process_lets_go(self):
        from unittest import mock
        real = os.replace
        calls = {"n": 0}

        def flaky(a, b):
            calls["n"] += 1
            if calls["n"] <= 3:
                raise PermissionError(13, "Permission denied")
            return real(a, b)

        with mock.patch.object(self.inst.os, "replace", flaky):
            self.assertEqual(self.inst.install(self.path, "kneepad hook claude"), "installed")
        self.assertGreaterEqual(calls["n"], 4)
        self.assertTrue(self.inst.is_installed(self.path))

    def test_a_permanent_denial_still_raises(self):
        from unittest import mock
        with mock.patch.object(self.inst.os, "replace", side_effect=PermissionError(13, "Permission denied")), \
                mock.patch.object(self.inst.time, "sleep"):
            with self.assertRaises(PermissionError):
                self.inst.install(self.path, "kneepad hook claude")

    def test_posix_does_not_retry(self):
        from unittest import mock
        self.inst._RETRY_SHARING = False
        n = {"c": 0}

        def deny(a, b):
            n["c"] += 1
            raise PermissionError(13, "Permission denied")

        with mock.patch.object(self.inst.os, "replace", deny):
            with self.assertRaises(PermissionError):
                self.inst.install(self.path, "kneepad hook claude")
        self.assertEqual(n["c"], 1)
