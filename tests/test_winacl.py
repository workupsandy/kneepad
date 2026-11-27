"""Windows ACL checks for the state directory and audit key.

The SDDL parsing and the decision logic run everywhere with icacls replaced by a fake. The last class talks to the real icacls and
only runs on Windows (it replaces the POSIX-mode tests that cannot run there)."""
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from kneepad import winacl  # noqa: E402

ME = "S-1-5-21-111-222-333-1001"
PRIVATE = f"D:PAI(A;OICI;FA;;;{ME})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
USERS_INHERITED = f"D:AI(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)(A;OICIID;0x1200a9;;;BU)(A;OICIID;FA;;;{ME})"
EVERYONE = f"D:PAI(A;;FA;;;{ME})(A;;FR;;;WD)"
OTHER_USER = f"D:PAI(A;;FA;;;{ME})(A;;FA;;;S-1-5-21-111-222-333-1002)"


class Parser(unittest.TestCase):
    def test_aliases_expand_to_sids(self):
        self.assertEqual([a[3] for a in winacl.parse_dacl(PRIVATE)], [ME, "S-1-5-18", "S-1-5-32-544"])

    def test_private_acl_has_no_exposure(self):
        self.assertEqual(winacl.exposed_principals(PRIVATE, ME), [])

    def test_users_group_is_exposure(self):
        self.assertEqual(winacl.exposed_principals(USERS_INHERITED, ME), ["BUILTIN\\Users"])

    def test_everyone_is_exposure(self):
        self.assertEqual(winacl.exposed_principals(EVERYONE, ME), ["Everyone"])

    def test_another_account_is_exposure_by_sid(self):
        self.assertEqual(winacl.exposed_principals(OTHER_USER, ME), ["S-1-5-21-111-222-333-1002"])

    def test_deny_entries_and_empty_rights_are_not_exposure(self):
        self.assertEqual(winacl.exposed_principals(f"D:P(D;;FA;;;WD)(A;;FA;;;{ME})(A;;;;;BU)", ME), [])

    def test_trusted_installer_and_creator_owner_are_fine(self):
        self.assertEqual(winacl.exposed_principals(f"D:P(A;;FA;;;S-1-5-80-956008885-1)(A;;FA;;;CO)(A;;FA;;;{ME})", ME), [])

    def test_sacl_part_is_ignored(self):
        self.assertEqual(winacl.exposed_principals(f"D:P(A;;FA;;;{ME})S:(AU;SA;FA;;;WD)", ME), [])

    def test_garbage_gives_no_entries(self):
        self.assertEqual(winacl.parse_dacl("not sddl"), [])


class FakeIcacls:
    """Stands in for icacls/whoami: keeps one SDDL per path and applies the few switches Kneepad uses."""

    def __init__(self, sddl_by_path, me=ME, fail=False):
        self.acl = dict(sddl_by_path)
        self.me, self.fail, self.calls = me, fail, []

    def __call__(self, args):
        self.calls.append(list(args))
        if self.fail:
            return 1, ""
        if args[0] == "whoami":
            return 0, f'"HOST\\\\user","{self.me}"\r\n'
        path = args[1]
        if "/save" in args:
            out = args[args.index("/save") + 1]
            with open(out, "wb") as fh:
                fh.write(("﻿" + path + "\r\n" + self.acl[path] + "\r\n").encode("utf-16-le"))
            return 0, ""
        if "/inheritance:r" in args:
            self.acl[path] = self.acl[path].replace("ID;", ";").replace("D:AI", "D:PAI")
        if "/grant:r" in args:
            for g in args[args.index("/grant:r") + 1:]:
                sid = g[1:].split(":")[0]
                if f";;;{sid})" not in self.acl[path]:
                    self.acl[path] += f"(A;OICI;FA;;;{sid})"
        for sw in ("/remove:g", "/remove:d"):
            if sw in args:
                sid = args[args.index(sw) + 1][1:]
                import re
                names = [sid] + [a for a, v in winacl._ALIASES.items() if v == sid]  # icacls resolves aliases and SIDs alike
                for n in names:
                    self.acl[path] = re.sub(r"\([^()]*;;;" + re.escape(n) + r"\)", "", self.acl[path])
        return 0, ""


class Decisions(unittest.TestCase):
    def setUp(self):
        winacl._me_cache.clear()

    def tearDown(self):
        winacl._me_cache.clear()

    def test_private_path_is_reported_private(self):
        with mock.patch.object(winacl, "_run", FakeIcacls({"p": PRIVATE})):
            self.assertEqual(winacl.check("p").status, "private")

    def test_exposed_path_names_who(self):
        with mock.patch.object(winacl, "_run", FakeIcacls({"p": USERS_INHERITED})):
            rep = winacl.check("p")
        self.assertEqual((rep.status, rep.exposed), ("exposed", ["BUILTIN\\Users"]))
        self.assertIn("BUILTIN\\Users", rep.detail)

    def test_unknown_when_icacls_fails_and_never_raises(self):
        with mock.patch.object(winacl, "_run", FakeIcacls({"p": PRIVATE}, fail=True)):
            self.assertEqual(winacl.check("p").status, "unknown")
            self.assertIsNone(winacl.tighten_if_exposed("p", True))

    def test_tighten_removes_inherited_users_access(self):
        fake = FakeIcacls({"p": USERS_INHERITED})
        with mock.patch.object(winacl, "_run", fake):
            self.assertTrue(winacl.tighten("p", True))
            self.assertEqual(winacl.check("p").status, "private")
        grant = [c for c in fake.calls if "/grant:r" in c][0]
        self.assertIn(f"*{ME}:(OI)(CI)F", grant)
        self.assertIn("*S-1-5-18:(OI)(CI)F", grant)

    def test_grant_happens_before_inheritance_is_removed(self):
        fake = FakeIcacls({"p": USERS_INHERITED})
        with mock.patch.object(winacl, "_run", fake):
            winacl.tighten("p", False)
        order = [("grant" if "/grant:r" in c else "inherit" if "/inheritance:r" in c else "") for c in fake.calls]
        self.assertLess(order.index("grant"), order.index("inherit"))
        self.assertIn(f"*{ME}:F", [c for c in fake.calls if "/grant:r" in c][0])

    def test_tighten_removes_everyone(self):
        with mock.patch.object(winacl, "_run", FakeIcacls({"p": EVERYONE})):
            self.assertTrue(winacl.tighten("p", False))

    def test_already_private_is_left_alone(self):
        fake = FakeIcacls({"p": PRIVATE})
        with mock.patch.object(winacl, "_run", fake):
            self.assertIsNone(winacl.tighten_if_exposed("p", True))
        self.assertFalse([c for c in fake.calls if "/grant:r" in c or "/inheritance:r" in c])

    def test_unknown_user_means_no_changes(self):
        fake = FakeIcacls({"p": EVERYONE}, me="")
        fake.me = "not-a-sid"
        with mock.patch.object(winacl, "_run", fake):
            self.assertFalse(winacl.tighten("p", True))
        self.assertFalse([c for c in fake.calls if "/inheritance:r" in c])

    def test_utf8_save_file_is_also_understood(self):
        def run(args):
            if args[0] == "whoami":
                return 0, f'"h\\u","{ME}"'
            out = args[args.index("/save") + 1]
            open(out, "wb").write(("p\r\n" + PRIVATE + "\r\n").encode("utf-8"))
            return 0, ""
        with mock.patch.object(winacl, "_run", run):
            self.assertEqual(winacl.check("p").status, "private")


class Wiring(unittest.TestCase):
    def test_new_state_dir_is_checked_on_windows_only_once(self):
        from kneepad import util
        d = os.path.join(tempfile.mkdtemp(), "state")
        with mock.patch.object(util, "is_windows", return_value=True), mock.patch.object(winacl, "tighten_if_exposed") as t:
            util.ensure_private_dir(d)
            util.ensure_private_dir(d)  # existing directory: no icacls on every hook call
        self.assertEqual(t.call_count, 1)

    def test_posix_never_calls_icacls(self):
        from kneepad import util
        d = os.path.join(tempfile.mkdtemp(), "state")
        with mock.patch.object(winacl, "tighten_if_exposed") as t:
            util.ensure_private_dir(d)
        if os.name != "nt":
            t.assert_not_called()

    def test_hook_path_never_shells_out_to_icacls(self):
        from kneepad.audit import AuditLog
        home = tempfile.mkdtemp()
        with mock.patch.object(winacl, "_run") as r:
            log = AuditLog(os.path.join(home, "s"))
            for i in range(3):
                log.append("t", {"i": i})
        if os.name != "nt":
            r.assert_not_called()

    def test_doctor_reports_exposure_on_windows(self):
        from kneepad import cli
        home = tempfile.mkdtemp()
        with mock.patch.object(cli.sys, "platform", "win32"), mock.patch.object(winacl, "check",
                                                                              return_value=winacl.AclReport("exposed", ["Everyone"], "also accessible to Everyone")):
            items = cli.run_doctor(home)
        flat = {i[1]: i for i in items}
        self.assertIs(flat["state directory is private"][0], False)
        self.assertIn("Everyone", flat["state directory is private"][2])


@unittest.skipUnless(sys.platform == "win32", "uses the real icacls")
class RealWindowsAcl(unittest.TestCase):
    """Windows replacements for the POSIX mode-bit tests (test_key_file_is_private and friends)."""

    def setUp(self):
        winacl._me_cache.clear()
        self.root = tempfile.mkdtemp()

    def test_a_directory_made_by_kneepad_is_private(self):
        from kneepad import util
        d = os.path.join(self.root, "state")
        util.ensure_private_dir(d)
        self.assertEqual(winacl.check(d).status, "private", winacl.check(d).detail)

    def test_exposure_is_detected_then_removed(self):
        d = os.path.join(self.root, "open")
        os.makedirs(d)
        subprocess.run(["icacls", d, "/grant", "*S-1-1-0:(OI)(CI)R"], capture_output=True)
        rep = winacl.check(d)
        self.assertEqual(rep.status, "exposed", rep.detail)
        self.assertTrue(winacl.tighten(d, True))
        self.assertEqual(winacl.check(d).status, "private", winacl.check(d).detail)

    def test_the_audit_key_is_private(self):
        from kneepad.audit import AuditLog
        log = AuditLog(os.path.join(self.root, "kh"))
        log.ensure_key()
        self.assertEqual(winacl.check(log.key_path).status, "private", winacl.check(log.key_path).detail)

    def test_an_exposed_key_is_tightened_by_init(self):
        from kneepad import cli
        from kneepad.audit import AuditLog
        home = os.path.join(self.root, "kh2")
        with mock.patch.dict(os.environ, {"KNEEPAD_HOME": home}):
            AuditLog(home).ensure_key()
            subprocess.run(["icacls", os.path.join(home, "key"), "/grant", "*S-1-1-0:R"], capture_output=True)
            self.assertEqual(winacl.check(os.path.join(home, "key")).status, "exposed")
            self.assertEqual(cli.main(["init"]), 0)
            self.assertEqual(winacl.check(os.path.join(home, "key")).status, "private")

    def test_doctor_marks_private_state_ok(self):
        from kneepad import cli
        home = os.path.join(self.root, "kh3")
        with mock.patch.dict(os.environ, {"KNEEPAD_HOME": home}):
            self.assertEqual(cli.main(["init"]), 0)
            flat = {i[1]: i for i in cli.run_doctor(home)}
        self.assertIs(flat["state directory is private"][0], True)
        self.assertIs(flat["audit key is private"][0], True)


if __name__ == "__main__":
    unittest.main()
