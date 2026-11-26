import io
import json
import os
import stat
import threading
import unittest
from contextlib import redirect_stdout, redirect_stderr

from helpers import IsolatedCase, make_repo, run_git

from kneepad import cli, hook, installer
from kneepad.audit import AuditLog
from kneepad.snapshots import SnapshotPlan, SnapshotStore, SnapshotError
from kneepad.badge import make_badge


class TestAudit(IsolatedCase):
    def fill(self, n=5):
        log = AuditLog(self.sb_home)
        for i in range(n):
            log.append("decision", {"i": i, "cmd": f"cmd {i}"})
        return log

    def test_chain_verifies(self):
        log = self.fill(10)
        r = log.verify()
        self.assertTrue(r.ok, r.error)
        self.assertEqual((r.count, r.head_seq, r.hmac_verified), (10, 10, True))

    def test_empty_log_verifies(self):
        self.assertTrue(AuditLog(self.sb_home).verify().ok)

    def test_key_file_is_private(self):
        self.fill(1)
        mode = stat.S_IMODE(os.stat(os.path.join(self.sb_home, "key")).st_mode)
        self.assertEqual(mode & 0o077, 0)
        mode = stat.S_IMODE(os.stat(os.path.join(self.sb_home, "audit.jsonl")).st_mode)
        self.assertEqual(mode & 0o077, 0)

    def _lines(self, log):
        with open(log.path, "rb") as fh:
            return fh.read().split(b"\n")

    def _write(self, log, lines):
        with open(log.path, "wb") as fh:
            fh.write(b"\n".join(lines))

    def test_every_single_byte_flip_is_detected(self):
        log = self.fill(4)
        original = open(log.path, "rb").read()
        undetected = []
        for pos in range(len(original)):
            mutated = bytearray(original)
            mutated[pos] ^= 0x01
            with open(log.path, "wb") as fh:
                fh.write(bytes(mutated))
            if AuditLog(self.sb_home).verify().ok:
                undetected.append(pos)
        with open(log.path, "wb") as fh:
            fh.write(original)
        self.assertEqual(undetected, [], f"{len(undetected)} of {len(original)} byte flips went undetected")

    def test_edit_delete_reorder_duplicate_detected(self):
        log = self.fill(6)
        lines = [l for l in self._lines(log) if l]
        for name, mutated in {
            "delete-middle": lines[:2] + lines[3:],
            "delete-first": lines[1:],
            "reorder": [lines[1], lines[0]] + lines[2:],
            "duplicate": lines[:3] + [lines[2]] + lines[3:],
            "insert-garbage": lines[:2] + [b"{}"] + lines[2:],
            "blank-line": lines[:2] + [b""] + lines[2:],
        }.items():
            self._write(log, mutated)
            if name != "blank-line":
                self.assertFalse(AuditLog(self.sb_home).verify().ok, name)
        self._write(log, [l for l in lines])

    def test_attacker_cannot_recompute_chain_without_key(self):
        from kneepad.audit import canonical, entry_hash
        log = self.fill(3)
        lines = [json.loads(l) for l in self._lines(log) if l]
        lines[1]["data"]["cmd"] = "forged"
        prev = lines[0]["hash"]
        for e in lines[1:]:
            e["prev"] = prev
            body = {k: v for k, v in e.items() if k not in ("hash", "hmac")}
            e["hash"] = entry_hash(body)
            prev = e["hash"]
        self._write(log, [canonical(e).encode() for e in lines] + [b""])
        r = AuditLog(self.sb_home).verify()
        self.assertFalse(r.ok)
        self.assertIn("signature", r.error.lower())

    def test_tail_truncation_needs_anchor(self):
        log = self.fill(5)
        anchor = log.anchor()
        lines = [l for l in self._lines(log) if l]
        self._write(log, lines[:3] + [b""])
        self.assertTrue(AuditLog(self.sb_home).verify().ok)  # documented limitation without an anchor
        self.assertFalse(AuditLog(self.sb_home).verify(anchor=anchor).ok)

    def test_anchor_matches_and_survives_appends(self):
        log = self.fill(3)
        a = log.anchor()
        log.append("decision", {"more": 1})
        self.assertTrue(log.verify(anchor=a).ok)

    def test_corrupt_log_is_rotated_not_lost(self):
        log = self.fill(3)
        with open(log.path, "ab") as fh:
            fh.write(b"this is not json\n")
        log.append("decision", {"after": 1})
        rotated = [n for n in os.listdir(self.sb_home) if n.startswith("audit.jsonl.corrupt")]
        self.assertEqual(len(rotated), 1)
        self.assertTrue(AuditLog(self.sb_home).verify().ok)

    def test_concurrent_appends_keep_chain_valid(self):
        errs = []

        def work(k):
            try:
                lg = AuditLog(self.sb_home)
                for i in range(15):
                    lg.append("decision", {"t": k, "i": i})
            except Exception as exc:  # pragma: no cover
                errs.append(exc)

        threads = [threading.Thread(target=work, args=(k,)) for k in range(6)]
        [t.start() for t in threads]
        [t.join() for t in threads]
        self.assertEqual(errs, [])
        r = AuditLog(self.sb_home).verify()
        self.assertTrue(r.ok, r.error)
        self.assertEqual(r.count, 90)

    def test_concurrent_processes(self):
        import subprocess, sys
        code = ("import sys;sys.path.insert(0,%r);from kneepad.audit import AuditLog\n"
                "l=AuditLog(%r)\nfor i in range(20): l.append('d',{'i':i})") % (os.path.join(os.path.dirname(__file__), "..", "src"), self.sb_home)
        procs = [subprocess.Popen([sys.executable, "-c", code]) for _ in range(4)]
        [p.wait() for p in procs]
        r = AuditLog(self.sb_home).verify()
        self.assertTrue(r.ok, r.error)
        self.assertEqual(r.count, 80)

    def test_secrets_are_redacted_in_hook_log(self):
        hook.handle(json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": self.proj,
                                "tool_input": {"command": "terraform destroy -var token=ghp_abcdefghijklmnopqrstuvwxyz0123456789"}}), self.sb_home)
        raw = open(os.path.join(self.sb_home, "audit.jsonl")).read()
        self.assertNotIn("ghp_abcdefghijklmnopqrstuvwxyz0123456789", raw)


class TestSnapshots(IsolatedCase):
    def test_file_snapshot_and_restore(self):
        p = self.write("d/a.txt", "hello")
        store = SnapshotStore(self.sb_home)
        m = store.create(SnapshotPlan(kind="files", cwd=self.proj, paths=[os.path.dirname(p)]))
        import shutil
        shutil.rmtree(os.path.dirname(p))
        store.restore(m["id"])
        self.assertEqual(open(p).read(), "hello")

    def test_restore_refuses_to_overwrite_without_force(self):
        p = self.write("a.txt", "v1")
        store = SnapshotStore(self.sb_home)
        m = store.create(SnapshotPlan(kind="files", cwd=self.proj, paths=[p]))
        with open(p, "w") as fh:
            fh.write("v2")
        store.restore(m["id"])
        self.assertEqual(open(p).read(), "v2")
        store.restore(m["id"], force=True)
        self.assertEqual(open(p).read(), "v1")

    def test_restore_to_other_dir(self):
        p = self.write("a.txt", "v1")
        store = SnapshotStore(self.sb_home)
        m = store.create(SnapshotPlan(kind="files", cwd=self.proj, paths=[p]))
        out = os.path.join(self.tmp, "out")
        os.makedirs(out)
        store.restore(m["id"], to=out)
        self.assertEqual(open(os.path.join(out, "a.txt")).read(), "v1")

    def test_symlinks_are_not_followed(self):
        secret = self.write("secret.txt", "TOPSECRET", base=self.tmp)
        d = os.path.join(self.proj, "d")
        os.makedirs(d)
        os.symlink(secret, os.path.join(d, "link"))
        store = SnapshotStore(self.sb_home)
        m = store.create(SnapshotPlan(kind="files", cwd=self.proj, paths=[d]))
        for root, _, files in os.walk(os.path.join(self.sb_home, "snapshots", m["id"])):
            for f in files:
                fp = os.path.join(root, f)
                if not os.path.islink(fp) and f != "manifest.json":
                    self.assertNotIn("TOPSECRET", open(fp).read())

    def test_snapshot_dir_is_private(self):
        p = self.write("a.txt")
        SnapshotStore(self.sb_home).create(SnapshotPlan(kind="files", cwd=self.proj, paths=[p]))
        self.assertEqual(stat.S_IMODE(os.stat(os.path.join(self.sb_home, "snapshots")).st_mode) & 0o077, 0)

    def test_failed_snapshot_leaves_nothing(self):
        store = SnapshotStore(self.sb_home)
        with self.assertRaises(SnapshotError):
            store.create(SnapshotPlan(kind="bogus", cwd=self.proj))
        self.assertEqual(store.list(), [])
        self.assertEqual(os.listdir(os.path.join(self.sb_home, "snapshots")), [])

    def test_git_stash_snapshot_recovers_hard_reset(self):
        make_repo(self.proj)
        f = self.write("a.txt", "committed")
        run_git(self.proj, "add", "-A")
        run_git(self.proj, "commit", "-q", "-m", "c")
        with open(f, "w") as fh:
            fh.write("precious uncommitted work")
        new = self.write("new.txt", "staged new")
        run_git(self.proj, "add", "new.txt")
        d = self.decide("git reset --hard")
        store = SnapshotStore(self.sb_home)
        m = store.create(d.plans[0])
        run_git(self.proj, "reset", "--hard")
        self.assertEqual(open(f).read(), "committed")
        store.restore(m["id"], apply=True)
        self.assertEqual(open(f).read(), "precious uncommitted work")
        self.assertEqual(open(new).read(), "staged new")
        # snapshot must not have disturbed the working tree at creation time
        self.assertIn("refs/kneepad/", run_git(self.proj, "for-each-ref"))

    def test_git_stash_snapshot_does_not_change_worktree(self):
        make_repo(self.proj)
        f = self.write("a.txt", "one")
        run_git(self.proj, "add", "-A")
        run_git(self.proj, "commit", "-q", "-m", "c")
        with open(f, "w") as fh:
            fh.write("two")
        before = run_git(self.proj, "status", "--porcelain")
        SnapshotStore(self.sb_home).create(self.decide("git reset --hard").plans[0])
        self.assertEqual(run_git(self.proj, "status", "--porcelain"), before)
        self.assertEqual(run_git(self.proj, "stash", "list"), "")

    def test_git_branch_snapshot_restores_deleted_branch(self):
        make_repo(self.proj)
        self.write("a")
        run_git(self.proj, "add", "-A")
        run_git(self.proj, "commit", "-q", "-m", "c")
        run_git(self.proj, "checkout", "-q", "-b", "feat")
        self.write("b")
        run_git(self.proj, "add", "-A")
        run_git(self.proj, "commit", "-q", "-m", "feat work")
        tip = run_git(self.proj, "rev-parse", "feat")
        run_git(self.proj, "checkout", "-q", "main")
        store = SnapshotStore(self.sb_home)
        m = store.create(self.decide("git branch -D feat").plans[0])
        run_git(self.proj, "branch", "-D", "feat")
        store.restore(m["id"])
        self.assertEqual(run_git(self.proj, "rev-parse", "feat"), tip)

    def test_git_clean_snapshot_restores_untracked(self):
        make_repo(self.proj)
        self.write("t.txt")
        run_git(self.proj, "add", "-A")
        run_git(self.proj, "commit", "-q", "-m", "c")
        u = self.write("scratch/u.txt", "untracked work")
        store = SnapshotStore(self.sb_home)
        m = store.create(self.decide("git clean -fd").plans[0])
        run_git(self.proj, "clean", "-fdq")
        self.assertFalse(os.path.exists(u))
        store.restore(m["id"])
        self.assertEqual(open(u).read(), "untracked work")

    def test_hostile_repo_fsmonitor_is_not_executed(self):
        make_repo(self.proj)
        self.write("a")
        run_git(self.proj, "add", "-A")
        run_git(self.proj, "commit", "-q", "-m", "c")
        marker = os.path.join(self.tmp, "PWNED")
        hook_script = self.write("evil.sh", f"#!/bin/sh\ntouch {marker}\n", base=self.tmp)
        os.chmod(hook_script, 0o755)
        run_git(self.proj, "config", "core.fsmonitor", hook_script)
        self.write("a", "modified")
        d = self.decide("git reset --hard")
        SnapshotStore(self.sb_home).create(d.plans[0])
        self.decide("git clean -fd")
        self.assertFalse(os.path.exists(marker), "core.fsmonitor from the repo was executed")

    def test_prune(self):
        p = self.write("a.txt")
        store = SnapshotStore(self.sb_home)
        for _ in range(3):
            store.create(SnapshotPlan(kind="files", cwd=self.proj, paths=[p]))
        self.assertEqual(len(store.list()), 3)
        store.prune(older_than_days=0.0)
        self.assertEqual(store.list(), [])

    def test_path_traversal_in_id_is_rejected(self):
        store = SnapshotStore(self.sb_home)
        self.assertIsNone(store.get("../../etc"))
        with self.assertRaises(SnapshotError):
            store.restore("../x")


class TestHook(IsolatedCase):
    def call(self, tool, tin, **extra):
        payload = {"hook_event_name": "PreToolUse", "tool_name": tool, "tool_input": tin, "cwd": self.proj, "session_id": "s"}
        payload.update(extra)
        return hook.handle(json.dumps(payload), self.sb_home)

    def test_deny_json_shape(self):
        code, out = self.call("Bash", {"command": "rm -rf /"})
        self.assertEqual(code, 0)
        o = json.loads(out)["hookSpecificOutput"]
        self.assertEqual((o["hookEventName"], o["permissionDecision"]), ("PreToolUse", "deny"))
        self.assertTrue(o["permissionDecisionReason"])

    def test_ask_json_shape(self):
        code, out = self.call("Bash", {"command": "terraform destroy"})
        self.assertEqual(json.loads(out)["hookSpecificOutput"]["permissionDecision"], "ask")

    def test_never_emits_allow(self):
        for tool, tin in [("Bash", {"command": "ls"}), ("Bash", {"command": "rm tmp-nope"}), ("Read", {"file_path": "x"}),
                          ("Write", {"file_path": f"{self.proj}/a.py"}), ("mcp__x__y", {"a": 1}), ("Bash", {"command": ""})]:
            code, out = self.call(tool, tin)
            self.assertEqual((code, out), (0, ""), (tool, tin))

    def test_allow_with_snapshot_is_silent_but_snapshots(self):
        p = self.write("note.txt", "keep me")
        code, out = self.call("Bash", {"command": "rm note.txt"})
        self.assertEqual((code, out), (0, ""))
        self.assertEqual(len(SnapshotStore(self.sb_home).list()), 1)

    def test_garbage_input_fails_to_ask(self):
        for raw in ["", "not json", "[]", "null", "123", '{"tool_name": "Bash"', "\x00\x01"]:
            code, out = hook.handle(raw, self.sb_home)
            self.assertEqual(code, 0, raw)
            self.assertEqual(json.loads(out)["hookSpecificOutput"]["permissionDecision"], "ask", raw)

    def test_wrong_shapes_do_not_crash(self):
        for payload in [{"tool_name": "Bash", "tool_input": None}, {"tool_name": "Bash", "tool_input": {"command": 5}},
                        {"tool_name": "Bash", "tool_input": {"command": ["rm", "-rf", "/"]}}, {"tool_name": 5, "tool_input": {}},
                        {"tool_name": "Write", "tool_input": {}}, {"tool_name": "Bash", "tool_input": {}, "cwd": "/does/not/exist"}]:
            code, out = hook.handle(json.dumps(payload), self.sb_home)
            self.assertEqual(code, 0, payload)

    def test_non_pretooluse_events_ignored(self):
        self.assertEqual(self.call("Bash", {"command": "rm -rf /"}, hook_event_name="PostToolUse"), (0, ""))

    def test_write_tools(self):
        code, out = self.call("Write", {"file_path": os.path.join(self.home, ".bashrc"), "content": "x"})
        self.assertEqual(json.loads(out)["hookSpecificOutput"]["permissionDecision"], "ask")
        code, out = self.call("Edit", {"file_path": f"{self.proj}/.env", "old_string": "a", "new_string": "b"})
        self.assertEqual(json.loads(out)["hookSpecificOutput"]["permissionDecision"], "ask")
        self.assertEqual(self.call("Write", {"file_path": f"{self.proj}/ok.py", "content": ""}), (0, ""))

    def test_mcp_tools(self):
        code, out = self.call("mcp__postgres__query", {"sql": "DROP TABLE users"})
        self.assertIn(json.loads(out)["hookSpecificOutput"]["permissionDecision"], ("ask", "deny"))

    def test_decisions_are_logged_and_chain_verifies(self):
        self.call("Bash", {"command": "rm -rf /"})
        self.call("Bash", {"command": "terraform destroy"})
        self.call("Bash", {"command": "ls"})  # silent allows are not logged
        log = AuditLog(self.sb_home)
        self.assertEqual(log.verify().count, 2)
        self.assertEqual(log.tail(1)[0]["data"]["action"], "ask")

    def test_monitor_mode_never_blocks(self):
        with open(os.path.join(self.proj, ".kneepad.toml"), "w") as fh:
            fh.write('mode = "monitor"\n')
        code, out = self.call("Bash", {"command": "rm -rf /"})
        self.assertEqual(json.loads(out)["hookSpecificOutput"]["permissionDecision"], "deny", "project config must not weaken protection")
        os.makedirs(self.sb_home, exist_ok=True)
        with open(os.path.join(self.sb_home, "config.toml"), "w") as fh:
            fh.write('mode = "monitor"\n')
        self.assertEqual(self.call("Bash", {"command": "rm -rf /"}), (0, ""))
        self.assertEqual(AuditLog(self.sb_home).verify().count, 2)

    def test_project_config_cannot_relax(self):
        with open(os.path.join(self.proj, ".kneepad.toml"), "w") as fh:
            fh.write('mode = "monitor"\ndisable_rules = ["tf-destroy"]\nallow_patterns = [".*"]\nallow_write_paths = ["*"]\n')
        code, out = self.call("Bash", {"command": "terraform destroy"})
        self.assertEqual(json.loads(out)["hookSpecificOutput"]["permissionDecision"], "ask")

    def test_project_config_can_tighten(self):
        with open(os.path.join(self.proj, ".kneepad.toml"), "w") as fh:
            fh.write('protected_paths = ["secrets/*"]\nprod_markers = ["live"]\n')
        code, out = self.call("Write", {"file_path": f"{self.proj}/secrets/k"})
        self.assertEqual(json.loads(out)["hookSpecificOutput"]["permissionDecision"], "ask")
        code, out = self.call("Bash", {"command": "kubectl delete ns live"})
        self.assertEqual(json.loads(out)["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_broken_config_still_protects(self):
        with open(os.path.join(self.proj, ".kneepad.toml"), "w") as fh:
            fh.write("this is [not valid toml")
        code, out = self.call("Bash", {"command": "rm -rf /"})
        self.assertEqual(json.loads(out)["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_internal_error_asks(self):
        from unittest import mock
        with mock.patch("kneepad.hook.Analyzer", side_effect=RuntimeError("boom")):
            code, out = self.call("Bash", {"command": "ls"})
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["hookSpecificOutput"]["permissionDecision"], "ask")

    def test_unwritable_home_does_not_change_decision(self):
        blocker = os.path.join(self.tmp, "afile")
        open(blocker, "w").close()
        code, out = hook.handle(json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": self.proj,
                                            "tool_input": {"command": "rm -rf /"}}), os.path.join(blocker, "sub"))
        self.assertEqual(json.loads(out)["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_performance_budget(self):
        import time
        t = time.time()
        for _ in range(20):
            self.call("Bash", {"command": "git status && npm test && docker ps | grep web"})
        self.assertLess((time.time() - t) / 20, 0.25)


class TestInstallerAndCli(IsolatedCase):
    def setUp(self):
        super().setUp()
        orig = os.getcwd()
        self.addCleanup(os.chdir, orig)
        os.chdir(self.proj)

    def run_cli(self, *argv, stdin=None):
        out, err = io.StringIO(), io.StringIO()
        from unittest import mock
        with redirect_stdout(out), redirect_stderr(err):
            if stdin is not None:
                with mock.patch("sys.stdin", io.StringIO(stdin)):
                    code = cli.main(list(argv))
            else:
                code = cli.main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def test_install_is_idempotent_and_preserves_other_settings(self):
        path = os.path.join(self.tmp, "settings.json")
        with open(path, "w") as fh:
            json.dump({"model": "x", "hooks": {"PreToolUse": [{"matcher": "Read", "hooks": [{"type": "command", "command": "other"}]}],
                                                "Stop": [{"hooks": [{"type": "command", "command": "bye"}]}]}}, fh)
        installer.install(path, "kneepad hook claude")
        installer.install(path, "kneepad hook claude")
        data = json.load(open(path))
        self.assertEqual(data["model"], "x")
        self.assertEqual(len(data["hooks"]["Stop"]), 1)
        ours = [g for g in data["hooks"]["PreToolUse"] if any("kneepad" in h["command"] for h in g["hooks"])]
        self.assertEqual(len(ours), 1)
        self.assertTrue(installer.is_installed(path))
        self.assertTrue(os.path.exists(path + ".kneepad-bak"))
        installer.uninstall(path)
        data = json.load(open(path))
        self.assertFalse(installer.is_installed(path))
        self.assertEqual(data["hooks"]["PreToolUse"][0]["hooks"][0]["command"], "other")
        self.assertEqual(data["hooks"]["Stop"][0]["hooks"][0]["command"], "bye")

    def test_install_refuses_invalid_json(self):
        path = os.path.join(self.tmp, "settings.json")
        with open(path, "w") as fh:
            fh.write("{ not json")
        with self.assertRaises(installer.InstallError):
            installer.install(path, "x")
        self.assertEqual(open(path).read(), "{ not json")

    def test_install_creates_missing_file(self):
        path = os.path.join(self.tmp, "new", "settings.json")
        installer.install(path, "kneepad hook claude")
        self.assertTrue(installer.is_installed(path))
        self.assertEqual(json.load(open(path))["hooks"]["PreToolUse"][0]["matcher"], installer.MATCHER)

    def test_matcher_covers_tools(self):
        import re
        for t in ("Bash", "Write", "Edit", "MultiEdit", "NotebookEdit", "mcp__db__query"):
            self.assertTrue(re.fullmatch(installer.MATCHER, t), t)
        self.assertFalse(re.fullmatch(installer.MATCHER, "Read"))

    def test_check_exit_codes(self):
        self.assertEqual(self.run_cli("check", "ls", "--cwd", self.proj)[0], 0)
        self.assertEqual(self.run_cli("check", "terraform destroy", "--cwd", self.proj)[0], 10)
        self.assertEqual(self.run_cli("check", "rm -rf /", "--cwd", self.proj)[0], 20)
        code, out, _ = self.run_cli("check", "rm -rf /", "--cwd", self.proj, "--json")
        self.assertEqual(json.loads(out)["action"], "deny")

    def test_check_has_no_side_effects(self):
        self.write("a.txt")
        self.run_cli("check", "rm a.txt", "--cwd", self.proj)
        self.assertTrue(os.path.exists(os.path.join(self.proj, "a.txt")))
        self.assertEqual(SnapshotStore(self.sb_home).list(), [])

    def test_init_verify_log_doctor(self):
        os.chdir(self.proj)
        code, out, err = self.run_cli("init", "--claude-code", "--scope", "project")
        self.assertEqual(code, 0, err)
        self.assertTrue(installer.is_installed(os.path.join(self.proj, ".claude", "settings.json")))
        hook.handle(json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": self.proj,
                                "tool_input": {"command": "terraform destroy"}}), self.sb_home)
        self.assertEqual(self.run_cli("verify")[0], 0)
        self.assertIn("terraform", self.run_cli("log")[1].lower())
        self.assertEqual(self.run_cli("doctor")[0], 0)
        self.assertEqual(self.run_cli("uninstall", "--scope", "project")[0], 0)

    def test_verify_fails_on_tamper(self):
        hook.handle(json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": self.proj,
                                "tool_input": {"command": "terraform destroy"}}), self.sb_home)
        p = os.path.join(self.sb_home, "audit.jsonl")
        s = open(p).read().replace("terraform", "terrafoxm")
        open(p, "w").write(s)
        self.assertNotEqual(self.run_cli("verify")[0], 0)

    def test_badge_is_gated(self):
        os.chdir(self.proj)
        out = os.path.join(self.proj, "b.svg")
        code, _, err = self.run_cli("badge", "--out", out)
        self.assertNotEqual(code, 0)
        self.assertFalse(os.path.exists(out))
        self.run_cli("init", "--claude-code", "--scope", "project")
        code, _, err = self.run_cli("badge", "--out", out)
        self.assertEqual(code, 0, err)
        svg = open(out).read()
        self.assertTrue(svg.startswith("<svg"))
        self.assertIn("kneepad", svg)
        # tampered log withdraws the badge
        hook.handle(json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": self.proj,
                                "tool_input": {"command": "terraform destroy"}}), self.sb_home)
        p = os.path.join(self.sb_home, "audit.jsonl")
        content = open(p).read().replace("terraform", "terrafoxm")
        with open(p, "w") as fh:
            fh.write(content)
        os.remove(out)
        self.assertNotEqual(self.run_cli("badge", "--out", out)[0], 0)
        self.assertEqual(self.run_cli("badge", "--out", out, "--force")[0], 0)

    def test_badge_svg_is_well_formed(self):
        import xml.dom.minidom
        xml.dom.minidom.parseString(make_badge())
        xml.dom.minidom.parseString(make_badge(label="a&b", message="<x>"))

    def test_rules_commands(self):
        from kneepad.rules import __file__ as _rf
        db = os.path.join(os.path.dirname(_rf), "data", "footguns.toml")
        self.assertEqual(self.run_cli("rules", "validate", db)[0], 0)
        code, out, _ = self.run_cli("rules", "list")
        self.assertIn("tf-destroy", out)
        self.assertEqual(self.run_cli("rules", "show", "tf-destroy")[0], 0)
        self.assertNotEqual(self.run_cli("rules", "show", "nope-nope")[0], 0)

    def test_run_blocks_and_executes(self):
        code, _, err = self.run_cli("run", "rm", "-rf", "/")
        self.assertNotEqual(code, 0)
        marker = os.path.join(self.proj, "ran.txt")
        code, _, _ = self.run_cli("run", "touch", marker)
        self.assertEqual(code, 0)
        self.assertTrue(os.path.exists(marker))

    def test_snapshots_cli(self):
        p = self.write("a.txt", "v1")
        SnapshotStore(self.sb_home).create(SnapshotPlan(kind="files", cwd=self.proj, paths=[p]))
        code, out, _ = self.run_cli("snapshots", "list")
        self.assertEqual(code, 0)
        sid = SnapshotStore(self.sb_home).list()[0]["id"]
        self.assertIn(sid, out)
        os.remove(p)
        self.assertEqual(self.run_cli("snapshots", "restore", sid)[0], 0)
        self.assertEqual(open(p).read(), "v1")


if __name__ == "__main__":
    unittest.main()
