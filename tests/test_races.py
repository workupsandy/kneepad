"""Race conditions: several real processes hit the same state at once."""

import glob
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest

SRC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src")
sys.path.insert(0, SRC)

from kneepad.audit import AuditLog  # noqa: E402


def spawn(code, env_extra, n):
    env = dict(os.environ)
    env.update(env_extra)
    env["PYTHONPATH"] = SRC + os.pathsep + env.get("PYTHONPATH", "")
    return [subprocess.Popen([sys.executable, "-c", code], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)
            for _ in range(n)]


def wait_all(procs, timeout=120):
    out = []
    for p in procs:
        o, e = p.communicate(timeout=timeout)
        out.append((p.returncode, o, e))
    return out


def lines(path):
    try:
        with open(path, "rb") as fh:
            return [l for l in fh if l.strip()]
    except FileNotFoundError:
        return []


class TestAuditRaces(unittest.TestCase):
    def test_key_creation_yields_one_key(self):
        home = tempfile.mkdtemp()
        code = "from kneepad.audit import AuditLog;import os;print(AuditLog(os.environ['KH']).ensure_key().hex())"
        res = wait_all(spawn(code, {"KH": home}, 12))
        self.assertTrue(all(r[0] == 0 for r in res), res)
        self.assertEqual(len({r[1].strip() for r in res}), 1)
        self.assertEqual(len(open(os.path.join(home, "key")).read().strip()), 64)

    def test_concurrent_appends_lose_nothing_and_chain_verifies(self):
        home = tempfile.mkdtemp()
        code = ("from kneepad.audit import AuditLog;import os\nl=AuditLog(os.environ['KH'])\n"
                "for i in range(40): l.append('decision',{'i':i,'action':'ask'})")
        res = wait_all(spawn(code, {"KH": home}, 8))
        self.assertTrue(all(r[0] == 0 for r in res), res)
        r = AuditLog(home).verify()
        self.assertTrue(r.ok, r.error)
        self.assertEqual(r.count, 8 * 40)
        self.assertTrue(r.hmac_verified)

    def test_torn_tail_with_many_simultaneous_writers_rotates_exactly_once(self):
        home = tempfile.mkdtemp()
        log = AuditLog(home)
        for i in range(3):
            log.append("decision", {"seed": i})
        with open(log.path, "ab") as fh:
            fh.write(b'{"v":1,"seq":99,"ts"')
        gate = os.path.join(home, "go")
        code = ("import os,time\nfrom kneepad.audit import AuditLog\n"
                "while not os.path.exists(os.environ['GATE']): pass\n"
                "AuditLog(os.environ['KH']).append('decision',{'action':'ask'})")
        procs = spawn(code, {"KH": home, "GATE": gate}, 10)
        time.sleep(0.8)
        open(gate, "w").close()
        res = wait_all(procs)
        self.assertTrue(all(r[0] == 0 for r in res), res)
        corrupt = glob.glob(log.path + ".corrupt-*")
        self.assertEqual(len(corrupt), 1, "the corrupt log must be set aside exactly once")
        self.assertEqual(len(lines(corrupt[0])), 4)  # 3 good entries plus the torn line, kept as evidence
        v = AuditLog(home).verify()
        self.assertTrue(v.ok, v.error)
        self.assertEqual(v.count, 10, "every writer's entry must land in the live log")

    def test_verify_never_fails_while_writers_are_active(self):
        home = tempfile.mkdtemp()
        code = ("import time,os\nfrom kneepad.audit import AuditLog\nl=AuditLog(os.environ['KH'])\nt=time.time()\n"
                "while time.time()-t<3: l.append('decision',{'command':'x'*3000,'action':'ask'})")
        procs = spawn(code, {"KH": home}, 3)
        time.sleep(0.4)
        failures = []
        t = time.time()
        while time.time() - t < 2.2:
            r = AuditLog(home).verify()
            if not r.ok:
                failures.append(r.error)
        wait_all(procs)
        self.assertEqual(failures, [])
        self.assertTrue(AuditLog(home).verify().ok)


class TestAppendIfEmpty(unittest.TestCase):
    def test_only_the_first_call_writes(self):
        log = AuditLog(tempfile.mkdtemp())
        self.assertIsNotNone(log.append_if_empty("init", {"v": 1}))
        self.assertIsNone(log.append_if_empty("init", {"v": 1}))
        self.assertEqual(len(log.read_all()), 1)
        self.assertTrue(log.verify().ok)

    def test_many_processes_one_entry(self):
        home = tempfile.mkdtemp()
        code = "from kneepad.audit import AuditLog;import os;AuditLog(os.environ['KH']).append_if_empty('init',{})"
        res = wait_all(spawn(code, {"KH": home}, 12))
        self.assertTrue(all(r[0] == 0 for r in res), res)
        self.assertEqual(len(AuditLog(home).read_all()), 1)


class TestSnapshotRaces(unittest.TestCase):
    def test_parallel_snapshots_get_unique_ids_and_all_restore(self):
        from kneepad.snapshots import SnapshotPlan, SnapshotStore
        home = tempfile.mkdtemp()
        work = tempfile.mkdtemp()
        for i in range(6):
            with open(os.path.join(work, f"f{i}.txt"), "w") as fh:
                fh.write(f"content {i}")
        code = ("import os,json\nfrom kneepad.snapshots import SnapshotPlan, SnapshotStore\n"
                "w=os.environ['W']\ni=os.environ['I']\n")
        procs = []
        for i in range(6):
            c = code.replace("os.environ['I']", repr(str(i))) + (
                "p=SnapshotPlan('files', w, paths=[os.path.join(w,'f%d.txt')])\nprint(SnapshotStore(os.environ['KH']).create(p)['id'])" % i)
            procs.extend(spawn(c, {"KH": home, "W": work}, 1))
        res = wait_all(procs)
        self.assertTrue(all(r[0] == 0 for r in res), res)
        ids = [r[1].strip() for r in res]
        self.assertEqual(len(set(ids)), 6)
        store = SnapshotStore(home)
        self.assertEqual(len(store.list()), 6)
        for sid in ids:
            self.assertIsNotNone(store.get(sid))

    def test_prune_racing_with_create_does_not_crash(self):
        from kneepad.snapshots import SnapshotPlan, SnapshotStore
        home = tempfile.mkdtemp()
        work = tempfile.mkdtemp()
        with open(os.path.join(work, "a.txt"), "w") as fh:
            fh.write("a")
        creator = ("import os\nfrom kneepad.snapshots import SnapshotPlan, SnapshotStore\ns=SnapshotStore(os.environ['KH'])\n"
                   "for _ in range(25): s.create(SnapshotPlan('files', os.environ['W'], paths=[os.path.join(os.environ['W'],'a.txt')]))")
        pruner = ("import os\nfrom kneepad.snapshots import SnapshotStore\ns=SnapshotStore(os.environ['KH'])\n"
                  "for _ in range(25): s.prune(max_total_mb=0); s.list()")
        procs = spawn(creator, {"KH": home, "W": work}, 2) + spawn(pruner, {"KH": home}, 2)
        res = wait_all(procs)
        self.assertTrue(all(r[0] == 0 for r in res), [r[2][-300:] for r in res if r[0] != 0])


class TestInstallRaces(unittest.TestCase):
    def test_parallel_init_claude_code_leaves_one_valid_entry(self):
        home = tempfile.mkdtemp()
        state = tempfile.mkdtemp()
        code = "import sys;from kneepad.cli import main;sys.exit(main(['init','--claude-code']))"
        res = wait_all(spawn(code, {"HOME": home, "USERPROFILE": home, "KNEEPAD_HOME": state}, 6))
        self.assertTrue(all(r[0] == 0 for r in res), [r[2][-300:] for r in res])
        data = json.load(open(os.path.join(home, ".claude", "settings.json")))  # must be valid JSON, never torn
        ours = [h for g in data["hooks"]["PreToolUse"] for h in g["hooks"] if "kneepad" in h["command"]]
        self.assertEqual(len(ours), 1)
        self.assertTrue(AuditLog(state).verify().ok)
        self.assertEqual(len(AuditLog(state).read_all()), 1, "init must record exactly one init event")

    def test_parallel_install_and_uninstall_never_corrupt_settings(self):
        home = tempfile.mkdtemp()
        state = tempfile.mkdtemp()
        ins = "import sys;from kneepad.cli import main;[main(['init','--claude-code']) for _ in range(15)]"
        uni = "import sys;from kneepad.cli import main;[main(['uninstall']) for _ in range(15)]"
        env = {"HOME": home, "USERPROFILE": home, "KNEEPAD_HOME": state}
        res = wait_all(spawn(ins, env, 2) + spawn(uni, env, 2))
        self.assertTrue(all(r[0] == 0 for r in res), [r[2][-300:] for r in res])
        p = os.path.join(home, ".claude", "settings.json")
        if os.path.exists(p):
            json.load(open(p))  # still parseable, whatever the final state is


if __name__ == "__main__":
    unittest.main()


class TestBrokenPipe(unittest.TestCase):
    """`kneepad rules list | head -1` must exit 0 and stay silent, whenever the reader leaves (CI: STB-007 on macOS)."""

    @unittest.skipIf(os.name == "nt", "needs a POSIX pipe whose reader can leave early (`| head -1`); Windows cannot pass a raw os.pipe() descriptor to a child")
    def test_reader_leaves_before_exit_flush(self):
        import subprocess
        import time
        src = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src")
        code = ("import sys,time;sys.path.insert(0,%r);from kneepad.cli import main\n"
                "rc=main(['rules','list'])\n"
                "time.sleep(0.5)\n"
                "sys.exit(rc)") % src
        env = {k: v for k, v in os.environ.items() if k != "PYTHONUNBUFFERED"}
        r, w = os.pipe()
        p = subprocess.Popen([sys.executable, "-c", code], stdout=w, stderr=subprocess.PIPE, env=env)
        os.close(w)
        time.sleep(0.3)
        os.read(r, 100)
        os.close(r)
        err = p.stderr.read().decode()
        rc = p.wait()
        p.stderr.close()
        self.assertEqual(err.strip(), "", err)
        self.assertEqual(rc, 0)
