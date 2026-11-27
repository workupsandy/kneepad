"""410-command allow/deny corpus written during QA: wrappers, quoting, nesting, cloud, data stores, secrets, and everyday work."""

import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from kneepad.config import Config  # noqa: E402
from kneepad.engine import Analyzer  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))


def load(name, home):
    out = []
    with open(os.path.join(HERE, name), encoding="utf-8") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if line and not line.startswith("#"):
                out.append(line.replace("@HOME@", home.replace("\\", "/")).replace("\\n", "\n"))
    return out


class TestQaCorpus(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.mkdtemp()
        self.work = tempfile.mkdtemp()
        self._saved = {k: os.environ.get(k) for k in ("HOME", "USERPROFILE", "KNEEPAD_HOME")}
        os.environ["HOME"] = os.environ["USERPROFILE"] = self.home
        os.environ["KNEEPAD_HOME"] = tempfile.mkdtemp()
        env = {**os.environ, "GIT_CONFIG_NOSYSTEM": "1"}
        for args in (["init", "-q"], ["config", "user.email", "q@q"], ["config", "user.name", "q"]):
            subprocess.run(["git", *args], cwd=self.work, capture_output=True, env=env)
        open(os.path.join(self.work, "tracked.txt"), "w").close()
        subprocess.run(["git", "add", "."], cwd=self.work, capture_output=True, env=env)
        subprocess.run(["git", "commit", "-qm", "i"], cwd=self.work, capture_output=True, env=env)
        self.az = Analyzer(config=Config(), cwd=self.work)

    def tearDown(self):
        for k, v in self._saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def test_every_dangerous_command_is_stopped(self):
        missed = [c for c in load("corpus_qa_stop.txt", self.home) if self.az.analyze_shell(c).action == "allow"]
        self.assertEqual(missed, [])

    def test_every_everyday_command_is_allowed(self):
        stopped = [(c, self.az.analyze_shell(c).action) for c in load("corpus_qa_allow.txt", self.home)
                   if self.az.analyze_shell(c).action != "allow"]
        self.assertEqual(stopped, [])

    def test_corpus_sizes_do_not_silently_shrink(self):
        self.assertGreaterEqual(len(load("corpus_qa_stop.txt", self.home)), 170)
        self.assertGreaterEqual(len(load("corpus_qa_allow.txt", self.home)), 220)


if __name__ == "__main__":
    unittest.main()
