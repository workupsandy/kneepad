"""Large corpora: everyday commands must pass silently; known-bad commands must be stopped.

The corpora live in tests/corpus_benign.txt and tests/corpus_malicious.txt (one command per line)
so that the data is plain text and never executed.
"""
import os
import unittest

from helpers import IsolatedCase, make_repo, run_git

HERE = os.path.dirname(os.path.abspath(__file__))


def load(name):
    with open(os.path.join(HERE, name), encoding="utf-8") as fh:
        text = fh.read()
    # Entries are separated by lines containing only "---" so multi-line commands (heredocs) work.
    return [e.strip("\n") for e in text.split("\n---\n") if e.strip()]


BENIGN = load("corpus_benign.txt")
MALICIOUS = load("corpus_malicious.txt")


class TestBenignCorpus(IsolatedCase):
    def setUp(self):
        super().setUp()
        make_repo(self.proj)
        self.write("README.md")
        run_git(self.proj, "add", "-A")
        run_git(self.proj, "commit", "-q", "-m", "init")

    def test_benign_commands_pass_silently(self):
        wrong = []
        for cmd in BENIGN:
            d = self.decide(cmd)
            if d.action != "allow" or any(f.action != "allow" for f in d.findings):
                wrong.append((cmd, d.action, [f.rule_id for f in d.findings]))
        self.assertEqual(wrong, [], f"{len(wrong)}/{len(BENIGN)} benign commands flagged")
        self.assertGreaterEqual(len(BENIGN), 250)


class TestMaliciousCorpus(IsolatedCase):
    def setUp(self):
        super().setUp()
        make_repo(self.proj)
        self.write("a.txt")
        run_git(self.proj, "add", "-A")
        run_git(self.proj, "commit", "-q", "-m", "init")
        self.write("untracked.txt")

    def test_malicious_commands_are_stopped(self):
        missed = []
        for cmd in MALICIOUS:
            d = self.decide(cmd)
            if d.action == "allow" and not d.findings:
                missed.append(cmd)
        self.assertEqual(missed, [], f"{len(missed)}/{len(MALICIOUS)} not stopped")
        self.assertGreaterEqual(len(MALICIOUS), 120)

    def test_catastrophic_are_denied_not_asked(self):
        for cmd in ["rm -rf /", "rm -rf ~", "sudo rm -rf /", "bash -c 'rm -rf /'", "dd if=/dev/zero of=/dev/sda",
                    "mkfs.ext4 /dev/sda1", ":(){ :|:& };:", "chmod -R 777 /", "git push --force origin main"]:
            self.assertEqual(self.decide(cmd).action, "deny", cmd)


if __name__ == "__main__":
    unittest.main()
