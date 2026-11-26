import random
import shlex
import time
import unittest

from helpers import IsolatedCase

ALPHABET = list("abcdefghijklmnopqrstuvwxyz0123456789 \t\n;|&<>()$`'\"\\{}[]*?~#!=-/._:@%^,+")
FRAGMENTS = ["rm", "-rf", "/", "sudo", "bash -c", "$(", ")", "`", "<<EOF", "EOF", "'", '"', "&&", "||", "|", ";", "git", "push",
             "--force", "psql -c", "DROP TABLE", "DELETE FROM", "kubectl", "delete", "$X", "${", "}", "~", "*", "\\", "<(", "2>&1",
             "eval", "xargs", "find", "-delete", "-exec", "{}", "\\;", "terraform", "destroy", "docker", "exec", "ssh", "host"]


class TestRobustness(IsolatedCase):
    def test_random_garbage_never_crashes(self):
        rnd = random.Random(1234)
        slow = []
        for _ in range(500):
            s = "".join(rnd.choice(ALPHABET) for _ in range(rnd.randint(0, 120)))
            t = time.time()
            d = self.decide(s)
            self.assertIn(d.action, ("allow", "ask", "deny"))
            if time.time() - t > 1:
                slow.append(s)
        self.assertEqual(slow, [])

    def test_random_fragment_soup_never_crashes(self):
        rnd = random.Random(99)
        for _ in range(500):
            s = " ".join(rnd.choice(FRAGMENTS) for _ in range(rnd.randint(1, 14)))
            self.assertIn(self.decide(s).action, ("allow", "ask", "deny"))

    def test_pathological_inputs_are_fast(self):
        cases = ["(" * 5000, "$(" * 3000, "'" * 20000, '"' * 20001, "a|" * 20000 + "b", "&&".join(["ls"] * 4000),
                 "echo " + "$(" * 200 + ")" * 200, "x=" + "$x" * 5000, "<<EOF\n" * 500, "\\" * 100000, "`" * 9999,
                 "rm " + "a " * 30000, ";" * 50000, "{" * 10000, "bash -c " + "'" * 5000]
        for c in cases:
            t = time.time()
            d = self.decide(c)
            self.assertIn(d.action, ("allow", "ask", "deny"))
            self.assertLess(time.time() - t, 5, c[:30])

    def test_binary_and_unicode_inputs(self):
        for s in ["\x00rm -rf /", "ls \udcff", "echo 日本語 🚀", "rm -rf /\u200b", "r\u200bm -rf /", "\ufeffrm -rf /", "rm\u00a0-rf\u00a0/"]:
            self.assertIn(self.decide(s).action, ("allow", "ask", "deny"))
        self.assertEqual(self.decide("\ufeffrm -rf /").action, "deny")

    def test_catastrophic_survives_wrapping(self):
        base = "rm -rf /"
        wrappers = ["{}", "sudo {}", "sudo -n {}", "env A=1 {}", "nohup {} &", "time {}", "true && {}", "false || {}", "{}; echo done",
                    "echo start; {}", "( {} )", "{{ {}; }}", "if true; then {}; fi", "for i in 1; do {}; done", "while true; do {}; done",
                    "bash -c {q}", "sh -c {q}", "eval {q}", "ssh h {q}", "docker exec c sh -c {q}", "sudo bash -c {q}",
                    "echo {q} | sh", "echo {q} | bash -s", "bash <<< {q}", "xargs -I{{}} sh -c {q}", "timeout 9 {}", "nice {}", "command {}"]
        for w in wrappers:
            cmd = w.format(base, q=shlex.quote(base))
            self.assertEqual(self.decide(cmd).action, "deny", cmd)

    def test_same_input_same_decision(self):
        for c in ["rm -rf /", "terraform destroy", "ls", "git push -f origin main"]:
            a = self.decide(c)
            b = self.decide(c)
            self.assertEqual((a.action, [f.rule_id for f in a.findings]), (b.action, [f.rule_id for f in b.findings]))


if __name__ == "__main__":
    unittest.main()
