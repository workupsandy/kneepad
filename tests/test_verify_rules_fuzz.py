"""Audit verify branches, rule-file validation errors, and seeded fuzzing of every hook protocol."""

import copy
import json
import os
import random
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from kneepad.adapters import ADAPTERS  # noqa: E402
from kneepad.audit import AuditLog, canonical  # noqa: E402
from kneepad.hook import handle  # noqa: E402
from kneepad.rules import load_rules_text  # noqa: E402


def make_log(n=4):
    home = tempfile.mkdtemp()
    log = AuditLog(home)
    for i in range(n):
        log.append("decision", {"i": i, "action": "ask"})
    return home, log


def rewrite(log, fn):
    with open(log.path, "rb") as fh:
        raw = [l for l in fh.read().split(b"\n") if l]
    out = fn(raw)
    with open(log.path, "wb") as fh:
        fh.write(b"\n".join(out) + b"\n")


class TestVerifyBranches(unittest.TestCase):
    def fails(self, mutate, needle):
        home, log = make_log()
        rewrite(log, mutate)
        r = AuditLog(home).verify()
        self.assertFalse(r.ok)
        self.assertIn(needle, r.error)

    def test_blank_line(self):
        self.fails(lambda raw: raw[:2] + [b""] + raw[2:], "blank line")

    def test_non_ascii(self):
        self.fails(lambda raw: [raw[0] + "é".encode("utf-8")] + raw[1:], "non-ASCII")

    def test_not_json(self):
        self.fails(lambda raw: raw[:1] + [b"{nope"] + raw[2:], "not valid JSON")

    def test_not_object(self):
        self.fails(lambda raw: raw[:1] + [b"[1]"] + raw[2:], "not an object")

    def test_missing_field(self):
        def m(raw):
            e = json.loads(raw[1])
            del e["prev"]
            return raw[:1] + [canonical(e).encode()] + raw[2:]
        self.fails(m, "missing field")

    def test_not_canonical(self):
        def m(raw):
            return raw[:1] + [json.dumps(json.loads(raw[1]), indent=0).replace("\n", "").encode()] + raw[2:]
        self.fails(m, "canonical")

    def test_forged_hmac(self):
        def m(raw):
            e = json.loads(raw[1])
            e["hmac"] = "0" * 64
            return raw[:1] + [canonical(e).encode()] + raw[2:]
        self.fails(m, "signature")

    def test_unsigned_entry_when_key_exists(self):
        def m(raw):
            e = json.loads(raw[1])
            del e["hmac"]
            return raw[:1] + [canonical(e).encode()] + raw[2:]
        self.fails(m, "unsigned")

    def test_edited_content_with_recomputed_chain_but_no_key_is_caught_by_hmac(self):
        home, log = make_log()
        import hashlib
        def m(raw):
            out = []
            prev = "0" * 64
            for i, line in enumerate(raw):
                e = json.loads(line)
                e["prev"] = prev
                if i == 1:
                    e["data"]["action"] = "allow"
                body = {k: v for k, v in e.items() if k not in ("hash", "hmac")}
                e["hash"] = hashlib.sha256(canonical(body).encode()).hexdigest()
                prev = e["hash"]
                out.append(canonical(e).encode())
            return out
        rewrite(log, m)
        r = AuditLog(home).verify()
        self.assertFalse(r.ok)
        self.assertIn("signature", r.error)

    def test_anchor_mismatch_and_truncation(self):
        home, log = make_log()
        anchor = log.anchor()
        seq, h = anchor.split(":")
        self.assertFalse(log.verify(anchor=f"{seq}:{'0' * 64}").ok)
        self.assertIn("rewritten", log.verify(anchor=f"{seq}:{'0' * 64}").error)
        rewrite(log, lambda raw: raw[:-1])
        r = log.verify(anchor=anchor)
        self.assertFalse(r.ok)
        self.assertIn("truncated", r.error)
        self.assertFalse(AuditLog(tempfile.mkdtemp()).verify(anchor="1:" + "a" * 64).ok)

    def test_stale_writer_gives_up_cleanly(self):
        from unittest import mock
        home, log = make_log(1)
        with mock.patch.object(AuditLog, "_is_live", return_value=False):
            with self.assertRaises(OSError):
                log.append("decision", {"x": 1})

    def test_key_unreadable_raises(self):
        from unittest import mock
        log = AuditLog(tempfile.mkdtemp())
        with mock.patch.object(AuditLog, "_read_key", return_value=None):
            with self.assertRaises(OSError):
                log.ensure_key()

    def test_anchor_refused_for_broken_log(self):
        home, log = make_log()
        with open(log.path, "ab") as fh:
            fh.write(b"junk\n")
        self.assertIsNone(log.anchor())

    def test_append_after_every_entry_keeps_seq_gapless_and_unicode_is_escaped(self):
        home = tempfile.mkdtemp()
        log = AuditLog(home)
        log.append("decision", {"command": "echo héllo ✓ 日本語 \u0000 \ud83d"[:-1]})
        raw = open(log.path, "rb").read()
        raw.decode("ascii")  # entries are ASCII-only on disk
        self.assertTrue(log.verify().ok)


GOOD = ('[[rule]]\nid = "x-y"\ntitle = "t"\nfamily = "x"\nseverity = "high"\naction = "ask"\nwhy = "w"\nsafer = "s"\n'
        'reversible = "no"\n[rule.match]\ncmd = ["thing"]\nsub = [["go"]]\n[rule.examples]\nmatch = ["thing go"]\nno_match = ["thing stop"]\n')


class TestRuleValidation(unittest.TestCase):
    def bad(self, text, needle):
        with self.assertRaises(ValueError) as cm:
            load_rules_text(text)
        self.assertIn(needle, str(cm.exception))

    def test_good_rule_loads(self):
        self.assertEqual(len(load_rules_text(GOOD)), 1)

    def test_each_invalid_field(self):
        cases = [
            (GOOD.replace('id = "x-y"', 'id = "Bad_ID"'), "kebab"),
            (GOOD.replace('severity = "high"', 'severity = "huge"'), "severity"),
            (GOOD.replace('action = "ask"', 'action = "maybe"'), "action"),
            (GOOD.replace('reversible = "no"', 'reversible = "sometimes"'), "reversible"),
            (GOOD.replace('severity = "high"', 'severity = "critical"'), "critical rules must deny"),
            (GOOD.replace('action = "ask"', 'action = "allow"'), "cannot simply allow"),
            (GOOD.replace('safer = "s"', 'safer = ""'), "safer"),
            (GOOD.replace('cmd = ["thing"]', 'cmd = "thing"'), "must be a list of strings"),
            (GOOD.replace('cmd = ["thing"]\n', ''), "cmd, cmd_re or raw_regex"),
            (GOOD.replace('sub = [["go"]]', 'sub = ["go"]'), "sub must be"),
            (GOOD.replace('sub = [["go"]]', 'sub = [["re:("]]'), "regex"),
            (GOOD.replace('sub = [["go"]]', 'bogus = 1'), "unknown match keys"),
            (GOOD.replace('[rule.examples]\nmatch = ["thing go"]\n', '[rule.examples]\nmatch = []\n'), "examples.match"),
            (GOOD.replace('reversible = "no"\n', 'reversible = "no"\nrefs = ["http://insecure"]\n'), "https"),
            (GOOD.replace('[rule.match]\ncmd = ["thing"]\nsub = [["go"]]\n', '[rule.match]\ncmd = ["thing"]\nargs_regex = "("\n'), "regex"),
            (GOOD.replace('sub = [["go"]]', 'flag_values = {"-x" = "y"}'), "flag_values"),
            (GOOD.split("[rule.match]")[0], "match"),
        ]
        for text, needle in cases:
            with self.subTest(needle=needle):
                self.bad(text, needle)

    def test_duplicate_ids_and_non_toml(self):
        self.bad(GOOD + GOOD, "duplicate")
        self.bad("[[rule", "")

    def test_validate_checks_structure_only_and_says_so(self):
        # Examples are executed by tests/test_rules_db.py, not by `kneepad rules validate`; the command must not imply otherwise.
        import io
        from contextlib import redirect_stdout
        from kneepad import cli
        p = os.path.join(tempfile.mkdtemp(), "r.toml")
        open(p, "w").write(GOOD.replace('match = ["thing go"]', 'match = ["thing stop"]'))
        out = io.StringIO()
        with redirect_stdout(out):
            rc = cli.main(["rules", "validate", p])
        self.assertEqual(rc, 0)
        self.assertIn("structure", out.getvalue())


def mutate(rng, obj):
    """Return a structurally damaged copy: drop keys, swap types, nest, truncate strings."""
    o = copy.deepcopy(obj)
    stack = [o]
    nodes = []
    while stack:
        n = stack.pop()
        nodes.append(n)
        for v in (n.values() if isinstance(n, dict) else n if isinstance(n, list) else []):
            if isinstance(v, (dict, list)):
                stack.append(v)
    for _ in range(rng.randint(1, 3)):
        n = rng.choice(nodes)
        if isinstance(n, dict) and n:
            k = rng.choice(list(n))
            c = rng.randint(0, 6)
            if c == 0:
                del n[k]
            elif c == 1:
                n[k] = None
            elif c == 2:
                n[k] = rng.choice([1, 2.5, True, [], {}, [1, 2], {"a": {"b": [None]}}])
            elif c == 3 and isinstance(n[k], str):
                n[k] = n[k][: rng.randint(0, len(n[k]))]
            elif c == 4:
                n[k] = [n[k]]
            elif c == 5:
                n[k] = json.dumps(n[k])
            else:
                n[k] = "\x00" * rng.randint(1, 50)
        elif isinstance(n, list) and n:
            n[rng.randrange(len(n))] = rng.choice([None, 7, "x", {}, []])
    return o


class TestHookFuzz(unittest.TestCase):
    """No payload, however damaged, may crash the hook, print a traceback, or emit unparseable output."""

    def test_seeded_fuzz_every_adapter(self):
        sys.path.insert(0, os.path.dirname(__file__))
        from test_allow_deny_matrix import Env, payload  # noqa: E402
        e = Env()
        try:
            rng = random.Random(20261127)
            checked = 0
            for a in sorted(ADAPTERS):
                for kind, val in (("bash", "rm -rf /"), ("bash", "ls"), ("write", os.path.join(e.home, ".ssh", "id_rsa")), ("mcp", "DROP TABLE x")):
                    base = payload(a, kind, val, e.work)
                    for _ in range(40):
                        raw = json.dumps(mutate(rng, base))
                        code, out = handle(raw, home=e.state, integration=a)
                        self.assertIn(code, (0, 2), (a, raw[:200]))
                        self.assertNotIn("Traceback", out)
                        if out.strip() and a != "generic":
                            json.loads(out)  # a vendor reply must be valid JSON
                        checked += 1
            self.assertEqual(checked, len(ADAPTERS) * 4 * 40)
            self.assertTrue(AuditLog(e.state).verify().ok)
        finally:
            e.close()

    def test_random_bytes_and_unicode_never_crash(self):
        rng = random.Random(7)
        home = tempfile.mkdtemp()
        for _ in range(300):
            n = rng.randint(0, 200)
            raw = "".join(chr(rng.choice([rng.randint(0, 127), rng.randint(128, 0x2FFF), rng.randint(0xE000, 0xFFFD)])) for _ in range(n))
            for a in ("claude", "generic", "cursor"):
                code, out = handle(raw, home=home, integration=a)
                self.assertIn(code, (0, 2))

    def test_random_commands_never_crash_the_analyzer(self):
        from kneepad.config import Config
        from kneepad.engine import Analyzer
        rng = random.Random(99)
        alphabet = list("abc rm-rf/~$\"'`|&;<>(){}[]*?\\\n\t#=:.,") + ["sudo ", "bash -c ", "eval ", "$(", "&& ", "|| ", "<<EOF\n", "EOF\n", "git ", "push ", "--force "]
        az = Analyzer(config=Config(), cwd=tempfile.mkdtemp())
        for _ in range(1500):
            cmd = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 60)))
            d = az.analyze_shell(cmd)
            self.assertIn(d.action, ("allow", "ask", "deny"), cmd)


if __name__ == "__main__":
    unittest.main()
