"""The footgun database tests itself: every rule's examples are executed."""

import os
import re
import unittest

from helpers import ROOT, IsolatedCase

from kneepad.rules import SEVERITIES, load_default_rules, load_rules_text, validate_rule_dict


class TestDatabaseSchema(unittest.TestCase):
    def setUp(self):
        self.rules = load_default_rules()

    def test_loads_and_has_substantial_coverage(self):
        self.assertGreaterEqual(len(self.rules), 100)
        self.assertGreaterEqual(sum(1 for r in self.rules if not r.virtual), 100)

    def test_ids_unique(self):
        ids = [r.id for r in self.rules]
        self.assertEqual(len(ids), len(set(ids)))

    def test_every_dsl_rule_has_examples(self):
        for r in self.rules:
            if r.virtual:
                continue
            self.assertTrue(r.examples.get("match"), r.id)
            self.assertTrue(r.examples.get("no_match"), r.id)

    def test_invariants(self):
        for r in self.rules:
            self.assertIn(r.severity, SEVERITIES, r.id)
            if r.severity == "critical" and not r.virtual:
                self.assertEqual(r.action, "deny", r.id)
            if r.action == "allow":
                self.assertTrue(r.virtual or r.snapshot != "none", f"{r.id}: allow rules need a snapshot")
            self.assertTrue(len(r.why) > 30, r.id)
            self.assertTrue(len(r.safer) > 10, r.id)

    def test_all_engine_emitted_rule_ids_exist(self):
        """Every emit('rule-id') literal in the engine must be defined in the database."""
        with open(os.path.join(ROOT, "src", "kneepad", "engine.py")) as fh:
            src = fh.read()
        emitted = set(re.findall(r'emit\(\s*"([a-z0-9-]+)"', src))
        emitted |= set(re.findall(r'self\.emit\(\s*"([a-z0-9-]+)"', src))
        ids = {r.id for r in self.rules}
        missing = emitted - ids
        self.assertFalse(missing, f"engine emits rules missing from footguns.toml: {missing}")
        self.assertGreaterEqual(len(emitted), 15)

    def test_sql_and_mongo_kind_mappings_exist(self):
        from kneepad.engine import SQL_KIND_TO_RULE
        ids = {r.id for r in self.rules}
        for rid in SQL_KIND_TO_RULE.values():
            self.assertIn(rid, ids)
        for rid in ("mongo-drop-database", "mongo-drop-collection", "mongo-delete-all", "mongo-update-all", "redis-flush"):
            self.assertIn(rid, ids)

    def test_validator_rejects_bad_rules(self):
        bad_cases = {
            "no examples": '''[[rule]]
id="a-b"
title="t"
family="f"
severity="high"
action="ask"
why="w"
safer="s"
[rule.match]
cmd=["x"]
''',
            "bad regex": '''[[rule]]
id="a-b"
title="t"
family="f"
severity="high"
action="ask"
why="w"
safer="s"
[rule.match]
cmd=["x"]
args_regex="("
[rule.examples]
match=["x"]
no_match=["y"]
''',
            "critical must deny": '''[[rule]]
id="a-b"
title="t"
family="f"
severity="critical"
action="ask"
why="w"
safer="s"
[rule.match]
cmd=["x"]
[rule.examples]
match=["x"]
no_match=["y"]
''',
            "matches everything": '''[[rule]]
id="a-b"
title="t"
family="f"
severity="low"
action="ask"
why="w"
safer="s"
[rule.match]
flags_any=["-f"]
[rule.examples]
match=["x"]
no_match=["y"]
''',
            "unknown key": '''[[rule]]
id="a-b"
title="t"
family="f"
severity="low"
action="ask"
why="w"
safer="s"
[rule.match]
cmd=["x"]
bogus=1
[rule.examples]
match=["x"]
no_match=["y"]
''',
            "bad id": '''[[rule]]
id="Bad_ID"
title="t"
family="f"
severity="low"
action="ask"
why="w"
safer="s"
virtual=true
''',
            "high allow without snapshot": '''[[rule]]
id="a-b"
title="t"
family="f"
severity="high"
action="allow"
why="w"
safer="s"
virtual=true
''',
        }
        for name, text in bad_cases.items():
            with self.assertRaises(ValueError, msg=name):
                load_rules_text(text)

    def test_duplicate_ids_rejected(self):
        one = '''[[rule]]
id="a-b"
title="t"
family="f"
severity="low"
action="ask"
why="w"
safer="s"
virtual=true
'''
        with self.assertRaises(ValueError):
            load_rules_text(one + one)


class TestRuleExamples(IsolatedCase):
    """Run each rule's own examples through the real analyzer, inside a real git repository."""

    def setUp(self):
        super().setUp()
        from helpers import make_repo, run_git
        make_repo(self.proj)
        self.write("README.md", "hello")
        run_git(self.proj, "add", "-A")
        run_git(self.proj, "commit", "-q", "-m", "init")

    def test_every_example_behaves_as_documented(self):
        failures = []
        for r in load_default_rules():
            if r.virtual:
                continue
            for cmd in r.examples["match"]:
                ids = self.rule_ids(cmd)
                if r.id not in ids:
                    failures.append(f"{r.id}: expected to match: {cmd!r} (got {sorted(ids)})")
            for cmd in r.examples["no_match"]:
                ids = self.rule_ids(cmd)
                if r.id in ids:
                    failures.append(f"{r.id}: must NOT match: {cmd!r}")
        self.assertFalse(failures, "\n" + "\n".join(failures))


if __name__ == "__main__":
    unittest.main()
