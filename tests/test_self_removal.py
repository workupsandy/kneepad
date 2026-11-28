"""0.3.3: an agent gets a prompt before it removes Kneepad itself."""

import unittest

from helpers import IsolatedCase


class TestSelfRemoval(IsolatedCase):
    def ids(self, cmd):
        return self.rule_ids(cmd)

    def test_asks_for_the_common_forms(self):
        for cmd in (
            "kneepad uninstall",
            "kneepad uninstall --all",
            "pip uninstall -y kneepad",
            "pip3 uninstall kneepad",
            "python -m pip uninstall -y kneepad",
            "python3 -m pip uninstall kneepad",
            "pipx uninstall kneepad",
            "uv pip uninstall kneepad",
            "uv tool uninstall kneepad",
            "poetry remove kneepad",
            "python3 -m kneepad uninstall",
            "sudo pip uninstall -y kneepad",
            "cd /tmp && pip uninstall kneepad",
            "bash -c 'pip uninstall -y kneepad'",
            "timeout 20 pipx uninstall kneepad",
            "rm -rf ~/.kneepad",
            "mv ~/.kneepad /tmp/gone",
        ):
            d = self.decide(cmd)
            self.assertIn(d.action, ("ask", "deny"), cmd)
            self.assertTrue(any(i.startswith("kneepad-self-") for i in {f.rule_id for f in d.findings}), cmd)

    def test_unrelated_commands_are_quiet(self):
        for cmd in (
            "pip install kneepad",
            "pip install -U kneepad",
            "pip uninstall requests",
            "pip uninstall -y requests kneepad-extras-not-ours",
            "pipx install kneepad",
            "kneepad doctor",
            "kneepad check 'ls'",
            "echo kneepad uninstall",
            "git commit -m 'kneepad uninstall docs'",
            "ls ~/.kneepad",
            "cat ~/.kneepad/config.toml",
        ):
            self.assertFalse({i for i in self.ids(cmd) if i.startswith("kneepad-self-")}, cmd)

    def test_rule_counts(self):
        from kneepad.rules import load_default_rules
        rules = load_default_rules()
        self.assertEqual(len(rules), 253)
        self.assertEqual(len([r for r in rules if not r.virtual]), 220)


if __name__ == "__main__":
    unittest.main()
