"""Regression tests for problems found by QA: regex bounds, oversized input, NUL bytes, --help."""

from __future__ import annotations

import json
import time
import unittest

from helpers import IsolatedCase  # noqa: F401

from kneepad import hook
from kneepad.rules import REGEX_INPUT_CAP, bounded_args


class TestHardening(IsolatedCase):
    def ids(self, cmd):
        d = self.analyzer().analyze_shell(cmd)
        return d.action, {f.rule_id for f in d.findings}

    def test_bounded_args_keeps_head_and_tail_and_is_bounded(self):
        s = "HEAD " + "x" * 100000 + " TAIL"
        b = bounded_args(s)
        self.assertLessEqual(len(b), REGEX_INPUT_CAP + 1)
        self.assertTrue(b.startswith("HEAD") and b.endswith("TAIL"))
        self.assertEqual(bounded_args("short"), "short")

    def test_oversized_arguments_ask_instead_of_silently_passing(self):
        action, ids = self.ids("echo " + "a " * (REGEX_INPUT_CAP // 2 + 10))
        self.assertEqual(action, "ask")
        self.assertIn("cmd-oversized", ids)

    def test_destructive_command_hidden_among_huge_arguments_is_still_stopped(self):
        action, _ = self.ids("echo " + "a " * 20000 + "; terraform destroy -auto-approve; echo " + "b " * 20000)
        self.assertEqual(action, "deny")

    def test_pathological_repeated_flags_finish_quickly(self):
        for unit, cmd in (("-i ", "sed"), ("-r ", "rm"), ("-R ", "chmod")):
            t = time.time()
            self.ids(f"{cmd} " + unit * 20000)
            self.assertLess(time.time() - t, 5.0, cmd)

    def test_oversized_hook_stdin_is_not_allowed(self):
        code, out = hook.handle(" " * (hook.MAX_STDIN + 1), home=self.sb_home)
        compact = out.replace(" ", "")
        self.assertIn('"permissionDecision":"ask"', compact)

    def test_nul_bytes_do_not_crash_or_hide_commands(self):
        for c in ("ls\x00; terraform destroy -auto-approve", "x\x00/y>\"z", "cat <\x00f", "source ~\x00/x"):
            self.ids(c)  # must not raise
        self.assertEqual(self.ids("ls\x00; terraform destroy -auto-approve")[0], "deny")

    def test_help_and_version_as_first_argument_are_not_flagged(self):
        for c in ("useradd --help", "dropdb --help", "terraform --version", "kubectl --help"):
            self.assertEqual(self.ids(c)[0], "allow", c)

    def test_help_exemption_does_not_open_a_bypass(self):
        # GNU dd honours --help only as argv[1]; later positions must still be analysed.
        self.assertNotEqual(self.ids("rm -rf / --help")[0], "allow")
        self.assertNotEqual(self.ids("sudo --help; rm -rf /")[0], "allow")
        self.assertNotEqual(self.ids("terraform destroy -auto-approve --help")[0], "allow")

    def test_read_only_boot_and_account_commands_pass(self):
        for c in ("efibootmgr -v", "bcdedit", "bootctl status", "visudo -c", "passwd --status bob"):
            self.assertEqual(self.ids(c)[0], "allow", c)


if __name__ == "__main__":
    unittest.main()
