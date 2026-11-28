"""0.3.3: brace expansion, cd tracking, more wrappers, and dry-run exemptions."""

import os
import unittest

from helpers import IsolatedCase

from kneepad import braces


class TestBraces(unittest.TestCase):
    def test_lists_and_sequences(self):
        self.assertEqual(braces.expand("./{src,docs}"), ["./src", "./docs"])
        self.assertEqual(braces.expand("a{1..3}b"), ["a1b", "a2b", "a3b"])
        self.assertEqual(braces.expand("{a,b{c,d}}"), ["a", "bc", "bd"])
        self.assertEqual(braces.expand("f{,.bak}"), ["f", "f.bak"])
        self.assertEqual(braces.expand("{c..a}"), ["c", "b", "a"])
        self.assertEqual(braces.expand("{01..03}"), ["01", "02", "03"])

    def test_literal_groups_stay_literal(self):
        for t in ("x{}y", "{x}", "plain", "{", "a}b{"):
            self.assertEqual(braces.expand(t), [t], t)

    def test_cap(self):
        self.assertIsNone(braces.expand("{1..99999}"))
        self.assertIsNone(braces.expand("{1..500}{1..500}"))


class TestRmBraces(IsolatedCase):
    def setUp(self):
        super().setUp()
        for d in ("src", "docs", "keep"):
            self.write(f"{d}/f.txt")

    def test_brace_targets_get_a_safety_copy(self):
        d = self.decide("rm -rf ./{src,docs}")
        plans = [p for p in d.plans if p.kind == "files"]
        self.assertEqual(len(plans), 1)
        got = sorted(os.path.basename(p) for p in plans[0].paths)
        self.assertEqual(got, ["docs", "src"])

    def test_same_as_spelled_out(self):
        a = self.decide("rm -rf ./{src,docs}")
        b = self.decide("rm -rf ./src ./docs")
        self.assertEqual(a.action, b.action)

    def test_home_brace_targets(self):
        for d in ("Documents", "Pictures"):
            os.makedirs(os.path.join(self.home, d))
            self.write(f"{d}/a", base=self.home)
        d = self.decide("rm -rf ~/{Documents,Pictures}")
        paths = [p for plan in d.plans for p in plan.paths]
        self.assertEqual(sorted(os.path.basename(p) for p in paths), ["Documents", "Pictures"])

    def test_catastrophic_hidden_in_braces(self):
        self.assertEqual(self.decide("rm -rf {/,x}").action, "deny")
        self.assertEqual(self.decide("rm -rf ~{,/}").action, "deny")

    def test_quoted_braces_are_literal(self):
        d = self.decide("rm -rf './{src,docs}'")
        self.assertFalse([p for p in d.plans if p.kind == "files"])

    def test_oversized_expansion_asks(self):
        self.assertEqual(self.decide("rm -rf ./{1..99999}{1..99999}").action, "ask")


class TestCd(IsolatedCase):
    def test_cd_home_then_wipe_is_catastrophic(self):
        self.assertEqual(self.decide("cd ~ && rm -rf *").action, "deny")
        self.assertEqual(self.decide("cd / && rm -rf *").action, "deny")
        self.assertEqual(self.decide("cd $HOME; rm -rf ./*").action, "deny")
        self.assertEqual(self.decide("pushd / && rm -rf *").action, "deny")
        self.assertEqual(self.decide("cd && rm -rf *").action, "deny")

    def test_cd_into_project_dir_resolves_relative_paths_there(self):
        other = os.path.join(self.tmp, "other")
        os.makedirs(os.path.join(other, "stuff"))
        self.write("stuff/x", base=other)
        d = self.decide(f"cd '{other}' && rm -rf stuff")  # single quotes keep Windows backslashes literal
        paths = [p for plan in d.plans for p in plan.paths]
        self.assertEqual(paths, [os.path.join(other, "stuff")])

    def test_cd_into_system_dir_asks(self):
        self.assertEqual(self.decide("cd /etc && rm -rf ssl").action, "ask")

    def test_dynamic_cd_leaves_cwd_alone(self):
        self.write("stuff/x")
        d = self.decide('cd "$SOMEWHERE" && rm -rf stuff')
        paths = [p for plan in d.plans for p in plan.paths]
        self.assertEqual(paths, [os.path.join(self.proj, "stuff")])

    def test_cd_does_not_leak_between_commands_analysed_separately(self):
        a = self.analyzer()
        a.analyze_shell("cd / && true")
        self.assertEqual(a.cwd, self.proj)

    def test_cd_inside_bash_c(self):
        self.assertEqual(self.decide("bash -c 'cd / && rm -rf *'").action, "deny")


class TestWrappers(IsolatedCase):
    def setUp(self):
        super().setUp()
        self.write("src/f.txt")

    def planned(self, cmd):
        return [p for plan in self.decide(cmd).plans for p in plan.paths]

    def test_wrappers_are_unwrapped(self):
        want = [os.path.join(self.proj, "src")]
        for cmd in (
            "watch rm -rf ./src",
            "watch -n 5 rm -rf ./src",
            "watch 'rm -rf ./src'",
            "flock /tmp/l rm -rf ./src",
            "flock -w 5 /tmp/l rm -rf ./src",
            "flock /tmp/l -c 'rm -rf ./src'",
            "env -S 'rm -rf ./src'",
            "env -S'rm -rf ./src'",
            "env --split-string='rm -rf ./src'",
            "env -i FOO=1 -S 'rm -rf ./src'",
        ):
            self.assertEqual(self.planned(cmd), want, cmd)

    def test_catastrophic_through_wrappers(self):
        for cmd in ("watch 'rm -rf /'", "flock /tmp/l -c 'rm -rf ~'", "env -S 'rm -rf /'"):
            self.assertEqual(self.decide(cmd).action, "deny", cmd)

    def test_harmless_wrapped_commands_stay_quiet(self):
        for cmd in ("watch -n 2 ls", "flock /tmp/l -c 'echo hi'", "env -S 'echo hi'", "watch 'git status'"):
            self.assertEqual(self.decide(cmd).action, "allow", cmd)


class TestDryRun(IsolatedCase):
    def action(self, cmd):
        return self.decide(cmd).action

    def test_dry_run_is_not_blocked(self):
        for cmd in (
            "git push --dry-run origin main --force",
            "git push -n --force origin main",
            "git push --force --dry-run",
            "helm uninstall x --dry-run",
            "helm rollback x 1 --dry-run",
            "aws s3 sync . s3://b --delete --dryrun",
            "aws s3 rm s3://b --recursive --dryrun",
            "aws ec2 terminate-instances --instance-ids i-1 --dry-run",
        ):
            self.assertEqual(self.action(cmd), "allow", cmd)

    def test_the_real_thing_is_still_stopped(self):
        for cmd, want in (
            ("git push --force origin main", "deny"),
            ("helm uninstall x", "ask"),
            ("aws s3 rm s3://b --recursive", None),
            ("aws s3 rb s3://b --force", "deny"),
        ):
            got = self.action(cmd)
            if want:
                self.assertEqual(got, want, cmd)
            else:
                self.assertNotEqual(got, "allow", cmd)

    def test_dry_run_flag_on_a_different_command_does_not_exempt(self):
        self.assertNotEqual(self.action("aws s3 rb s3://b --force --dryrun"), "allow")
        self.assertNotEqual(self.action("git push --force origin main && git push -n"), "allow")


class TestRegressions034(IsolatedCase):
    """0.3.4: found by the company CTO's review of 0.3.3."""

    def setUp(self):
        super().setUp()
        self.write("src/f.txt")
        self.write("node_modules/y")
        self.write("top.txt")

    def planned(self, cmd):
        return sorted({os.path.basename(p) for plan in self.decide(cmd).plans for p in plan.paths})

    def test_wrong_guess_about_cd_never_drops_the_project_copy(self):
        for cmd in (
            "(cd node_modules && ls) && rm -rf *",
            "cd node_modules && ls; cd - ; rm -rf *",
            "cd src | cat; rm -rf *",
            "cd src & rm -rf *",
            "false && cd src; rm -rf *",
            "cd src && rm -rf *",
        ):
            got = self.planned(cmd)
            self.assertIn("top.txt", got, cmd)
            self.assertIn("src", got, cmd)

    def test_cd_followed_target_is_still_planned_too(self):
        self.assertIn("f.txt", self.planned("cd src && rm -rf *"))

    def test_dry_run_switched_off_is_a_real_run(self):
        for cmd in (
            "helm uninstall api --dry-run=false",
            "helm uninstall api --dry-run=none",
            "aws s3 rm s3://b --recursive --dryrun --no-dryrun",
        ):
            self.assertNotEqual(self.decide(cmd).action, "allow", cmd)
        self.assertEqual(self.decide("git push --force origin main --dry-run --no-dry-run").action, "deny")

    def test_dry_run_still_allowed_when_really_on(self):
        for cmd in (
            "helm uninstall api --dry-run",
            "helm uninstall api --dry-run=client",
            "git push --force origin main --dry-run",
            "aws s3 rm s3://b --recursive --dryrun",
        ):
            self.assertEqual(self.decide(cmd).action, "allow", cmd)

    def test_two_different_safety_copies_are_not_merged(self):
        self.assertEqual(len([p for p in self.decide("cd src && rm -rf *").plans if p.kind == "files"]), 2)


if __name__ == "__main__":
    unittest.main()
