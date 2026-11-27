"""Shared test helpers: isolated HOME, KNEEPAD_HOME and working directories."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)

from kneepad.config import Config  # noqa: E402
from kneepad.engine import Analyzer  # noqa: E402


class IsolatedCase(unittest.TestCase):
    """Each test gets a private HOME, KNEEPAD_HOME and project directory."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = os.path.realpath(self._tmp.name)
        self.home = os.path.join(self.tmp, "home")
        self.sb_home = os.path.join(self.tmp, "sbhome")
        self.proj = os.path.join(self.tmp, "proj")
        for d in (self.home, self.proj):
            os.makedirs(d)
        patcher = mock.patch.dict(os.environ, {"HOME": self.home, "USERPROFILE": self.home, "KNEEPAD_HOME": self.sb_home}, clear=False)
        patcher.start()
        self.addCleanup(patcher.stop)
        os.environ.pop("KNEEPAD_MODE", None)

    def analyzer(self, cwd: str | None = None, config: Config | None = None) -> Analyzer:
        return Analyzer(cwd=cwd or self.proj, home=self.home, config=config or Config(), env={})

    def decide(self, command: str, cwd: str | None = None, config: Config | None = None):
        return self.analyzer(cwd, config).analyze_shell(command)

    def rule_ids(self, command: str, cwd: str | None = None, config: Config | None = None):
        return {f.rule_id for f in self.decide(command, cwd, config).findings}

    def write(self, rel: str, content: str = "x", base: str | None = None) -> str:
        p = os.path.join(base or self.proj, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as fh:
            fh.write(content)
        return p


GIT_ENV = {
    "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t",
    "GIT_CONFIG_NOSYSTEM": "1",
}


def run_git(cwd: str, *args: str) -> str:
    env = dict(os.environ)
    env.update(GIT_ENV)
    r = subprocess.run(["git", "-C", cwd, *args], capture_output=True, text=True, env=env)
    if r.returncode != 0:
        raise AssertionError(f"git {' '.join(args)} failed: {r.stderr}")
    return r.stdout.strip()


def make_repo(path: str) -> None:
    os.makedirs(path, exist_ok=True)
    run_git(path, "init", "-q", "-b", "main")
    run_git(path, "config", "commit.gpgsign", "false")
