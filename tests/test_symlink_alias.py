"""A config path pattern must hit whether a tool names the file by its real path or through a symlinked alias.

macOS reports the working directory as /private/var/... while temp paths are spelled /var/..., which made a relative
protected_paths pattern miss (CFG-011 on macOS CI)."""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from kneepad.engine import Analyzer  # noqa: E402
from kneepad.config import Config  # noqa: E402


@unittest.skipIf(os.name == "nt", "POSIX symlinks")
class SymlinkAlias(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.real = os.path.realpath(os.path.join(self.tmp, "real"))
        os.makedirs(os.path.join(self.real, "secrets"))
        self.alias = os.path.join(self.tmp, "alias")
        os.symlink(self.real, self.alias)

    def _az(self, cwd, **kw):
        cfg = Config()
        for k, v in kw.items():
            setattr(cfg, k, v)
        return Analyzer(config=cfg, cwd=cwd)

    def test_protected_pattern_hits_via_alias_when_cwd_is_real(self):
        d = self._az(self.real, protected_paths=["secrets"]).analyze_write_path(os.path.join(self.alias, "secrets", "a.txt"))
        self.assertNotEqual(d.action, "allow", d)

    def test_protected_pattern_hits_via_real_when_cwd_is_alias(self):
        d = self._az(self.alias, protected_paths=["secrets"]).analyze_write_path(os.path.join(self.real, "secrets", "a.txt"))
        self.assertNotEqual(d.action, "allow", d)

    def test_unrelated_path_still_allowed(self):
        d = self._az(self.real, protected_paths=["secrets"]).analyze_write_path(os.path.join(self.alias, "other", "a.txt"))
        self.assertEqual(d.action, "allow", d)

    def test_allow_write_paths_via_alias(self):
        d = self._az(self.real, allow_write_paths=["."]).analyze_write_path(os.path.join(self.alias, ".env"))
        self.assertEqual(d.action, "allow", d)


if __name__ == "__main__":
    unittest.main()
