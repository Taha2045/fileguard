import os
import tempfile
import unittest
from pathlib import Path

import fileguard as fg


class TestFileGuard(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        (self.root / "a.txt").write_text("alpha")
        (self.root / "sub").mkdir()
        (self.root / "sub" / "b.conf").write_text("beta")

    def tearDown(self):
        self.tmp.cleanup()

    def _changes(self, baseline):
        return fg.compare(baseline["files"], fg.scan(self.root))

    def test_clean(self):
        b = fg.create_baseline(self.root)
        c = self._changes(b)
        self.assertFalse(any(c.values()))

    def test_modified_added_deleted(self):
        b = fg.create_baseline(self.root)
        (self.root / "a.txt").write_text("tampered")
        (self.root / "new.sh").write_text("#!/bin/sh")
        (self.root / "sub" / "b.conf").unlink()
        c = self._changes(b)
        self.assertEqual(c["modified"], ["a.txt"])
        self.assertEqual(c["added"], ["new.sh"])
        self.assertEqual(c["deleted"], ["sub/b.conf"])

    @unittest.skipIf(os.name == "nt", "POSIX permissions only")
    def test_permission_change(self):
        b = fg.create_baseline(self.root)
        os.chmod(self.root / "a.txt", 0o777)
        c = self._changes(b)
        self.assertEqual(c["permissions"][0][0], "a.txt")

    def test_exclude(self):
        (self.root / "debug.log").write_text("x")
        b = fg.create_baseline(self.root, exclude=["*.log"])
        self.assertNotIn("debug.log", b["files"])

    def test_hmac_detects_baseline_tampering(self):
        b = fg.create_baseline(self.root, key="secret")
        fg.verify_baseline(b, "secret")  # valid -> no exception
        b["files"]["a.txt"]["sha256"] = "0" * 64  # attacker edits the baseline
        with self.assertRaises(fg.BaselineError):
            fg.verify_baseline(b, "secret")

    def test_wrong_key_rejected(self):
        b = fg.create_baseline(self.root, key="secret")
        with self.assertRaises(fg.BaselineError):
            fg.verify_baseline(b, "other")

    def test_cli_exit_codes(self):
        bl = self.root.parent / "bl_test.json"
        os.environ.pop("FILEGUARD_KEY", None)
        self.assertEqual(fg.main(["init", str(self.root), "-b", str(bl)]), 0)
        self.assertEqual(fg.main(["check", str(self.root), "-b", str(bl)]), 0)
        (self.root / "a.txt").write_text("changed")
        self.assertEqual(fg.main(["check", str(self.root), "-b", str(bl)]), 1)
        bl.unlink()


if __name__ == "__main__":
    unittest.main()
