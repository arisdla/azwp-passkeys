#!/usr/bin/env python3
"""Regression tests for packaging boundaries and reproducibility."""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parent.parent


class ReleaseBuilder(unittest.TestCase):
    def test_normalization_and_dependency_demo_exclusion(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            first = base / "first"
            first.mkdir()
            for name in ["azwp-passkeys.php", "autoload.php", "uninstall.php", "LICENSE", "README.md",
                         "composer.json", "composer.lock"]:
                (first / name).write_text("fixture\n")
            for name in ["src", "assets", "views", "languages", "data", "watchdog", "vendor"]:
                (first / name).mkdir()
                (first / name / "fixture.txt").write_text("fixture\n")
            demo = first / "vendor/lbuchs/webauthn/_test"
            demo.mkdir(parents=True)
            (demo / "server.php").write_text("<?php echo 'do not ship';")
            second = base / "second"
            shutil.copytree(first, second)
            for path in second.rglob("*"):
                if path.is_file():
                    path.chmod(0o600)
                    os.utime(path, (1700000000, 1700000000))
            for stage in [first, second]:
                subprocess.run([sys.executable, "-I", str(ROOT / "bin/zip-release.py"), str(stage),
                                str(stage.with_suffix(".zip")), "1700000001"], check=True)
            self.assertEqual(first.with_suffix(".zip").read_bytes(), second.with_suffix(".zip").read_bytes())
            with zipfile.ZipFile(first.with_suffix(".zip")) as archive:
                self.assertNotIn("azwp-passkeys/vendor/lbuchs/webauthn/_test/server.php", archive.namelist())
            shutil.rmtree(first / "assets")
            (first / "assets").symlink_to(second / "assets", target_is_directory=True)
            result = subprocess.run([sys.executable, "-I", str(ROOT / "bin/zip-release.py"), str(first),
                                     str(base / "unsafe.zip"), "1700000001"], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Release symlinks are not allowed", result.stderr)

    def test_archive_validation_survives_python_optimization(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "invalid.zip"
            with zipfile.ZipFile(archive, "w") as output:
                output.writestr("azwp-passkeys/.env", "must not ship")
            result = subprocess.run([sys.executable, str(ROOT / "tests/release.py"), str(archive)],
                                    env={**os.environ, "PYTHONOPTIMIZE": "1"}, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Missing azwp-passkeys.php", result.stderr)


if __name__ == "__main__":
    unittest.main()
