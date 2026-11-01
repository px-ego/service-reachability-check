from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class HandoffPackageTests(unittest.TestCase):
    def test_builder_creates_sanitized_allowlisted_archive(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "handoff.zip"
            completed = subprocess.run(
                [
                    sys.executable,
                    "tools/build_handoff_zip.py",
                    "--output",
                    str(output),
                ],
                cwd=PROJECT_ROOT,
                check=True,
                capture_output=True,
                encoding="utf-8",
                text=True,
            )
            result = json.loads(completed.stdout)
            self.assertTrue(result["success"])
            self.assertTrue(output.is_file())

            with zipfile.ZipFile(output) as archive:
                names = sorted(
                    info.filename
                    for info in archive.infolist()
                    if not info.is_dir()
                )
                roots = {name.split("/", 1)[0] for name in names}
                self.assertEqual(
                    roots,
                    {
                        "service-reachability-check",
                        "service-reachability-dispatch",
                    },
                )
                self.assertIn(
                    "service-reachability-check/config/default.yaml",
                    names,
                )
                self.assertIn(
                    "service-reachability-check/config/alert_routes.yaml",
                    names,
                )
                self.assertIn(
                    "service-reachability-check/.env.example",
                    names,
                )
                self.assertIn(
                    "service-reachability-dispatch/plugin.yaml",
                    names,
                )
                self.assertNotIn(
                    "service-reachability-check/.env",
                    names,
                )
                self.assertFalse(
                    any(
                        forbidden in name.split("/")
                        for name in names
                        for forbidden in (
                            ".tmp",
                            ".pytest_cache",
                            "__pycache__",
                        )
                    )
                )
                self.assertFalse(
                    any(name.endswith((".pyc", ".png", ".zip")) for name in names)
                )
                self.assertEqual(
                    archive.read(
                        "service-reachability-check/config/default.yaml"
                    ),
                    archive.read(
                        "service-reachability-check/config/default.example.yaml"
                    ),
                )
                self.assertEqual(
                    archive.read(
                        "service-reachability-check/config/alert_routes.yaml"
                    ),
                    archive.read(
                        "service-reachability-check/config/alert_routes.example.yaml"
                    ),
                )


if __name__ == "__main__":
    unittest.main()
