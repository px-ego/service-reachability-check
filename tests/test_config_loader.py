from __future__ import annotations

import copy
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts.config_loader import ConfigError, load_config


PROJECT_ROOT = Path(__file__).resolve().parents[1]
EXAMPLE_CONFIG = PROJECT_ROOT / "config" / "default.example.yaml"
EXAMPLE_ROUTES = PROJECT_ROOT / "config" / "alert_routes.example.yaml"


class ConfigLoaderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.owner_env = mock.patch.dict(
            os.environ,
            {
                "SERVICE_REACHABILITY_FEISHU_OWNER_OPEN_ID": "ou_test_owner",
            },
            clear=False,
        )
        self.owner_env.start()

    def tearDown(self) -> None:
        self.owner_env.stop()

    def test_example_config_loads(self) -> None:
        loaded = load_config(config_path=EXAMPLE_CONFIG, routes_path=EXAMPLE_ROUTES)

        self.assertEqual(loaded.config["probes"]["retry_count"], 3)
        self.assertGreaterEqual(len(loaded.routes["routes"]), 1)
        self.assertTrue(loaded.routes["routes"][0]["id"])
        self.assertTrue(
            loaded.routes["routes"][0]["owners"][0]["feishu_user_id"]
        )
        self.assertEqual(
            loaded.summary()["routes"]["count"],
            len(loaded.routes["routes"]),
        )

    def test_skill_contract_contains_no_environment_specific_identifiers(self) -> None:
        text = (PROJECT_ROOT / "SKILL.md").read_text(encoding="utf-8")

        self.assertIsNone(
            re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text),
        )
        self.assertIsNone(re.search(r"[A-Za-z]:\\", text))
        self.assertNotIn("ou_", text)
        self.assertNotIn("真实测试环境", text)

    def test_summary_json_command_does_not_print_secret_values(self) -> None:
        env = os.environ.copy()
        env["FEISHU_WEBHOOK_URL"] = "https://example.invalid/secret-webhook"
        env["FEISHU_SECRET"] = "super-secret-value"

        completed = subprocess.run(
            [
                sys.executable,
                "scripts/service_reachability_check.py",
                "--config",
                str(EXAMPLE_CONFIG),
                "--routes",
                str(EXAMPLE_ROUTES),
                "--summary-json",
            ],
            cwd=PROJECT_ROOT,
            check=True,
            capture_output=True,
            encoding="utf-8",
            text=True,
            env=env,
        )

        summary = json.loads(completed.stdout)
        self.assertIn("feishu", summary)
        self.assertTrue(summary["feishu"]["webhook_configured"])
        self.assertTrue(summary["feishu"]["secret_configured"])
        self.assertNotIn("https://example.invalid/secret-webhook", completed.stdout)
        self.assertNotIn("super-secret-value", completed.stdout)

    def test_retry_and_timeout_config_reject_bool_string_zero_and_negative(self) -> None:
        invalid_cases = [
            (("probes", "retry_count"), True),
            (("probes", "retry_count"), "3"),
            (("probes", "retry_count"), 0),
            (("probes", "retry_count"), -1),
            (("probes", "retry_interval_seconds"), True),
            (("probes", "retry_interval_seconds"), "2"),
            (("probes", "retry_interval_seconds"), -1),
            (("probes", "ssh_timeout_seconds"), True),
            (("probes", "ssh_timeout_seconds"), "10"),
            (("probes", "ssh_timeout_seconds"), 0),
            (("probes", "command_timeout_seconds"), True),
            (("probes", "command_timeout_seconds"), "10"),
            (("probes", "command_timeout_seconds"), -1),
            (("diagnosis", "tcp_timeout_seconds"), True),
            (("diagnosis", "tcp_timeout_seconds"), "5"),
            (("diagnosis", "tcp_timeout_seconds"), 0),
            (("diagnosis", "http_timeout_seconds"), True),
            (("diagnosis", "http_timeout_seconds"), "10"),
            (("diagnosis", "http_timeout_seconds"), -1),
            (("diagnosis", "http_success_status"), True),
            (("diagnosis", "http_success_status"), "200"),
            (("diagnosis", "http_success_status"), 0),
        ]

        for path, value in invalid_cases:
            with self.subTest(path=path, value=value):
                config = copy.deepcopy(
                    load_config(config_path=EXAMPLE_CONFIG, routes_path=EXAMPLE_ROUTES).config
                )
                section, key = path
                config[section][key] = value
                self.assert_invalid_default_config(config, key)

    def assert_invalid_default_config(self, config: dict, message: str) -> None:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            suffix=".yaml",
            delete=False,
        ) as file:
            json.dump(config, file, ensure_ascii=False)
            config_path = Path(file.name)

        try:
            with self.assertRaisesRegex(ConfigError, message):
                load_config(config_path=config_path, routes_path=EXAMPLE_ROUTES)
        finally:
            config_path.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
