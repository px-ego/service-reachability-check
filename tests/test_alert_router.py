from __future__ import annotations

import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts.alert_router import resolve_alert_route
from scripts.config_loader import ConfigError, load_config
from scripts.feishu_event_parser import ParsedAlert


PROJECT_ROOT = Path(__file__).resolve().parents[1]
EXAMPLE_CONFIG = PROJECT_ROOT / "config" / "default.example.yaml"
OWNER = {"name": "值班运维", "feishu_user_id": "ou_fallback"}


def parsed_alert(monitor_name: str) -> ParsedAlert:
    return ParsedAlert(
        source_bot="拨测通知机器人",
        status="fault",
        monitor_name=monitor_name,
        reason="Request timeout",
        alert_time="2026-07-07 23:35:20",
        raw_text=f"监控告警: [🔴 故障] {monitor_name}",
    )


def route(
    route_id: str,
    *,
    monitor_name: str | None = None,
    monitor_name_regex: str | None = None,
) -> dict:
    match = {}
    if monitor_name is not None:
        match["monitor_name"] = monitor_name
    if monitor_name_regex is not None:
        match["monitor_name_regex"] = monitor_name_regex
    return {
        "id": route_id,
        "match": match,
        "service_name": f"service-{route_id}",
        "diagnosis": {
            "type": "tcp",
            "host": "service.internal.example",
            "port": 8002,
        },
        "owners": [
            {"name": "运维人员A", "feishu_user_id": "ou_owner_a"},
        ],
    }


def routes_config(*route_items: dict, fallback_owners: list[dict] | None = None) -> dict:
    return {
        "routes": list(route_items),
        "fallback": {
            "owners": fallback_owners if fallback_owners is not None else [],
        },
    }


def normalized_event(text: str) -> dict:
    return {
        "sender_name": "拨测通知机器人",
        "sender_id": "optional-id",
        "sender_type": "bot",
        "text": text,
    }


def subprocess_env() -> dict[str, str]:
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    return env


class AlertRouterTests(unittest.TestCase):
    def test_exact_match_returns_diagnosis_and_owners(self) -> None:
        monitor_name = "示例数据服务｜端口8002"
        config = routes_config(route("data-release", monitor_name=monitor_name))

        result = resolve_alert_route(parsed_alert(monitor_name), config).to_dict()

        self.assertEqual(result["status"], "matched")
        self.assertEqual(result["route"]["id"], "data-release")
        self.assertEqual(result["route"]["match_type"], "exact")
        self.assertEqual(result["route"]["diagnosis"]["port"], 8002)
        self.assertEqual(result["route"]["owners"][0]["feishu_user_id"], "ou_owner_a")
        self.assertEqual(result["alert"]["monitor_name"], monitor_name)

    def test_regex_uses_full_match(self) -> None:
        config = routes_config(
            route(
                "data-release-regex",
                monitor_name_regex=r"示例部门｜.+｜端口\d+",
            )
        )

        matched = resolve_alert_route(
            parsed_alert("示例部门｜数据服务｜端口8002"),
            config,
        ).to_dict()
        not_matched = resolve_alert_route(
            parsed_alert("前缀｜示例部门｜数据服务｜端口8002"),
            config,
        ).to_dict()

        self.assertEqual(matched["route"]["match_type"], "regex")
        self.assertEqual(not_matched["reason"], "route_not_found")

    def test_exact_match_takes_priority_over_regex(self) -> None:
        monitor_name = "示例HTTP服务"
        config = routes_config(
            route("broad-regex", monitor_name_regex=r".*"),
            route("contract-exact", monitor_name=monitor_name),
        )

        result = resolve_alert_route(parsed_alert(monitor_name), config).to_dict()

        self.assertEqual(result["status"], "matched")
        self.assertEqual(result["route"]["id"], "contract-exact")
        self.assertEqual(result["route"]["match_type"], "exact")

    def test_multiple_exact_matches_return_conflict(self) -> None:
        monitor_name = "示例子服务"
        config = routes_config(
            route("route-a", monitor_name=monitor_name),
            route("route-b", monitor_name=monitor_name),
            fallback_owners=[OWNER],
        )

        result = resolve_alert_route(parsed_alert(monitor_name), config).to_dict()

        self.assertEqual(result["status"], "error")
        self.assertEqual(result["reason"], "route_conflict")
        self.assertEqual(result["matched_route_ids"], ["route-a", "route-b"])
        self.assertEqual(result["fallback_owners"], [OWNER])
        self.assertNotIn("route", result)

    def test_multiple_regex_matches_return_conflict(self) -> None:
        config = routes_config(
            route("route-a", monitor_name_regex=r"示例.*"),
            route("route-b", monitor_name_regex=r".*子服务"),
            fallback_owners=[OWNER],
        )

        result = resolve_alert_route(parsed_alert("示例子服务"), config).to_dict()

        self.assertEqual(result["reason"], "route_conflict")
        self.assertEqual(result["matched_route_ids"], ["route-a", "route-b"])
        self.assertEqual(result["fallback_owners"], [OWNER])

    def test_missing_route_returns_fallback_owners(self) -> None:
        result = resolve_alert_route(
            parsed_alert("未配置服务"),
            routes_config(fallback_owners=[OWNER]),
        ).to_dict()

        self.assertEqual(result["status"], "error")
        self.assertEqual(result["reason"], "route_not_found")
        self.assertEqual(result["fallback_owners"], [OWNER])
        self.assertEqual(result["alert"]["monitor_name"], "未配置服务")

    def test_missing_route_includes_empty_fallback_list(self) -> None:
        result = resolve_alert_route(
            parsed_alert("未配置服务"),
            routes_config(),
        ).to_dict()

        self.assertEqual(result["fallback_owners"], [])


class AlertRouteConfigValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.valid_config = routes_config(
            route("valid-route", monitor_name="服务A"),
            fallback_owners=[OWNER],
        )

    def assert_invalid(self, config: dict, message: str) -> None:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            suffix=".yaml",
            delete=False,
        ) as file:
            json.dump(config, file, ensure_ascii=False)
            routes_path = Path(file.name)

        try:
            with self.assertRaisesRegex(ConfigError, message):
                load_config(config_path=EXAMPLE_CONFIG, routes_path=routes_path)
        finally:
            routes_path.unlink(missing_ok=True)

    def test_valid_exact_and_http_routes_load(self) -> None:
        config = copy.deepcopy(self.valid_config)
        config["routes"].append(
            {
                "id": "valid-http",
                "match": {"monitor_name_regex": r"HTTP 服务 \d+"},
                "service_name": "HTTP service",
                "diagnosis": {
                    "type": "http",
                    "url": "https://service.example/health",
                },
                "owners": [
                    {"name": "运维人员B", "feishu_user_id": "ou_owner_b"},
                ],
            }
        )

        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            suffix=".yaml",
            delete=False,
        ) as file:
            json.dump(config, file, ensure_ascii=False)
            routes_path = Path(file.name)

        try:
            loaded = load_config(config_path=EXAMPLE_CONFIG, routes_path=routes_path)
        finally:
            routes_path.unlink(missing_ok=True)

        self.assertEqual(len(loaded.routes["routes"]), 2)

    def test_route_requires_exactly_one_match_selector(self) -> None:
        both = copy.deepcopy(self.valid_config)
        both["routes"][0]["match"]["monitor_name_regex"] = r".*"
        neither = copy.deepcopy(self.valid_config)
        neither["routes"][0]["match"] = {}

        self.assert_invalid(both, "must define exactly one")
        self.assert_invalid(neither, "must define exactly one")

    def test_invalid_regex_is_rejected(self) -> None:
        config = copy.deepcopy(self.valid_config)
        config["routes"][0]["match"] = {"monitor_name_regex": "["}

        self.assert_invalid(config, "monitor_name_regex is invalid")

    def test_missing_service_name_is_rejected(self) -> None:
        config = copy.deepcopy(self.valid_config)
        config["routes"][0]["service_name"] = "  "

        self.assert_invalid(config, "service_name must be a non-empty string")

    def test_invalid_tcp_ports_are_rejected(self) -> None:
        for port in (0, 65536, "8002", True):
            with self.subTest(port=port):
                config = copy.deepcopy(self.valid_config)
                config["routes"][0]["diagnosis"]["port"] = port

                self.assert_invalid(config, "port must be an integer from 1 to 65535")

    def test_invalid_http_urls_are_rejected(self) -> None:
        for url in ("service.example/health", "ftp://service.example/health"):
            with self.subTest(url=url):
                config = copy.deepcopy(self.valid_config)
                config["routes"][0]["diagnosis"] = {
                    "type": "http",
                    "url": url,
                }

                self.assert_invalid(config, "complete HTTP or HTTPS URL")

    def test_per_perspective_http_and_tcp_targets_load(self) -> None:
        config = copy.deepcopy(self.valid_config)
        config["routes"][0]["diagnosis"] = {
            "type": "http",
            "targets": {
                "internal": {"url": "https://service-internal.example.invalid/health"},
                "external": {"url": "https://service-external.example.invalid/health"},
            },
        }
        config["routes"].append(
            {
                "id": "tcp-targets",
                "match": {"monitor_name": "tcp-service"},
                "service_name": "tcp-service",
                "diagnosis": {
                    "type": "tcp",
                    "targets": {
                        "internal": {
                            "host": "service-internal.example.invalid",
                            "port": 3000,
                        },
                        "external": {
                            "host": "service-external.example.invalid",
                            "port": 3000,
                        },
                    },
                },
                "owners": [
                    {"name": "owner", "feishu_user_id": "ou_owner"},
                ],
            }
        )

        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            suffix=".yaml",
            delete=False,
        ) as file:
            json.dump(config, file, ensure_ascii=False)
            routes_path = Path(file.name)

        try:
            loaded = load_config(config_path=EXAMPLE_CONFIG, routes_path=routes_path)
        finally:
            routes_path.unlink(missing_ok=True)

        self.assertEqual(len(loaded.routes["routes"]), 2)

    def test_per_perspective_targets_reject_missing_invalid_and_mixed_fields(self) -> None:
        cases = [
            (
                {
                    "type": "http",
                    "url": "http://shared.example/health",
                    "targets": {
                        "internal": {"url": "http://internal.example/health"},
                        "external": {"url": "http://external.example/health"},
                    },
                },
                "cannot define shared url",
            ),
            (
                {
                    "type": "http",
                    "targets": {
                        "internal": {"url": "http://internal.example/health"},
                    },
                },
                r"targets\.external must be a mapping",
            ),
            (
                {
                    "type": "http",
                    "targets": {
                        "internal": {"url": "internal.example/health"},
                        "external": {"url": "http://external.example/health"},
                    },
                },
                "complete HTTP or HTTPS URL",
            ),
            (
                {
                    "type": "tcp",
                    "host": "shared.example",
                    "port": 3000,
                    "targets": {
                        "internal": {
                            "host": "service-internal.example.invalid",
                            "port": 3000,
                        },
                        "external": {
                            "host": "service-external.example.invalid",
                            "port": 3000,
                        },
                    },
                },
                "cannot define shared host, port",
            ),
            (
                {
                    "type": "tcp",
                    "targets": {
                        "internal": {
                            "host": "service-internal.example.invalid",
                            "port": True,
                        },
                        "external": {
                            "host": "service-external.example.invalid",
                            "port": 3000,
                        },
                    },
                },
                "port must be an integer from 1 to 65535",
            ),
        ]

        for diagnosis, message in cases:
            with self.subTest(diagnosis=diagnosis):
                config = copy.deepcopy(self.valid_config)
                config["routes"][0]["diagnosis"] = diagnosis

                self.assert_invalid(config, message)

    def test_route_owner_requires_name_and_feishu_user_id(self) -> None:
        missing_name = copy.deepcopy(self.valid_config)
        missing_name["routes"][0]["owners"] = [
            {"name": "", "feishu_user_id": "ou_owner"}
        ]
        missing_id = copy.deepcopy(self.valid_config)
        missing_id["routes"][0]["owners"] = [{"name": "运维人员"}]

        self.assert_invalid(missing_name, r"owners\[0\]\.name")
        self.assert_invalid(missing_id, r"owners\[0\]\.feishu_user_id")

    def test_fallback_owner_uses_same_validation(self) -> None:
        config = copy.deepcopy(self.valid_config)
        config["fallback"]["owners"] = [{"name": "值班运维"}]

        self.assert_invalid(config, r"fallback\.owners\[0\]\.feishu_user_id")

    def test_owner_environment_reference_resolves_to_existing_shape(self) -> None:
        config = copy.deepcopy(self.valid_config)
        config["routes"][0]["owners"] = [
            {
                "name": "环境变量负责人",
                "feishu_user_id_env": "TEST_FEISHU_OWNER_ID",
            }
        ]

        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            suffix=".yaml",
            delete=False,
        ) as file:
            json.dump(config, file, ensure_ascii=False)
            routes_path = Path(file.name)

        try:
            with mock.patch.dict(
                os.environ,
                {"TEST_FEISHU_OWNER_ID": "ou_environment_owner"},
            ):
                loaded = load_config(config_path=EXAMPLE_CONFIG, routes_path=routes_path)
        finally:
            routes_path.unlink(missing_ok=True)

        self.assertEqual(
            loaded.routes["routes"][0]["owners"],
            [
                {
                    "name": "环境变量负责人",
                    "feishu_user_id": "ou_environment_owner",
                }
            ],
        )

    def test_owner_environment_reference_must_be_configured(self) -> None:
        config = copy.deepcopy(self.valid_config)
        config["routes"][0]["owners"] = [
            {
                "name": "环境变量负责人",
                "feishu_user_id_env": "TEST_MISSING_FEISHU_OWNER_ID",
            }
        ]

        with mock.patch.dict(os.environ, {}, clear=True):
            self.assert_invalid(config, "is not configured")

    def test_owner_rejects_literal_and_environment_reference_together(self) -> None:
        config = copy.deepcopy(self.valid_config)
        config["routes"][0]["owners"] = [
            {
                "name": "冲突负责人",
                "feishu_user_id": "ou_literal_owner",
                "feishu_user_id_env": "TEST_FEISHU_OWNER_ID",
            }
        ]

        self.assert_invalid(config, "must define exactly one")


class AlertRouteCliTests(unittest.TestCase):
    def run_cli(
        self,
        config: dict,
        raw_event: dict,
        *,
        stdin: bool,
    ) -> dict:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            suffix=".yaml",
            delete=False,
        ) as routes_file:
            json.dump(config, routes_file, ensure_ascii=False)
            routes_path = Path(routes_file.name)

        event_path: Path | None = None
        command = [
            sys.executable,
            "scripts/service_reachability_check.py",
            "--config",
            str(EXAMPLE_CONFIG),
            "--routes",
            str(routes_path),
            "--resolve-event-json",
            "-",
        ]
        input_payload = json.dumps(raw_event, ensure_ascii=False)

        if not stdin:
            with tempfile.NamedTemporaryFile(
                "w",
                encoding="utf-8",
                suffix=".json",
                delete=False,
            ) as event_file:
                json.dump(raw_event, event_file, ensure_ascii=False)
                event_path = Path(event_file.name)
            command[-1] = str(event_path)
            input_payload = None

        try:
            completed = subprocess.run(
                command,
                cwd=PROJECT_ROOT,
                input=input_payload,
                check=True,
                capture_output=True,
                encoding="utf-8",
                text=True,
                env=subprocess_env(),
            )
        finally:
            routes_path.unlink(missing_ok=True)
            if event_path is not None:
                event_path.unlink(missing_ok=True)

        return json.loads(completed.stdout)

    def test_resolve_event_json_file_returns_matched_route(self) -> None:
        monitor_name = "示例数据服务｜端口8002"
        raw_event = normalized_event(
            f"监控告警: [🔴 故障] {monitor_name}\n\n"
            "[发生故障] Request timeout\n"
            "告警时间: 2026-07-07 23:35:20"
        )

        result = self.run_cli(
            routes_config(route("data-release", monitor_name=monitor_name)),
            raw_event,
            stdin=False,
        )

        self.assertEqual(result["status"], "matched")
        self.assertEqual(result["route"]["id"], "data-release")

    def test_resolve_event_json_stdin_returns_missing_route(self) -> None:
        raw_event = normalized_event(
            "监控告警: [🔴 故障] 未配置服务\n\n"
            "[发生故障] Request timeout\n"
            "告警时间: 2026-07-07 23:35:20"
        )

        result = self.run_cli(
            routes_config(fallback_owners=[OWNER]),
            raw_event,
            stdin=True,
        )

        self.assertEqual(result["reason"], "route_not_found")
        self.assertEqual(
            result["fallback_owners"],
            [{"name": OWNER["name"], "feishu_user_id": "[redacted]"}],
        )

    def test_recovered_alert_is_returned_before_route_resolution(self) -> None:
        raw_event = normalized_event(
            "监控告警: [✅ 正常] 服务A\n\n"
            "[恢复正常] 200 -\n"
            "告警时间: 2026-07-07 23:35:20"
        )

        result = self.run_cli(routes_config(), raw_event, stdin=True)

        self.assertEqual(result, {"status": "ignored", "reason": "recovered_alert"})

    def test_title_only_fault_is_resolved_before_probe_execution(self) -> None:
        raw_event = normalized_event(
            "监控告警: [🔴 故障] 服务A\n\n"
            "[发生故障] Request timeout"
        )

        result = self.run_cli(
            routes_config(route("service-a", monitor_name="服务A")),
            raw_event,
            stdin=True,
        )

        self.assertEqual(result["status"], "matched")
        self.assertEqual(result["route"]["id"], "service-a")
        self.assertEqual(result["alert"]["alert_time"], "")


if __name__ == "__main__":
    unittest.main()
