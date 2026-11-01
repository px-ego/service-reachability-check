from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts.feishu_event_parser import parse_feishu_event


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def subprocess_env() -> dict[str, str]:
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    env["SERVICE_REACHABILITY_FEISHU_OWNER_OPEN_ID"] = "ou_test_owner"
    return env


def event(text: str, sender_name: str = "拨测通知机器人") -> dict:
    return {
        "sender_name": sender_name,
        "sender_id": "optional-id",
        "sender_type": "bot",
        "text": text,
    }


class FeishuEventParserTests(unittest.TestCase):
    def setUp(self) -> None:
        self.feishu_config = {
            "alert_bot": {
                "allowed_names": ["拨测通知机器人"],
                "allowed_sender_id_env": "SERVICE_REACHABILITY_ALERT_BOT_ID",
                "self_names": ["Hermes", "service-reachability-check"],
            }
        }

    def test_fault_alert_parses_structured_fields(self) -> None:
        raw_text = (
            "监控告警: [🔴 故障] 示例数据服务｜端口8002\n\n"
            "[发生故障] Request timeout\n"
            "告警时间: 2026-07-07 23:35:20"
        )

        result = parse_feishu_event(event(raw_text), self.feishu_config)

        self.assertEqual(result.status, "parsed")
        self.assertIsNotNone(result.alert)
        assert result.alert is not None
        self.assertEqual(result.alert.source_bot, "拨测通知机器人")
        self.assertEqual(result.alert.status, "fault")
        self.assertEqual(result.alert.monitor_name, "示例数据服务｜端口8002")
        self.assertEqual(result.alert.reason, "Request timeout")
        self.assertEqual(result.alert.alert_time, "2026-07-07 23:35:20")
        self.assertEqual(result.alert.raw_text, raw_text)

    def test_screenshot_reason_shapes_are_extracted(self) -> None:
        cases = [
            ("示例HTTP服务", "Request failed with status code 502"),
            ("示例子服务", "Child inaccessible"),
            ("示例数据服务｜端口8002", "Request timeout"),
        ]

        for monitor_name, reason in cases:
            with self.subTest(reason=reason):
                raw_text = (
                    f"监控告警: [🔴 故障] {monitor_name}\n\n"
                    f"[发生故障] {reason}\n"
                    "告警时间: 2026-07-05 11:49:45"
                )

                result = parse_feishu_event(event(raw_text), self.feishu_config)

                self.assertEqual(result.status, "parsed")
                self.assertIsNotNone(result.alert)
                assert result.alert is not None
                self.assertEqual(result.alert.monitor_name, monitor_name)
                self.assertEqual(result.alert.reason, reason)

    def test_recovered_alert_is_ignored(self) -> None:
        raw_text = (
            "监控告警: [✅ 正常] 示例HTTP服务\n\n"
            "[恢复正常] 200 -\n"
            "告警时间: 2026-07-05 12:14:46"
        )

        result = parse_feishu_event(event(raw_text), self.feishu_config)

        self.assertEqual(result.to_dict(), {"status": "ignored", "reason": "recovered_alert"})

    def test_non_alert_bot_is_ignored(self) -> None:
        raw_text = (
            "监控告警: [🔴 故障] 示例HTTP服务\n\n"
            "[发生故障] Request timeout\n"
            "告警时间: 2026-07-05 11:49:45"
        )

        result = parse_feishu_event(event(raw_text, sender_name="其他机器人"), self.feishu_config)

        self.assertEqual(result.to_dict(), {"status": "ignored", "reason": "non_alert_bot"})

    def test_human_message_is_ignored(self) -> None:
        raw_text = (
            "监控告警: [🔴 故障] 示例HTTP服务\n\n"
            "[发生故障] Request timeout\n"
            "告警时间: 2026-07-05 11:49:45"
        )
        raw_event = event(raw_text, sender_name="张三")
        raw_event["sender_type"] = "user"

        result = parse_feishu_event(raw_event, self.feishu_config)

        self.assertEqual(result.to_dict(), {"status": "ignored", "reason": "non_alert_bot"})

    def test_self_message_is_ignored(self) -> None:
        raw_text = (
            "监控告警: [🔴 故障] 示例HTTP服务\n\n"
            "[发生故障] Request timeout\n"
            "告警时间: 2026-07-05 11:49:45"
        )

        result = parse_feishu_event(event(raw_text, sender_name="Hermes"), self.feishu_config)

        self.assertEqual(result.to_dict(), {"status": "ignored", "reason": "self_message"})

    def test_non_alert_format_is_ignored(self) -> None:
        raw_text = (
            "普通聊天消息\n\n"
            "[发生故障] Request timeout\n"
            "告警时间: 2026-07-05 11:49:45"
        )

        result = parse_feishu_event(event(raw_text), self.feishu_config)

        self.assertEqual(result.to_dict(), {"status": "ignored", "reason": "non_alert_format"})

    def test_title_only_fault_parses_with_missing_fields(self) -> None:
        raw_text = (
            "监控告警: [🔴 故障] 示例HTTP服务\n\n"
            "[发生故障] Request timeout"
        )

        result = parse_feishu_event(event(raw_text), self.feishu_config)

        self.assertEqual(result.status, "parsed")
        self.assertIsNotNone(result.alert)
        assert result.alert is not None
        self.assertEqual(result.alert.alert_time, "")
        self.assertEqual(result.alert.reason, "Request timeout")

    def test_sender_id_can_authorize_bot_when_name_is_unavailable(self) -> None:
        raw_event = event(
            "监控告警: [🔴 故障] 示例网关",
            sender_name="",
        )
        raw_event["sender_id"] = "ou_alert_bot"
        config = {
            **self.feishu_config,
            "alert_bot": {
                **self.feishu_config["alert_bot"],
                "allowed_sender_id_env": "TEST_ALERT_BOT_ID",
            },
        }

        with mock.patch.dict(
            os.environ,
            {"TEST_ALERT_BOT_ID": "ou_alert_bot"},
            clear=False,
        ):
            result = parse_feishu_event(raw_event, config)

        self.assertEqual(result.status, "parsed")
        self.assertIsNotNone(result.alert)
        assert result.alert is not None
        self.assertEqual(result.alert.monitor_name, "示例网关")
        self.assertEqual(result.alert.reason, "")
        self.assertEqual(result.alert.alert_time, "")

    def test_fault_without_reason_parses_empty_reason(self) -> None:
        raw_text = (
            "监控告警: [🔴 故障] 示例HTTP服务\n\n"
            "告警时间: 2026-07-05 11:49:45"
        )

        result = parse_feishu_event(event(raw_text), self.feishu_config)

        self.assertEqual(result.status, "parsed")
        self.assertIsNotNone(result.alert)
        assert result.alert is not None
        self.assertEqual(result.alert.reason, "")


class FeishuEventCliTests(unittest.TestCase):
    def test_event_json_file_outputs_parse_result(self) -> None:
        raw_event = event(
            "监控告警: [🔴 故障] 示例子服务\n\n"
            "[发生故障] Child inaccessible\n"
            "告警时间: 2026-07-05 11:49:48"
        )

        with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".json", delete=False) as file:
            json.dump(raw_event, file, ensure_ascii=False)
            event_path = Path(file.name)

        try:
            completed = subprocess.run(
                [
                    sys.executable,
                    "scripts/service_reachability_check.py",
                    "--config",
                    "config/default.example.yaml",
                    "--routes",
                    "config/alert_routes.example.yaml",
                    "--event-json",
                    str(event_path),
                ],
                cwd=PROJECT_ROOT,
                check=True,
                capture_output=True,
                encoding="utf-8",
                text=True,
                env=subprocess_env(),
            )
        finally:
            event_path.unlink(missing_ok=True)

        payload = json.loads(completed.stdout)
        self.assertEqual(payload["status"], "parsed")
        self.assertEqual(payload["alert"]["monitor_name"], "示例子服务")
        self.assertEqual(payload["alert"]["reason"], "Child inaccessible")

    def test_event_json_stdin_outputs_parse_result(self) -> None:
        raw_event = event(
            "监控告警: [🔴 故障] 示例HTTP服务\n\n"
            "[发生故障] Request failed with status code 502\n"
            "告警时间: 2026-07-05 11:49:45"
        )

        completed = subprocess.run(
            [
                sys.executable,
                "scripts/service_reachability_check.py",
                "--config",
                "config/default.example.yaml",
                "--routes",
                "config/alert_routes.example.yaml",
                "--event-json",
                "-",
            ],
            cwd=PROJECT_ROOT,
            input=json.dumps(raw_event, ensure_ascii=False),
            check=True,
            capture_output=True,
            encoding="utf-8",
            text=True,
            env=subprocess_env(),
        )

        payload = json.loads(completed.stdout)
        self.assertEqual(payload["status"], "parsed")
        self.assertEqual(payload["alert"]["reason"], "Request failed with status code 502")

    def test_event_json_stdin_accepts_utf8_bom(self) -> None:
        raw_event = event(
            "监控告警: [🔴 故障] 示例网关\n\n"
            "[发生故障] PowerShell UTF-8 pipeline\n"
            "告警时间: 2026-07-20 16:30:00"
        )

        completed = subprocess.run(
            [
                sys.executable,
                "scripts/service_reachability_check.py",
                "--config",
                "config/default.example.yaml",
                "--routes",
                "config/alert_routes.example.yaml",
                "--event-json",
                "-",
            ],
            cwd=PROJECT_ROOT,
            input="\ufeff" + json.dumps(raw_event, ensure_ascii=False),
            check=True,
            capture_output=True,
            encoding="utf-8",
            text=True,
            env=subprocess_env(),
        )

        payload = json.loads(completed.stdout)
        self.assertEqual(payload["status"], "parsed")
        self.assertEqual(payload["alert"]["monitor_name"], "示例网关")


if __name__ == "__main__":
    unittest.main()
