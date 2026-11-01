from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

from scripts.feishu_notify import FeishuSendResult
from scripts.manual_diagnosis_pipeline import run_manual_diagnosis
from scripts.probe_executor import CommandExecutionResult, RemoteCommand
from scripts.service_reachability_check import main


OWNER = {"name": "手动测试负责人", "feishu_user_id": "ou_test_manual_owner"}


class FakeRunner:
    def __init__(self, results: dict[str, list[CommandExecutionResult]]) -> None:
        self.results = {key: list(value) for key, value in results.items()}
        self.calls: list[tuple[dict[str, Any], RemoteCommand]] = []

    def run(
        self,
        probe_config: dict[str, Any],
        command: RemoteCommand,
    ) -> CommandExecutionResult:
        self.calls.append((dict(probe_config), command))
        return self.results[probe_config["perspective"]].pop(0)


def event(
    *,
    sender_name: str = "拨测通知机器人",
    text: str | None = None,
) -> dict[str, str]:
    return {
        "sender_name": sender_name,
        "sender_id": "manual-test",
        "sender_type": "bot",
        "text": text
        or (
            "监控告警: [🔴 故障] 示例HTTP服务\n\n"
            "[发生故障] Manual chain test\n"
            "告警时间: 2026-07-16 10:00:00"
        ),
    }


def config() -> dict[str, Any]:
    return {
        "runtime": {
            "dry_run": True,
            "alert_routes_path": "config/alert_routes.yaml",
        },
        "feishu": {
            "enabled": False,
            "webhook_env": "FEISHU_WEBHOOK_URL",
            "secret_env": "FEISHU_SECRET",
            "alert_bot": {
                "allowed_names": ["拨测通知机器人"],
                "self_names": ["Hermes", "service-reachability-check"],
            },
        },
        "probes": {
            "retry_count": 1,
            "retry_interval_seconds": 0,
            "ssh_timeout_seconds": 10,
            "command_timeout_seconds": 10,
            "internal": {
                "name": "internal-probe",
                "host": "internal-probe.example",
                "port": 22,
                "user": "probe",
                "key_path_env": "INTERNAL_PROBE_SSH_KEY_PATH",
            },
            "external": {
                "name": "external-probe",
                "host": "external-probe.example",
                "port": 22,
                "user": "probe",
                "key_path_env": "EXTERNAL_PROBE_SSH_KEY_PATH",
            },
        },
        "diagnosis": {
            "tcp_timeout_seconds": 5,
            "http_timeout_seconds": 10,
            "http_success_status": 200,
        },
    }


def routes_config() -> dict[str, Any]:
    return {
        "routes": [
            {
                "id": "llm-gateway-test",
                "match": {"monitor_name": "示例HTTP服务"},
                "service_name": "示例 HTTP 服务",
                "diagnosis": {
                    "type": "http",
                    "targets": {
                        "internal": {"url": "https://service.example.invalid/health"},
                        "external": {"url": "https://service.example.invalid/health"},
                    },
                },
                "owners": [OWNER],
            }
        ],
        "fallback": {"owners": [OWNER]},
    }


def ok(status_code: str = "200") -> CommandExecutionResult:
    return CommandExecutionResult(exit_code=0, stdout=status_code)


class ManualDiagnosisPipelineTests(unittest.TestCase):
    def test_normal_result_runs_both_perspectives_and_does_not_send(self) -> None:
        runner = FakeRunner({"internal": [ok()], "external": [ok()]})

        result = run_manual_diagnosis(
            event=event(),
            config=config(),
            routes_config=routes_config(),
            runner=runner,
        )

        self.assertEqual(result["status"], "normal")
        self.assertFalse(result["should_notify"])
        self.assertEqual(result["notification"]["should_send"], False)
        self.assertEqual(result["send_result"]["reason"], "send_not_requested")
        self.assertEqual(
            runner.calls[0][1].argv[-1],
            "https://service.example.invalid/health",
        )
        self.assertEqual(
            runner.calls[1][1].argv[-1],
            "https://service.example.invalid/health",
        )

    def test_abnormal_result_builds_notification_payload_without_sending_by_default(self) -> None:
        runner = FakeRunner({"internal": [ok()], "external": [ok("502")]})

        result = run_manual_diagnosis(
            event=event(),
            config=config(),
            routes_config=routes_config(),
            runner=runner,
        )

        self.assertEqual(result["status"], "abnormal")
        self.assertTrue(result["should_notify"])
        self.assertEqual(result["classification"], "external_path_issue_likely")
        self.assertTrue(result["notification"]["should_send"])
        self.assertEqual(result["notification"]["payload"]["msg_type"], "interactive")
        self.assertEqual(result["send_result"]["reason"], "send_not_requested")

    def test_send_feishu_sends_only_when_sendable_payload_exists(self) -> None:
        runner = FakeRunner({"internal": [ok()], "external": [ok("502")]})
        sent_payloads: list[dict[str, Any]] = []

        def sender(payload: dict[str, Any], _feishu_config: dict[str, Any]) -> FeishuSendResult:
            sent_payloads.append(payload)
            return FeishuSendResult(success=True, reason="sent", status_code=200)

        result = run_manual_diagnosis(
            event=event(),
            config=config(),
            routes_config=routes_config(),
            runner=runner,
            send_feishu=True,
            sender=sender,
        )

        self.assertEqual(result["send_result"]["reason"], "sent")
        self.assertEqual(len(sent_payloads), 1)

    def test_route_not_found_returns_route_error_and_does_not_probe(self) -> None:
        runner = FakeRunner({"internal": [ok()], "external": [ok()]})

        result = run_manual_diagnosis(
            event=event(),
            config=config(),
            routes_config={"routes": [], "fallback": {"owners": [OWNER]}},
            runner=runner,
        )

        self.assertEqual(result["status"], "error")
        self.assertEqual(result["reason"], "route_not_found")
        self.assertTrue(result["notification"]["should_send"])
        self.assertEqual(runner.calls, [])

    def test_parse_ignored_result_returns_before_route_and_probe(self) -> None:
        runner = FakeRunner({"internal": [ok()], "external": [ok()]})

        result = run_manual_diagnosis(
            event=event(sender_name="其他机器人"),
            config=config(),
            routes_config=routes_config(),
            runner=runner,
        )

        self.assertEqual(result, {"status": "ignored", "reason": "non_alert_bot"})
        self.assertEqual(runner.calls, [])


class ManualDiagnosisCliTests(unittest.TestCase):
    def test_diagnose_event_json_cli_uses_runner_and_outputs_result(self) -> None:
        runner = FakeRunner({"internal": [ok()], "external": [ok()]})
        with temporary_json_file(config()) as config_path:
            with temporary_json_file(routes_config()) as routes_path:
                with temporary_json_file(event()) as event_path:
                    stdout = io.StringIO()
                    with mock.patch(
                        "scripts.service_reachability_check.ParamikoSSHCommandRunner",
                        return_value=runner,
                    ):
                        with contextlib.redirect_stdout(stdout):
                            exit_code = main(
                                [
                                    "--config",
                                    str(config_path),
                                    "--routes",
                                    str(routes_path),
                                    "--diagnose-event-json",
                                    str(event_path),
                                ]
                            )

        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["status"], "normal")
        self.assertFalse(payload["should_notify"])
        self.assertEqual(len(runner.calls), 2)

    def test_hermes_event_json_normal_result_does_not_send(self) -> None:
        runner = FakeRunner({"internal": [ok()], "external": [ok()]})
        with temporary_json_file(config()) as config_path:
            with temporary_json_file(routes_config()) as routes_path:
                with temporary_json_file(event()) as event_path:
                    stdout = io.StringIO()
                    with mock.patch(
                        "scripts.service_reachability_check.ParamikoSSHCommandRunner",
                        return_value=runner,
                    ), mock.patch(
                        "scripts.manual_diagnosis_pipeline.feishu_notify.send_diagnostic_message"
                    ) as sender:
                        with contextlib.redirect_stdout(stdout):
                            exit_code = main(
                                [
                                    "--config",
                                    str(config_path),
                                    "--routes",
                                    str(routes_path),
                                    "--hermes-event-json",
                                    str(event_path),
                                ]
                            )

        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["status"], "normal")
        self.assertFalse(payload["should_notify"])
        self.assertEqual(payload["send_result"]["reason"], "no_sendable_payload")
        sender.assert_not_called()
        self.assertEqual(len(runner.calls), 2)

    def test_hermes_event_json_abnormal_result_sends_once(self) -> None:
        runner = FakeRunner({"internal": [ok()], "external": [ok("502")]})
        with temporary_json_file(config()) as config_path:
            with temporary_json_file(routes_config()) as routes_path:
                with temporary_json_file(event()) as event_path:
                    stdout = io.StringIO()
                    with mock.patch(
                        "scripts.service_reachability_check.ParamikoSSHCommandRunner",
                        return_value=runner,
                    ), mock.patch(
                        "scripts.manual_diagnosis_pipeline.feishu_notify.send_diagnostic_message",
                        return_value=FeishuSendResult(
                            success=True,
                            reason="sent",
                            status_code=200,
                        ),
                    ) as sender:
                        with contextlib.redirect_stdout(stdout):
                            exit_code = main(
                                [
                                    "--config",
                                    str(config_path),
                                    "--routes",
                                    str(routes_path),
                                    "--hermes-event-json",
                                    str(event_path),
                                ]
                            )

        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["status"], "abnormal")
        self.assertTrue(payload["should_notify"])
        self.assertEqual(payload["send_result"]["reason"], "sent")
        self.assertEqual(
            payload["route"]["owners"][0]["feishu_user_id"],
            "[redacted]",
        )
        self.assertNotIn("ou_test_manual_owner", stdout.getvalue())
        sender.assert_called_once()
        sent_payload = sender.call_args.args[0]
        card_json = json.dumps(sent_payload["card"], ensure_ascii=False)
        self.assertIn("<at id=ou_test_manual_owner></at>", card_json)
        private_card_json = json.dumps(
            payload["notification"]["private_payload"]["card"],
            ensure_ascii=False,
        )
        self.assertIn("手动测试负责人", private_card_json)
        self.assertNotIn("<at", private_card_json)

    def test_hermes_event_json_route_error_sends_without_probe(self) -> None:
        runner = FakeRunner({"internal": [ok()], "external": [ok()]})
        with temporary_json_file(config()) as config_path:
            with temporary_json_file({"routes": [], "fallback": {"owners": [OWNER]}}) as routes_path:
                with temporary_json_file(event()) as event_path:
                    stdout = io.StringIO()
                    with mock.patch(
                        "scripts.service_reachability_check.ParamikoSSHCommandRunner",
                        return_value=runner,
                    ), mock.patch(
                        "scripts.manual_diagnosis_pipeline.feishu_notify.send_diagnostic_message",
                        return_value=FeishuSendResult(
                            success=True,
                            reason="sent",
                            status_code=200,
                        ),
                    ) as sender:
                        with contextlib.redirect_stdout(stdout):
                            exit_code = main(
                                [
                                    "--config",
                                    str(config_path),
                                    "--routes",
                                    str(routes_path),
                                    "--hermes-event-json",
                                    str(event_path),
                                ]
                            )

        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["status"], "error")
        self.assertEqual(payload["reason"], "route_not_found")
        self.assertEqual(payload["send_result"]["reason"], "sent")
        sender.assert_called_once()
        self.assertEqual(runner.calls, [])

    def test_hermes_event_json_ignored_alert_does_not_probe_or_send(self) -> None:
        runner = FakeRunner({"internal": [ok()], "external": [ok()]})
        with temporary_json_file(config()) as config_path:
            with temporary_json_file(routes_config()) as routes_path:
                with temporary_json_file(event(sender_name="其他机器人")) as event_path:
                    stdout = io.StringIO()
                    with mock.patch(
                        "scripts.service_reachability_check.ParamikoSSHCommandRunner",
                        return_value=runner,
                    ), mock.patch(
                        "scripts.manual_diagnosis_pipeline.feishu_notify.send_diagnostic_message"
                    ) as sender:
                        with contextlib.redirect_stdout(stdout):
                            exit_code = main(
                                [
                                    "--config",
                                    str(config_path),
                                    "--routes",
                                    str(routes_path),
                                    "--hermes-event-json",
                                    str(event_path),
                                ]
                            )

        self.assertEqual(exit_code, 0)
        self.assertEqual(
            json.loads(stdout.getvalue()),
            {"status": "ignored", "reason": "non_alert_bot"},
        )
        sender.assert_not_called()
        self.assertEqual(runner.calls, [])

    def test_send_feishu_cannot_be_combined_with_hermes_event_json(self) -> None:
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            with self.assertRaises(SystemExit) as raised:
                main(["--hermes-event-json", "-", "--send-feishu"])

        self.assertEqual(raised.exception.code, 2)
        self.assertIn("--send-feishu requires --diagnose-event-json", stderr.getvalue())


class temporary_json_file:
    def __init__(self, payload: dict[str, Any]) -> None:
        self.payload = payload
        self.path: Path | None = None

    def __enter__(self) -> Path:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            suffix=".json",
            delete=False,
        ) as file:
            json.dump(self.payload, file, ensure_ascii=False)
            self.path = Path(file.name)
        return self.path

    def __exit__(self, *_args: object) -> None:
        if self.path is not None:
            self.path.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
