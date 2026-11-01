from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

from scripts.alert_router import RouteResolutionResult, resolve_alert_route
from scripts.diagnosis_engine import diagnose_reachability
from scripts.feishu_event_parser import ParsedAlert
from scripts.probe_executor import (
    CommandExecutionResult,
    ParamikoSSHCommandRunner,
    ProbeExecutionError,
    ProbeExecutionPolicy,
    RemoteCommand,
    build_probe_command,
    execute_route_probes,
)


OWNER = {"name": "owner-a", "feishu_user_id": "ou_owner_a"}


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
        perspective = probe_config["perspective"]
        queue = self.results[perspective]
        if not queue:
            raise AssertionError(f"no fake result left for {perspective}")
        return queue.pop(0)


def parsed_alert() -> ParsedAlert:
    return ParsedAlert(
        source_bot="alert-bot",
        status="fault",
        monitor_name="service-a",
        reason="Request timeout",
        alert_time="2026-07-07 23:35:20",
        raw_text="raw alert text",
    )


def route_result(diagnosis: dict[str, Any]) -> RouteResolutionResult:
    return resolve_alert_route(
        parsed_alert(),
        {
            "routes": [
                {
                    "id": "service-a",
                    "match": {"monitor_name": "service-a"},
                    "service_name": "Service A",
                    "diagnosis": diagnosis,
                    "owners": [OWNER],
                }
            ],
            "fallback": {"owners": []},
        },
    )


def tcp_route() -> RouteResolutionResult:
    return route_result(
        {
            "type": "tcp",
            "host": "service-a.internal.example",
            "port": 8002,
        }
    )


def http_route(url: str = "https://service.example/health") -> RouteResolutionResult:
    return route_result({"type": "http", "url": url})


def http_targets_route() -> RouteResolutionResult:
    return route_result(
        {
            "type": "http",
            "targets": {
                "internal": {"url": "https://service.example.invalid/health"},
                "external": {"url": "https://service.example.invalid/health"},
            },
        }
    )


def tcp_targets_route() -> RouteResolutionResult:
    return route_result(
        {
            "type": "tcp",
            "targets": {
                "internal": {"host": "service-internal.example.invalid", "port": 3000},
                "external": {"host": "service-external.example.invalid", "port": 3000},
            },
        }
    )


def config(
    *,
    retry_count: int = 1,
    retry_interval_seconds: int = 0,
    ssh_timeout_seconds: int = 10,
    command_timeout_seconds: int = 10,
    tcp_timeout_seconds: int = 5,
    http_timeout_seconds: int = 10,
    http_success_status: int = 200,
) -> dict[str, Any]:
    return {
        "probes": {
            "retry_count": retry_count,
            "retry_interval_seconds": retry_interval_seconds,
            "ssh_timeout_seconds": ssh_timeout_seconds,
            "command_timeout_seconds": command_timeout_seconds,
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
            "tcp_timeout_seconds": tcp_timeout_seconds,
            "http_timeout_seconds": http_timeout_seconds,
            "http_success_status": http_success_status,
        },
    }


def ok(stdout: str = "ok") -> CommandExecutionResult:
    return CommandExecutionResult(exit_code=0, stdout=stdout)


def failed(
    *,
    exit_code: int | None = 1,
    stdout: str = "",
    stderr: str = "",
    error_type: str = "",
    error_message: str = "",
) -> CommandExecutionResult:
    return CommandExecutionResult(
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        error_type=error_type,
        error_message=error_message,
    )


class ProbeCommandBuildTests(unittest.TestCase):
    def test_build_tcp_command(self) -> None:
        result = tcp_route()
        self.assertIsNotNone(result.route)

        command = build_probe_command(result.route, config()["diagnosis"])

        self.assertEqual(command.kind, "tcp")
        self.assertEqual(command.timeout_seconds, 5)
        self.assertEqual(
            command.argv,
            ("tcping", "service-a.internal.example", "8002"),
        )
        self.assertEqual(
            command.to_shell(),
            "timeout --signal=KILL 5s tcping service-a.internal.example 8002",
        )

    def test_build_http_command_and_quote_shell_arguments(self) -> None:
        raw_url = "https://service.example/health check?token=a b"
        result = http_route(raw_url)
        self.assertIsNotNone(result.route)

        command = build_probe_command(result.route, config()["diagnosis"])
        shell = command.to_shell()

        self.assertEqual(command.kind, "http")
        self.assertEqual(command.timeout_seconds, 10)
        self.assertEqual(
            command.argv,
            (
                "curl",
                "-sS",
                "-o",
                "/dev/null",
                "-w",
                "%{http_code}",
                "--max-time",
                "10",
                raw_url,
            ),
        )
        self.assertNotEqual(shell, " ".join(command.argv))
        self.assertTrue(shell.startswith("timeout --signal=KILL 10s curl "))
        self.assertIn("'%{http_code}'", shell)
        self.assertIn(f"'{raw_url}'", shell)

    def test_tcp_effective_timeout_uses_command_and_diagnosis_min(self) -> None:
        result = tcp_route()
        self.assertIsNotNone(result.route)
        policy = ProbeExecutionPolicy.from_config(
            config(command_timeout_seconds=3, tcp_timeout_seconds=5)
        )

        command = build_probe_command(result.route, policy)

        self.assertEqual(command.timeout_seconds, 3)

    def test_http_wrapper_timeout_uses_min_but_curl_max_time_uses_http_timeout(self) -> None:
        result = http_route()
        self.assertIsNotNone(result.route)
        policy = ProbeExecutionPolicy.from_config(
            config(command_timeout_seconds=4, http_timeout_seconds=10)
        )

        command = build_probe_command(result.route, policy)

        self.assertEqual(command.timeout_seconds, 4)
        self.assertEqual(command.argv[-2], "10")

    def test_build_http_command_uses_perspective_target(self) -> None:
        result = http_targets_route()
        self.assertIsNotNone(result.route)

        internal = build_probe_command(
            result.route,
            config()["diagnosis"],
            perspective="internal",
        )
        external = build_probe_command(
            result.route,
            config()["diagnosis"],
            perspective="external",
        )

        self.assertEqual(internal.argv[-1], "https://service.example.invalid/health")
        self.assertEqual(external.argv[-1], "https://service.example.invalid/health")
        self.assertNotIn("-u", internal.argv)
        self.assertNotIn("--user", internal.argv)

    def test_build_tcp_command_uses_perspective_target(self) -> None:
        result = tcp_targets_route()
        self.assertIsNotNone(result.route)

        internal = build_probe_command(
            result.route,
            config()["diagnosis"],
            perspective="internal",
        )
        external = build_probe_command(
            result.route,
            config()["diagnosis"],
            perspective="external",
        )

        self.assertEqual(
            internal.argv,
            ("tcping", "service-internal.example.invalid", "3000"),
        )
        self.assertEqual(
            external.argv,
            ("tcping", "service-external.example.invalid", "3000"),
        )

    def test_per_perspective_target_requires_perspective(self) -> None:
        result = http_targets_route()
        self.assertIsNotNone(result.route)

        with self.assertRaisesRegex(ProbeExecutionError, "perspective is required"):
            build_probe_command(result.route, config()["diagnosis"])


class ParamikoSSHCommandRunnerTests(unittest.TestCase):
    def test_hanging_remote_command_is_closed_at_local_deadline(self) -> None:
        with tempfile.NamedTemporaryFile(delete=False) as key_file:
            key_path = Path(key_file.name)

        channel = mock.Mock()
        channel.exit_status_ready.return_value = False
        stdout = mock.Mock(channel=channel)
        stderr = mock.Mock()
        client = mock.Mock()
        client.exec_command.return_value = (None, stdout, stderr)
        command = RemoteCommand(
            argv=("tcping", "service.internal", "1"),
            timeout_seconds=5,
            kind="tcp",
        )
        probe_config = {
            "host": "probe.example",
            "port": 22,
            "user": "probe",
            "key_path_env": "TEST_PROBE_KEY_PATH",
            "ssh_timeout_seconds": 10,
        }

        try:
            with mock.patch.dict(
                os.environ,
                {"TEST_PROBE_KEY_PATH": str(key_path)},
            ), mock.patch(
                "paramiko.SSHClient",
                return_value=client,
            ), mock.patch(
                "scripts.probe_executor.time.monotonic",
                side_effect=(100.0, 106.0),
            ), mock.patch("scripts.probe_executor.time.sleep"):
                result = ParamikoSSHCommandRunner().run(probe_config, command)
        finally:
            key_path.unlink(missing_ok=True)

        self.assertEqual(result.error_type, "command_timeout")
        self.assertIn("exceeded 5 seconds", result.error_message)
        channel.close.assert_called_once_with()
        client.close.assert_called_once_with()
        client.exec_command.assert_called_once_with(
            "timeout --signal=KILL 5s tcping service.internal 1",
            timeout=5,
        )


class ProbeExecutionTests(unittest.TestCase):
    def test_execute_route_probes_uses_perspective_specific_commands(self) -> None:
        runner = FakeRunner(
            {
                "internal": [ok("200")],
                "external": [ok("200")],
            }
        )

        internal, external = execute_route_probes(
            http_targets_route(),
            config(),
            runner,
        )

        self.assertTrue(internal.success)
        self.assertTrue(external.success)
        self.assertEqual(
            runner.calls[0][1].argv[-1],
            "https://service.example.invalid/health",
        )
        self.assertEqual(
            runner.calls[1][1].argv[-1],
            "https://service.example.invalid/health",
        )

    def test_runs_both_perspectives_even_when_one_fails(self) -> None:
        runner = FakeRunner(
            {
                "internal": [failed(stderr="connection timed out")],
                "external": [ok("tcping success")],
            }
        )

        internal, external = execute_route_probes(
            tcp_route(),
            config(),
            runner,
        )

        self.assertFalse(internal.success)
        self.assertTrue(external.success)
        self.assertEqual([call[0]["perspective"] for call in runner.calls], ["internal", "external"])
        self.assertEqual(internal.final_error, "connection timed out")

    def test_success_stops_retry_on_first_attempt(self) -> None:
        runner = FakeRunner(
            {
                "internal": [ok("tcping success")],
                "external": [ok("tcping success")],
            }
        )
        sleeps: list[float] = []

        internal, external = execute_route_probes(
            tcp_route(),
            config(retry_count=3, retry_interval_seconds=2),
            runner,
            sleep_fn=sleeps.append,
        )

        self.assertTrue(internal.success)
        self.assertTrue(external.success)
        self.assertEqual(internal.attempts, 1)
        self.assertEqual(external.attempts, 1)
        self.assertEqual(len(runner.calls), 2)
        self.assertEqual(sleeps, [])

    def test_failures_retry_and_record_attempt_details(self) -> None:
        runner = FakeRunner(
            {
                "internal": [
                    failed(stderr="timeout 1"),
                    failed(stderr="timeout 2"),
                    failed(stderr="timeout 3"),
                ],
                "external": [ok("tcping success")],
            }
        )
        sleeps: list[float] = []

        internal, external = execute_route_probes(
            tcp_route(),
            config(retry_count=3, retry_interval_seconds=2),
            runner,
            sleep_fn=sleeps.append,
        )

        self.assertFalse(internal.success)
        self.assertTrue(external.success)
        self.assertEqual(internal.attempts, 3)
        self.assertEqual(internal.final_error, "timeout 3")
        self.assertEqual(len(internal.details["attempts"]), 3)
        self.assertEqual(sleeps, [2, 2])
        self.assertEqual(
            internal.details["retry_policy"],
            {"retry_count": 3, "retry_interval_seconds": 2},
        )

    def test_http_uses_configured_success_status(self) -> None:
        runner = FakeRunner(
            {
                "internal": [ok("204")],
                "external": [ok("204")],
            }
        )

        internal, external = execute_route_probes(
            http_route(),
            config(http_success_status=204),
            runner,
        )

        self.assertTrue(internal.success)
        self.assertTrue(external.success)
        self.assertEqual(internal.evidence, "curl returned HTTP 204")

    def test_http_non_success_status_is_failed_probe(self) -> None:
        runner = FakeRunner(
            {
                "internal": [ok("502")],
                "external": [ok("200")],
            }
        )

        internal, external = execute_route_probes(
            http_route(),
            config(),
            runner,
        )

        self.assertFalse(internal.success)
        self.assertTrue(external.success)
        self.assertEqual(internal.final_error, "http_status_502")
        self.assertEqual(internal.evidence, "curl returned HTTP 502")

    def test_command_timeout_and_ssh_errors_are_failed_probes(self) -> None:
        runner = FakeRunner(
            {
                "internal": [
                    failed(
                        exit_code=None,
                        error_type="command_timeout",
                        error_message="timed out",
                    )
                ],
                "external": [
                    failed(
                        exit_code=None,
                        error_type="ssh_failed",
                        error_message="connection reset",
                    )
                ],
            }
        )

        internal, external = execute_route_probes(
            tcp_route(),
            config(),
            runner,
        )

        self.assertFalse(internal.success)
        self.assertFalse(external.success)
        self.assertEqual(internal.final_error, "command_timeout: timed out")
        self.assertEqual(external.final_error, "ssh_failed: connection reset")

    def test_internal_and_external_retry_independently_after_timeout(self) -> None:
        runner = FakeRunner(
            {
                "internal": [
                    failed(
                        exit_code=None,
                        error_type="command_timeout",
                        error_message="timed out",
                    ),
                    ok("tcping success"),
                ],
                "external": [
                    failed(
                        exit_code=None,
                        error_type="ssh_connection_failed",
                        error_message="network unreachable",
                    ),
                    failed(stderr="still unreachable"),
                ],
            }
        )
        sleeps: list[float] = []

        internal, external = execute_route_probes(
            tcp_route(),
            config(retry_count=2, retry_interval_seconds=1),
            runner,
            sleep_fn=sleeps.append,
        )

        self.assertTrue(internal.success)
        self.assertFalse(external.success)
        self.assertEqual(internal.attempts, 2)
        self.assertEqual(external.attempts, 2)
        self.assertEqual(
            [call[0]["perspective"] for call in runner.calls],
            ["internal", "internal", "external", "external"],
        )
        self.assertEqual(sleeps, [1, 1])
        self.assertEqual(external.final_error, "still unreachable")

    def test_attempt_details_record_elapsed_and_timeout_budget(self) -> None:
        runner = FakeRunner(
            {
                "internal": [failed(stderr="timeout 1"), ok("tcping success")],
                "external": [ok("tcping success")],
            }
        )
        clock_values = iter([100.0, 100.25, 101.0, 101.75, 200.0, 200.5])

        internal, external = execute_route_probes(
            tcp_route(),
            config(
                retry_count=2,
                command_timeout_seconds=3,
                tcp_timeout_seconds=5,
            ),
            runner,
            monotonic_fn=lambda: next(clock_values),
        )

        self.assertTrue(internal.success)
        self.assertTrue(external.success)
        self.assertEqual(internal.details["effective_timeout_seconds"], 3)
        self.assertEqual(internal.details["diagnosis_timeout_seconds"], 5)
        self.assertEqual(internal.details["ssh_timeout_seconds"], 10)
        self.assertEqual(internal.details["attempts"][0]["timeout_seconds"], 3)
        self.assertEqual(internal.details["attempts"][0]["elapsed_seconds"], 0.25)
        self.assertEqual(internal.details["attempts"][1]["elapsed_seconds"], 0.75)
        self.assertEqual(external.details["attempts"][0]["elapsed_seconds"], 0.5)

    def test_probe_outcomes_feed_diagnosis_engine(self) -> None:
        runner = FakeRunner(
            {
                "internal": [ok("tcping success")],
                "external": [failed(stderr="connection timed out")],
            }
        )
        route = tcp_route()

        outcomes = execute_route_probes(route, config(), runner)
        diagnosis = diagnose_reachability(route, outcomes).to_dict()

        self.assertEqual(diagnosis["status"], "abnormal")
        self.assertTrue(diagnosis["should_notify"])
        self.assertEqual(
            diagnosis["classification"],
            "external_path_issue_likely",
        )

    def test_unmatched_route_is_rejected_before_probe_execution(self) -> None:
        route = resolve_alert_route(
            parsed_alert(),
            {"routes": [], "fallback": {"owners": []}},
        )

        with self.assertRaisesRegex(ProbeExecutionError, "must be matched"):
            execute_route_probes(route, config(), FakeRunner({}))

    def test_paramiko_runner_missing_config_returns_structured_failure(self) -> None:
        runner = ParamikoSSHCommandRunner()
        result = runner.run(
            {"name": "internal-probe", "host": "", "port": 22},
            RemoteCommand(("tcping", "service", "80"), 5, "tcp"),
        )

        self.assertEqual(result.exit_code, None)
        self.assertEqual(result.error_type, "probe_config_missing")

    def test_policy_rejects_bool_and_non_integer_values(self) -> None:
        invalid_configs = [
            config(retry_count=True),
            config(retry_count="3"),  # type: ignore[arg-type]
            config(retry_count=0),
            config(retry_interval_seconds=True),
            config(retry_interval_seconds="1"),  # type: ignore[arg-type]
            config(retry_interval_seconds=-1),
            config(ssh_timeout_seconds=True),
            config(command_timeout_seconds="10"),  # type: ignore[arg-type]
            config(tcp_timeout_seconds=0),
            config(http_timeout_seconds=-1),
            config(http_success_status=True),
        ]

        for invalid_config in invalid_configs:
            with self.subTest(invalid_config=invalid_config):
                with self.assertRaises(ProbeExecutionError):
                    execute_route_probes(
                        tcp_route(),
                        invalid_config,
                        FakeRunner(
                            {
                                "internal": [ok("tcping success")],
                                "external": [ok("tcping success")],
                            }
                        ),
                    )


if __name__ == "__main__":
    unittest.main()
