from __future__ import annotations

import os
import shlex
import socket
import time
from dataclasses import dataclass
from typing import Any, Callable, Literal, Protocol

from scripts.alert_router import ResolvedRoute, RouteResolutionResult
from scripts.diagnosis_engine import ProbeOutcome, ProbePerspective


CommandKind = Literal["tcp", "http"]


class ProbeExecutionError(ValueError):
    """Raised when probe execution is called with invalid local inputs."""


@dataclass(frozen=True)
class RemoteCommand:
    argv: tuple[str, ...]
    timeout_seconds: int
    kind: CommandKind

    def to_shell(self) -> str:
        command = " ".join(shlex.quote(arg) for arg in self.argv)
        return (
            f"timeout --signal=KILL {self.timeout_seconds}s "
            f"{command}"
        )


@dataclass(frozen=True)
class CommandExecutionResult:
    exit_code: int | None
    stdout: str = ""
    stderr: str = ""
    error_type: str = ""
    error_message: str = ""


@dataclass(frozen=True)
class ProbeExecutionPolicy:
    retry_count: int = 3
    retry_interval_seconds: int = 0
    ssh_timeout_seconds: int = 10
    command_timeout_seconds: int = 10
    tcp_timeout_seconds: int = 5
    http_timeout_seconds: int = 10
    http_success_status: int = 200

    @classmethod
    def from_config(cls, config: dict[str, Any]) -> "ProbeExecutionPolicy":
        return cls.from_sections(
            probes_config=config.get("probes", {}),
            diagnosis_config=config.get("diagnosis", {}),
        )

    @classmethod
    def from_sections(
        cls,
        probes_config: dict[str, Any],
        diagnosis_config: dict[str, Any],
    ) -> "ProbeExecutionPolicy":
        return cls(
            retry_count=_positive_int(
                probes_config,
                "retry_count",
                default=3,
                label="probes.retry_count",
            ),
            retry_interval_seconds=_non_negative_int(
                probes_config,
                "retry_interval_seconds",
                default=0,
                label="probes.retry_interval_seconds",
            ),
            ssh_timeout_seconds=_positive_int(
                probes_config,
                "ssh_timeout_seconds",
                default=10,
                label="probes.ssh_timeout_seconds",
            ),
            command_timeout_seconds=_positive_int(
                probes_config,
                "command_timeout_seconds",
                default=10,
                label="probes.command_timeout_seconds",
            ),
            tcp_timeout_seconds=_positive_int(
                diagnosis_config,
                "tcp_timeout_seconds",
                default=5,
                label="diagnosis.tcp_timeout_seconds",
            ),
            http_timeout_seconds=_positive_int(
                diagnosis_config,
                "http_timeout_seconds",
                default=10,
                label="diagnosis.http_timeout_seconds",
            ),
            http_success_status=_positive_int(
                diagnosis_config,
                "http_success_status",
                default=200,
                label="diagnosis.http_success_status",
            ),
        )

    def diagnosis_timeout_for(self, kind: CommandKind) -> int:
        if kind == "tcp":
            return self.tcp_timeout_seconds
        return self.http_timeout_seconds

    def command_timeout_for(self, kind: CommandKind) -> int:
        return min(self.command_timeout_seconds, self.diagnosis_timeout_for(kind))

    def to_dict(self) -> dict[str, int]:
        return {
            "retry_count": self.retry_count,
            "retry_interval_seconds": self.retry_interval_seconds,
            "ssh_timeout_seconds": self.ssh_timeout_seconds,
            "command_timeout_seconds": self.command_timeout_seconds,
            "tcp_timeout_seconds": self.tcp_timeout_seconds,
            "http_timeout_seconds": self.http_timeout_seconds,
            "http_success_status": self.http_success_status,
        }


class CommandRunner(Protocol):
    def run(
        self,
        probe_config: dict[str, Any],
        command: RemoteCommand,
    ) -> CommandExecutionResult:
        ...


class ParamikoSSHCommandRunner:
    def run(
        self,
        probe_config: dict[str, Any],
        command: RemoteCommand,
    ) -> CommandExecutionResult:
        host = _string_value(probe_config.get("host"))
        user = _string_value(probe_config.get("user"))
        key_path_env = _string_value(probe_config.get("key_path_env"))
        key_path = os.getenv(key_path_env) if key_path_env else ""
        port = probe_config.get("port", 22)
        ssh_timeout = probe_config.get("ssh_timeout_seconds", command.timeout_seconds)

        if not host or not user or not key_path_env or not key_path:
            return _execution_error(
                "probe_config_missing",
                "probe ssh host, user, key_path_env, or key path env value is missing",
            )
        if type(port) is not int or port <= 0:
            return _execution_error("probe_config_invalid", "probe ssh port is invalid")
        if type(ssh_timeout) is not int or ssh_timeout <= 0:
            return _execution_error(
                "probe_config_invalid",
                "probe ssh timeout is invalid",
            )
        if not os.path.exists(key_path):
            return _execution_error("ssh_key_missing", "ssh private key file is missing")

        try:
            import paramiko
        except ImportError as exc:
            return _execution_error("dependency_missing", str(exc))

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                hostname=host,
                port=port,
                username=user,
                key_filename=key_path,
                timeout=ssh_timeout,
                banner_timeout=ssh_timeout,
                auth_timeout=ssh_timeout,
                look_for_keys=False,
                allow_agent=False,
            )
            _, stdout, stderr = client.exec_command(
                command.to_shell(),
                timeout=command.timeout_seconds,
            )
            stdout.channel.settimeout(command.timeout_seconds)
            exit_code = _wait_for_exit_status(
                stdout.channel,
                command.timeout_seconds,
            )
            return CommandExecutionResult(
                exit_code=exit_code,
                stdout=_read_stream(stdout),
                stderr=_read_stream(stderr),
            )
        except paramiko.AuthenticationException as exc:
            return _execution_error("ssh_auth_failed", str(exc))
        except socket.timeout as exc:
            return _execution_error("command_timeout", str(exc))
        except TimeoutError as exc:
            return _execution_error("command_timeout", str(exc))
        except paramiko.SSHException as exc:
            return _execution_error("ssh_failed", str(exc))
        except OSError as exc:
            return _execution_error("ssh_connection_failed", str(exc))
        finally:
            client.close()


def _wait_for_exit_status(channel: Any, timeout_seconds: int) -> int:
    deadline = time.monotonic() + timeout_seconds
    while not channel.exit_status_ready():
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            channel.close()
            raise socket.timeout(
                f"remote command exceeded {timeout_seconds} seconds"
            )
        time.sleep(min(0.05, remaining))
    return channel.recv_exit_status()


def build_probe_command(
    route: ResolvedRoute,
    policy_or_diagnosis_config: ProbeExecutionPolicy | dict[str, Any],
    perspective: ProbePerspective | None = None,
) -> RemoteCommand:
    policy = _coerce_policy(policy_or_diagnosis_config)
    diagnosis = _diagnosis_for_perspective(route.diagnosis, perspective)
    diagnosis_type = diagnosis.get("type")

    if diagnosis_type == "tcp":
        return RemoteCommand(
            argv=(
                "tcping",
                str(diagnosis["host"]),
                str(diagnosis["port"]),
            ),
            timeout_seconds=policy.command_timeout_for("tcp"),
            kind="tcp",
        )

    if diagnosis_type == "http":
        timeout = policy.http_timeout_seconds
        return RemoteCommand(
            argv=(
                "curl",
                "-sS",
                "-o",
                "/dev/null",
                "-w",
                "%{http_code}",
                "--max-time",
                str(timeout),
                str(diagnosis["url"]),
            ),
            timeout_seconds=policy.command_timeout_for("http"),
            kind="http",
        )

    raise ProbeExecutionError("route diagnosis type must be tcp or http")


def _diagnosis_for_perspective(
    diagnosis: dict[str, Any],
    perspective: ProbePerspective | None,
) -> dict[str, Any]:
    targets = diagnosis.get("targets")
    if targets is None:
        return diagnosis
    if perspective not in ("internal", "external"):
        raise ProbeExecutionError(
            "perspective is required when route diagnosis uses per-perspective targets"
        )
    if not isinstance(targets, dict) or not isinstance(targets.get(perspective), dict):
        raise ProbeExecutionError(
            f"route diagnosis target for {perspective} must be configured"
        )
    return {
        "type": diagnosis.get("type"),
        **targets[perspective],
    }


def execute_route_probes(
    route_result: RouteResolutionResult,
    config: dict[str, Any],
    runner: CommandRunner,
    sleep_fn: Callable[[float], None] = time.sleep,
    monotonic_fn: Callable[[], float] = time.monotonic,
) -> tuple[ProbeOutcome, ProbeOutcome]:
    if route_result.status != "matched" or route_result.route is None:
        raise ProbeExecutionError("route_result must be matched before probe execution")

    probes_config = config.get("probes", {})
    policy = ProbeExecutionPolicy.from_config(config)

    outcomes = []
    for perspective in ("internal", "external"):
        command = build_probe_command(
            route_result.route,
            policy,
            perspective=perspective,
        )
        probe_config = _effective_probe_config(probes_config, perspective, policy)
        outcomes.append(
            _execute_one_probe(
                perspective=perspective,
                probe_config=probe_config,
                command=command,
                runner=runner,
                policy=policy,
                sleep_fn=sleep_fn,
                monotonic_fn=monotonic_fn,
            )
        )

    return outcomes[0], outcomes[1]


def _execute_one_probe(
    *,
    perspective: ProbePerspective,
    probe_config: dict[str, Any],
    command: RemoteCommand,
    runner: CommandRunner,
    policy: ProbeExecutionPolicy,
    sleep_fn: Callable[[float], None],
    monotonic_fn: Callable[[], float],
) -> ProbeOutcome:
    attempts: list[dict[str, Any]] = []
    final_error = ""
    evidence = ""

    for attempt_number in range(1, policy.retry_count + 1):
        started_at = monotonic_fn()
        try:
            result = runner.run(probe_config, command)
        except Exception as exc:  # pragma: no cover - defensive adapter boundary.
            result = _execution_error("runner_exception", str(exc))
        elapsed_seconds = max(0.0, monotonic_fn() - started_at)

        success, attempt_error, attempt_evidence = _interpret_result(
            command,
            result,
            policy.http_success_status,
        )
        final_error = attempt_error
        evidence = attempt_evidence
        attempts.append(
            {
                "attempt": attempt_number,
                "success": success,
                "elapsed_seconds": round(elapsed_seconds, 3),
                "timeout_seconds": command.timeout_seconds,
                "exit_code": result.exit_code,
                "stdout": _truncate(result.stdout),
                "stderr": _truncate(result.stderr),
                "error_type": result.error_type,
                "error_message": _truncate(result.error_message),
                "final_error": final_error,
                "evidence": evidence,
            }
        )

        if success:
            return ProbeOutcome(
                perspective=perspective,
                success=True,
                attempts=attempt_number,
                final_error="",
                evidence=evidence,
                details=_probe_details(command, probe_config, policy, attempts),
            )

        if (
            attempt_number < policy.retry_count
            and policy.retry_interval_seconds > 0
        ):
            sleep_fn(policy.retry_interval_seconds)

    return ProbeOutcome(
        perspective=perspective,
        success=False,
        attempts=policy.retry_count,
        final_error=final_error,
        evidence=evidence,
        details=_probe_details(command, probe_config, policy, attempts),
    )


def _interpret_result(
    command: RemoteCommand,
    result: CommandExecutionResult,
    http_success_status: int,
) -> tuple[bool, str, str]:
    if result.error_type:
        message = result.error_message or result.error_type
        return (
            False,
            f"{result.error_type}: {message}",
            f"{command.kind} probe failed before command completed: {message}",
        )

    if command.kind == "tcp":
        if result.exit_code == 0:
            return True, "", _non_empty(result.stdout, "tcping exited with code 0")
        message = _first_non_empty(
            result.error_message,
            result.stderr,
            result.stdout,
            f"tcping exited with code {result.exit_code}",
        )
        return False, message, message

    if result.exit_code != 0:
        message = _first_non_empty(
            result.error_message,
            result.stderr,
            result.stdout,
            f"curl exited with code {result.exit_code}",
        )
        return False, message, message

    status_text = result.stdout.strip()
    try:
        status_code = int(status_text)
    except ValueError:
        message = _non_empty(status_text, "curl did not return an HTTP status code")
        return False, message, message

    evidence = f"curl returned HTTP {status_code}"
    if status_code == http_success_status:
        return True, "", evidence
    return False, f"http_status_{status_code}", evidence


def _effective_probe_config(
    probes_config: dict[str, Any],
    perspective: ProbePerspective,
    policy: ProbeExecutionPolicy,
) -> dict[str, Any]:
    probe = dict(probes_config.get(perspective, {}))
    probe["perspective"] = perspective
    probe["ssh_timeout_seconds"] = policy.ssh_timeout_seconds
    probe["command_timeout_seconds"] = policy.command_timeout_seconds
    return probe


def _probe_details(
    command: RemoteCommand,
    probe_config: dict[str, Any],
    policy: ProbeExecutionPolicy,
    attempts: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "command_kind": command.kind,
        "command_timeout_seconds": command.timeout_seconds,
        "diagnosis_timeout_seconds": policy.diagnosis_timeout_for(command.kind),
        "effective_timeout_seconds": command.timeout_seconds,
        "probe_name": probe_config.get("name", ""),
        "retry_policy": {
            "retry_count": policy.retry_count,
            "retry_interval_seconds": policy.retry_interval_seconds,
        },
        "ssh_timeout_seconds": policy.ssh_timeout_seconds,
        "attempts": attempts,
    }


def _execution_error(error_type: str, error_message: str) -> CommandExecutionResult:
    return CommandExecutionResult(
        exit_code=None,
        error_type=error_type,
        error_message=error_message,
    )


def _coerce_policy(
    policy_or_diagnosis_config: ProbeExecutionPolicy | dict[str, Any],
) -> ProbeExecutionPolicy:
    if isinstance(policy_or_diagnosis_config, ProbeExecutionPolicy):
        return policy_or_diagnosis_config
    return ProbeExecutionPolicy.from_sections(
        probes_config={},
        diagnosis_config=policy_or_diagnosis_config,
    )


def _positive_int(
    mapping: dict[str, Any],
    key: str,
    *,
    default: int,
    label: str,
) -> int:
    value = mapping.get(key, default)
    if type(value) is not int or value <= 0:
        raise ProbeExecutionError(f"{label} must be a positive integer")
    return value


def _non_negative_int(
    mapping: dict[str, Any],
    key: str,
    *,
    default: int,
    label: str,
) -> int:
    value = mapping.get(key, default)
    if type(value) is not int or value < 0:
        raise ProbeExecutionError(f"{label} must be a non-negative integer")
    return value


def _read_stream(stream: Any) -> str:
    data = stream.read()
    if isinstance(data, bytes):
        return data.decode("utf-8", errors="replace")
    return str(data)


def _string_value(value: Any) -> str:
    return value if isinstance(value, str) else ""


def _truncate(value: str, limit: int = 500) -> str:
    if len(value) <= limit:
        return value
    return value[:limit] + "...[truncated]"


def _first_non_empty(*values: Any) -> str:
    for value in values:
        text = str(value).strip()
        if text:
            return text
    return ""


def _non_empty(value: str, fallback: str) -> str:
    text = value.strip()
    return text if text else fallback
