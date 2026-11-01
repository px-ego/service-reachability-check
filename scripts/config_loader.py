from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG_PATH = PROJECT_ROOT / "config" / "default.yaml"
LOCAL_ENV_PATH = PROJECT_ROOT / ".env"


class ConfigError(ValueError):
    """Raised when configuration is missing or malformed."""


@dataclass(frozen=True)
class LoadedConfig:
    project_root: Path
    config_path: Path
    routes_path: Path
    config: dict[str, Any]
    routes: dict[str, Any]

    def summary(self) -> dict[str, Any]:
        feishu = self.config.get("feishu", {})
        probes = self.config.get("probes", {})
        runtime = self.config.get("runtime", {})
        diagnosis = self.config.get("diagnosis", {})
        routes = self.routes.get("routes", [])
        fallback = self.routes.get("fallback", {})

        webhook_env = feishu.get("webhook_env", "")
        secret_env = feishu.get("secret_env", "")
        app_notify = feishu.get("app_notify", {})
        alert_bot = feishu.get("alert_bot", {})
        sender_id_env = alert_bot.get("allowed_sender_id_env", "")

        return {
            "project_root": str(self.project_root),
            "config_path": str(self.config_path),
            "routes_path": str(self.routes_path),
            "runtime": {
                "dry_run": bool(runtime.get("dry_run", True)),
            },
            "feishu": {
                "enabled": bool(feishu.get("enabled", False)),
                "webhook_env": webhook_env,
                "webhook_configured": _env_is_set(webhook_env),
                "secret_env": secret_env,
                "secret_configured": _env_is_set(secret_env),
                "allowed_alert_bot_names": alert_bot.get("allowed_names", []),
                "alert_bot_sender_id_env": sender_id_env,
                "alert_bot_sender_id_configured": _env_is_set(sender_id_env),
                "self_names": alert_bot.get("self_names", []),
                "app_notify": {
                    "enabled": bool(app_notify.get("enabled", False)),
                    "app_id_configured": _env_is_set(app_notify.get("app_id_env")),
                    "app_secret_configured": _env_is_set(app_notify.get("app_secret_env")),
                },
            },
            "probes": {
                "retry_count": probes.get("retry_count"),
                "retry_interval_seconds": probes.get("retry_interval_seconds"),
                "ssh_timeout_seconds": probes.get("ssh_timeout_seconds"),
                "command_timeout_seconds": probes.get("command_timeout_seconds"),
                "internal": _probe_summary(probes.get("internal", {})),
                "external": _probe_summary(probes.get("external", {})),
            },
            "diagnosis": {
                "tcp_timeout_seconds": diagnosis.get("tcp_timeout_seconds"),
                "http_timeout_seconds": diagnosis.get("http_timeout_seconds"),
                "http_success_status": diagnosis.get("http_success_status"),
            },
            "routes": {
                "count": len(routes),
                "fallback_owner_count": len(fallback.get("owners", [])),
            },
        }


def load_config(
    config_path: str | Path | None = None,
    routes_path: str | Path | None = None,
) -> LoadedConfig:
    _load_local_env()
    resolved_config_path = _resolve_path(config_path or DEFAULT_CONFIG_PATH)
    config = _load_yaml_mapping(resolved_config_path)
    _validate_default_config(config)

    configured_routes_path = routes_path or config.get("runtime", {}).get("alert_routes_path")
    if not configured_routes_path:
        raise ConfigError("runtime.alert_routes_path is required")

    resolved_routes_path = _resolve_path(configured_routes_path)
    routes = _load_yaml_mapping(resolved_routes_path)
    _validate_routes(routes)
    _resolve_owner_env_references(routes)

    return LoadedConfig(
        project_root=PROJECT_ROOT,
        config_path=resolved_config_path,
        routes_path=resolved_routes_path,
        config=config,
        routes=routes,
    )


def _load_local_env() -> None:
    """Load simple KEY=VALUE pairs without overriding the process environment."""

    if not LOCAL_ENV_PATH.is_file():
        return
    for raw_line in LOCAL_ENV_PATH.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, value = line.split("=", 1)
        name = name.strip()
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
            continue
        value = value.strip()
        if (
            len(value) >= 2
            and value[0] == value[-1]
            and value[0] in {'"', "'"}
        ):
            value = value[1:-1]
        os.environ.setdefault(name, value)


def _load_yaml_mapping(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise ConfigError(f"config file does not exist: {path}")

    try:
        with path.open("r", encoding="utf-8") as file:
            data = yaml.safe_load(file) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"invalid YAML in {path}: {exc}") from exc

    if not isinstance(data, dict):
        raise ConfigError(f"YAML root must be a mapping: {path}")
    return data


def _validate_default_config(config: dict[str, Any]) -> None:
    for section in ("runtime", "feishu", "probes", "diagnosis"):
        if section not in config or not isinstance(config[section], dict):
            raise ConfigError(f"{section} section is required")

    probes = config["probes"]
    _validate_positive_int(probes, "retry_count")
    _validate_non_negative_int(probes, "retry_interval_seconds")
    _validate_positive_int(probes, "ssh_timeout_seconds")
    _validate_positive_int(probes, "command_timeout_seconds")

    for probe_key in ("internal", "external"):
        probe = probes.get(probe_key)
        if not isinstance(probe, dict):
            raise ConfigError(f"probes.{probe_key} section is required")
        _validate_probe_config(probe_key, probe)

    diagnosis = config["diagnosis"]
    _validate_positive_int(diagnosis, "tcp_timeout_seconds")
    _validate_positive_int(diagnosis, "http_timeout_seconds")
    _validate_positive_int(diagnosis, "http_success_status")

    feishu = config["feishu"]
    alert_bot = feishu.get("alert_bot")
    if not isinstance(alert_bot, dict):
        raise ConfigError("feishu.alert_bot section is required")
    sender_id_env = alert_bot.get("allowed_sender_id_env")
    if sender_id_env is not None and not _is_non_empty_string(sender_id_env):
        raise ConfigError(
            "feishu.alert_bot.allowed_sender_id_env must be a non-empty string"
        )

    app_notify = feishu.get("app_notify")
    if app_notify is not None:
        if not isinstance(app_notify, dict):
            raise ConfigError("feishu.app_notify must be a mapping")
        if type(app_notify.get("enabled", False)) is not bool:
            raise ConfigError("feishu.app_notify.enabled must be a boolean")
        for field in ("app_id_env", "app_secret_env", "domain_env"):
            if not _is_non_empty_string(app_notify.get(field)):
                raise ConfigError(f"feishu.app_notify.{field} must be a non-empty string")


def _validate_probe_config(probe_key: str, probe: dict[str, Any]) -> None:
    for field in ("name", "host", "user", "key_path_env"):
        if field not in probe:
            raise ConfigError(f"probes.{probe_key}.{field} is required")
    _validate_positive_int(probe, "port", prefix=f"probes.{probe_key}")


def _validate_routes(routes: dict[str, Any]) -> None:
    route_items = routes.get("routes", [])
    if not isinstance(route_items, list):
        raise ConfigError("routes must be a list")

    seen_ids: set[str] = set()
    for index, route in enumerate(route_items):
        if not isinstance(route, dict):
            raise ConfigError(f"routes[{index}] must be a mapping")

        route_id = route.get("id")
        if not _is_non_empty_string(route_id):
            raise ConfigError(f"routes[{index}].id must be a non-empty string")
        if route_id in seen_ids:
            raise ConfigError(f"duplicate route id: {route_id}")
        seen_ids.add(route_id)

        match = route.get("match")
        if not isinstance(match, dict):
            raise ConfigError(f"routes[{index}].match is required")

        has_exact = "monitor_name" in match
        has_regex = "monitor_name_regex" in match
        if has_exact == has_regex:
            raise ConfigError(
                f"routes[{index}].match must define exactly one of "
                "monitor_name or monitor_name_regex"
            )
        if has_exact and not _is_non_empty_string(match.get("monitor_name")):
            raise ConfigError(
                f"routes[{index}].match.monitor_name must be a non-empty string"
            )
        if has_regex:
            pattern = match.get("monitor_name_regex")
            if not _is_non_empty_string(pattern):
                raise ConfigError(
                    f"routes[{index}].match.monitor_name_regex must be a non-empty string"
                )
            try:
                re.compile(pattern)
            except re.error as exc:
                raise ConfigError(
                    f"routes[{index}].match.monitor_name_regex is invalid: {exc}"
                ) from exc

        if not _is_non_empty_string(route.get("service_name")):
            raise ConfigError(
                f"routes[{index}].service_name must be a non-empty string"
            )

        diagnosis = route.get("diagnosis")
        if not isinstance(diagnosis, dict):
            raise ConfigError(f"routes[{index}].diagnosis is required")
        diagnosis_type = diagnosis.get("type")
        if diagnosis_type == "tcp":
            _validate_tcp_diagnosis(index, diagnosis)
        elif diagnosis_type == "http":
            _validate_http_diagnosis(index, diagnosis)
        else:
            raise ConfigError(f"routes[{index}].diagnosis.type must be tcp or http")

        _validate_owners(route.get("owners"), f"routes[{index}].owners", required=True)

    fallback = routes.get("fallback", {})
    if not isinstance(fallback, dict):
        raise ConfigError("fallback must be a mapping")
    _validate_owners(fallback.get("owners", []), "fallback.owners", required=False)


def _validate_tcp_diagnosis(route_index: int, diagnosis: dict[str, Any]) -> None:
    label = f"routes[{route_index}].diagnosis"
    if "targets" in diagnosis:
        _reject_shared_target_fields(
            diagnosis,
            route_index,
            shared_fields=("host", "port"),
        )
        _validate_perspective_targets(
            route_index,
            diagnosis["targets"],
            target_validator=_validate_tcp_target,
        )
        return

    _validate_tcp_target(route_index, diagnosis, label)


def _validate_http_diagnosis(route_index: int, diagnosis: dict[str, Any]) -> None:
    label = f"routes[{route_index}].diagnosis"
    if "targets" in diagnosis:
        _reject_shared_target_fields(
            diagnosis,
            route_index,
            shared_fields=("url",),
        )
        _validate_perspective_targets(
            route_index,
            diagnosis["targets"],
            target_validator=_validate_http_target,
        )
        return

    _validate_http_target(route_index, diagnosis, label)


def _reject_shared_target_fields(
    diagnosis: dict[str, Any],
    route_index: int,
    *,
    shared_fields: tuple[str, ...],
) -> None:
    configured = [field for field in shared_fields if field in diagnosis]
    if configured:
        fields = ", ".join(configured)
        raise ConfigError(
            f"routes[{route_index}].diagnosis cannot define shared {fields} "
            "when targets is configured"
        )


def _validate_perspective_targets(
    route_index: int,
    targets: Any,
    *,
    target_validator: Any,
) -> None:
    if not isinstance(targets, dict):
        raise ConfigError(f"routes[{route_index}].diagnosis.targets must be a mapping")
    for perspective in ("internal", "external"):
        target = targets.get(perspective)
        label = f"routes[{route_index}].diagnosis.targets.{perspective}"
        if not isinstance(target, dict):
            raise ConfigError(f"{label} must be a mapping")
        target_validator(route_index, target, label)


def _validate_tcp_target(route_index: int, target: dict[str, Any], label: str) -> None:
    if not _is_non_empty_string(target.get("host")):
        raise ConfigError(f"{label}.host must be a non-empty string")
    port = target.get("port")
    if type(port) is not int or not 1 <= port <= 65535:
        raise ConfigError(f"{label}.port must be an integer from 1 to 65535")


def _validate_http_target(route_index: int, target: dict[str, Any], label: str) -> None:
    _validate_http_url(route_index, target.get("url"), label=f"{label}.url")


def _validate_http_url(route_index: int, value: Any, label: str | None = None) -> None:
    if label is None:
        label = f"routes[{route_index}].diagnosis.url"
    if not _is_non_empty_string(value):
        raise ConfigError(f"{label} must be a non-empty string")

    parsed = urlparse(value)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ConfigError(f"{label} must be a complete HTTP or HTTPS URL")


def _validate_owners(value: Any, label: str, required: bool) -> None:
    if not isinstance(value, list) or (required and not value):
        suffix = "a non-empty list" if required else "a list"
        raise ConfigError(f"{label} must be {suffix}")

    for index, owner in enumerate(value):
        owner_label = f"{label}[{index}]"
        if not isinstance(owner, dict):
            raise ConfigError(f"{owner_label} must be a mapping")
        if not _is_non_empty_string(owner.get("name")):
            raise ConfigError(f"{owner_label}.name must be a non-empty string")
        has_user_id = "feishu_user_id" in owner
        has_user_id_env = "feishu_user_id_env" in owner
        if not has_user_id and not has_user_id_env:
            raise ConfigError(
                f"{owner_label}.feishu_user_id or feishu_user_id_env is required"
            )
        if has_user_id and has_user_id_env:
            raise ConfigError(
                f"{owner_label} must define exactly one of "
                "feishu_user_id or feishu_user_id_env"
            )
        if has_user_id and not _is_non_empty_string(owner.get("feishu_user_id")):
            raise ConfigError(
                f"{owner_label}.feishu_user_id must be a non-empty string"
            )
        if has_user_id_env:
            env_name = owner.get("feishu_user_id_env")
            if not _is_non_empty_string(env_name):
                raise ConfigError(
                    f"{owner_label}.feishu_user_id_env must be a non-empty string"
                )
            if not _env_is_set(env_name):
                raise ConfigError(
                    f"environment variable referenced by "
                    f"{owner_label}.feishu_user_id_env is not configured"
                )


def _resolve_owner_env_references(routes: dict[str, Any]) -> None:
    owner_groups = [
        route.get("owners", [])
        for route in routes.get("routes", [])
        if isinstance(route, dict)
    ]
    fallback = routes.get("fallback", {})
    if isinstance(fallback, dict):
        owner_groups.append(fallback.get("owners", []))

    for owners in owner_groups:
        if not isinstance(owners, list):
            continue
        for owner in owners:
            if not isinstance(owner, dict) or "feishu_user_id_env" not in owner:
                continue
            env_name = str(owner.pop("feishu_user_id_env")).strip()
            owner["feishu_user_id"] = os.environ[env_name].strip()


def _is_non_empty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _resolve_path(path: str | Path) -> Path:
    candidate = Path(path).expanduser()
    if candidate.is_absolute():
        return candidate.resolve()
    return (PROJECT_ROOT / candidate).resolve()


def _validate_positive_int(
    mapping: dict[str, Any],
    key: str,
    prefix: str | None = None,
) -> None:
    value = mapping.get(key)
    label = f"{prefix}.{key}" if prefix else key
    if type(value) is not int or value <= 0:
        raise ConfigError(f"{label} must be a positive integer")


def _validate_non_negative_int(mapping: dict[str, Any], key: str) -> None:
    value = mapping.get(key)
    if type(value) is not int or value < 0:
        raise ConfigError(f"{key} must be a non-negative integer")


def _env_is_set(env_name: str | None) -> bool:
    return bool(env_name and os.getenv(env_name))


def _probe_summary(probe: dict[str, Any]) -> dict[str, Any]:
    key_path_env = probe.get("key_path_env", "")
    return {
        "name": probe.get("name"),
        "host_configured": bool(probe.get("host")),
        "port": probe.get("port"),
        "user_configured": bool(probe.get("user")),
        "key_path_env": key_path_env,
        "key_path_configured": _env_is_set(key_path_env),
    }
