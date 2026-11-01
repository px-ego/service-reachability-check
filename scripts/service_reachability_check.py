from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.alert_router import resolve_alert_route
from scripts.config_loader import ConfigError, load_config
from scripts.feishu_event_parser import parse_feishu_event
from scripts.feishu_notify import send_diagnostic_message
from scripts.manual_diagnosis_pipeline import run_manual_diagnosis
from scripts.probe_executor import ParamikoSSHCommandRunner


REDACTED = "[redacted]"


def configure_standard_streams() -> None:
    for stream_name in ("stdin", "stdout", "stderr"):
        stream = getattr(sys, stream_name)
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Service reachability diagnostics Hermes skill entrypoint."
    )
    parser.add_argument(
        "--config",
        default=None,
        help="Path to default.yaml. Defaults to config/default.yaml.",
    )
    parser.add_argument(
        "--routes",
        default=None,
        help="Path to alert_routes.yaml. Overrides runtime.alert_routes_path.",
    )
    parser.add_argument(
        "--summary-json",
        action="store_true",
        help="Print a machine-readable non-sensitive configuration summary.",
    )
    event_group = parser.add_mutually_exclusive_group()
    event_group.add_argument(
        "--event-json",
        default=None,
        help="Path to normalized Feishu event JSON, or '-' to read from stdin.",
    )
    event_group.add_argument(
        "--resolve-event-json",
        default=None,
        help=(
            "Path to normalized Feishu event JSON, or '-' for stdin; "
            "parse the alert and resolve its configured route."
        ),
    )
    event_group.add_argument(
        "--send-feishu-payload-json",
        default=None,
        help=(
            "Path to prepared Feishu custom bot payload JSON, or '-' for stdin; "
            "send it via configured webhook without running diagnosis."
        ),
    )
    event_group.add_argument(
        "--diagnose-event-json",
        default=None,
        help=(
            "Path to normalized Feishu event JSON, or '-' for stdin; "
            "run parse, route resolution, SSH probes, and diagnosis."
        ),
    )
    event_group.add_argument(
        "--hermes-event-json",
        default=None,
        help=(
            "Path to normalized Feishu event JSON, or '-' for stdin; "
            "run the Hermes full pipeline and send configured abnormal notifications."
        ),
    )
    parser.add_argument(
        "--send-feishu",
        action="store_true",
        help="Send Feishu only for sendable abnormal manual diagnosis results.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    configure_standard_streams()

    parser = build_parser()
    args = parser.parse_args(argv)
    if args.send_feishu and not args.diagnose_event_json:
        parser.error("--send-feishu requires --diagnose-event-json")

    try:
        loaded = load_config(config_path=args.config, routes_path=args.routes)
    except ConfigError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2

    if args.send_feishu_payload_json:
        try:
            payload = read_payload_json(args.send_feishu_payload_json)
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            print(f"payload json error: {exc}", file=sys.stderr)
            return 2

        result = send_diagnostic_message(
            payload,
            loaded.config.get("feishu", {}),
        )
        print_json(result.to_dict(), loaded.routes)
        return 0

    if args.hermes_event_json:
        try:
            event = read_event_json(args.hermes_event_json)
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            print(f"event json error: {exc}", file=sys.stderr)
            return 2

        result = run_manual_diagnosis(
            event=event,
            config=loaded.config,
            routes_config=loaded.routes,
            runner=ParamikoSSHCommandRunner(),
            send_feishu=True,
        )
        print_json(result, loaded.routes)
        return 0

    if args.diagnose_event_json:
        try:
            event = read_event_json(args.diagnose_event_json)
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            print(f"event json error: {exc}", file=sys.stderr)
            return 2

        result = run_manual_diagnosis(
            event=event,
            config=loaded.config,
            routes_config=loaded.routes,
            runner=ParamikoSSHCommandRunner(),
            send_feishu=args.send_feishu,
        )
        print_json(result, loaded.routes)
        return 0

    event_json_path = args.resolve_event_json or args.event_json
    if event_json_path:
        try:
            event = read_event_json(event_json_path)
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            print(f"event json error: {exc}", file=sys.stderr)
            return 2

        parse_result = parse_feishu_event(event, loaded.config.get("feishu", {}))
        if (
            args.resolve_event_json
            and parse_result.status == "parsed"
            and parse_result.alert is not None
        ):
            result = resolve_alert_route(parse_result.alert, loaded.routes)
        else:
            result = parse_result
        print_json(result.to_dict(), loaded.routes)
        return 0

    summary = loaded.summary()
    if args.summary_json:
        print(json.dumps(summary, ensure_ascii=False, indent=2))
    else:
        print_human_summary(summary)
    return 0


def print_json(payload: dict, routes: dict) -> None:
    sensitive_values = _owner_user_ids(routes)
    sanitized = _sanitize_cli_value(payload, sensitive_values)
    print(json.dumps(sanitized, ensure_ascii=False, indent=2))


def _owner_user_ids(routes: dict) -> tuple[str, ...]:
    values: list[str] = []
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
            if not isinstance(owner, dict):
                continue
            user_id = owner.get("feishu_user_id")
            if isinstance(user_id, str) and user_id and user_id not in values:
                values.append(user_id)
    return tuple(values)


def _sanitize_cli_value(value: object, sensitive_values: tuple[str, ...]) -> object:
    if isinstance(value, dict):
        return {
            key: (
                REDACTED
                if key == "feishu_user_id"
                else _sanitize_cli_value(item, sensitive_values)
            )
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_sanitize_cli_value(item, sensitive_values) for item in value]
    if isinstance(value, tuple):
        return [_sanitize_cli_value(item, sensitive_values) for item in value]
    if isinstance(value, str):
        sanitized = value
        for sensitive_value in sensitive_values:
            sanitized = sanitized.replace(sensitive_value, REDACTED)
        return sanitized
    return value


def read_event_json(path: str) -> dict:
    return read_json_object(path, "event")


def read_payload_json(path: str) -> dict:
    return read_json_object(path, "payload")


def read_json_object(path: str, label: str) -> dict:
    if path == "-":
        raw_payload = sys.stdin.read()
    else:
        raw_payload = Path(path).read_text(encoding="utf-8")

    raw_payload = raw_payload.removeprefix("\ufeff")
    payload = json.loads(raw_payload)
    if not isinstance(payload, dict):
        raise ValueError(f"{label} JSON root must be an object")
    return payload


def print_human_summary(summary: dict) -> None:
    print("service-reachability-check configuration")
    print(f"- project root: {summary['project_root']}")
    print(f"- config: {summary['config_path']}")
    print(f"- alert routes: {summary['routes_path']}")
    print(f"- dry run: {summary['runtime']['dry_run']}")
    print(
        "- Feishu: "
        f"enabled={summary['feishu']['enabled']}, "
        f"webhook_env={summary['feishu']['webhook_env']} "
        f"(configured={summary['feishu']['webhook_configured']}), "
        f"secret_env={summary['feishu']['secret_env']} "
        f"(configured={summary['feishu']['secret_configured']})"
    )
    print(
        "- alert bots: "
        + ", ".join(summary["feishu"]["allowed_alert_bot_names"])
    )
    print(
        "- alert bot sender id: "
        f"env={summary['feishu']['alert_bot_sender_id_env']} "
        f"(configured={summary['feishu']['alert_bot_sender_id_configured']})"
    )
    app_notify = summary["feishu"]["app_notify"]
    print(
        "- Feishu application bot: "
        f"enabled={app_notify['enabled']}, "
        f"app_id_configured={app_notify['app_id_configured']}, "
        f"app_secret_configured={app_notify['app_secret_configured']}"
    )
    print(
        "- probes: "
        f"retry_count={summary['probes']['retry_count']}, "
        f"retry_interval_seconds={summary['probes']['retry_interval_seconds']}"
    )
    for probe_key in ("internal", "external"):
        probe = summary["probes"][probe_key]
        print(
            f"  - {probe_key}: "
            f"name={probe['name']}, "
            f"host_configured={probe['host_configured']}, "
            f"user_configured={probe['user_configured']}, "
            f"port={probe['port']}, "
            f"key_path_env={probe['key_path_env']} "
            f"(configured={probe['key_path_configured']})"
        )
    print(
        "- diagnosis: "
        f"tcp_timeout_seconds={summary['diagnosis']['tcp_timeout_seconds']}, "
        f"http_timeout_seconds={summary['diagnosis']['http_timeout_seconds']}, "
        f"http_success_status={summary['diagnosis']['http_success_status']}"
    )
    print(
        "- routes: "
        f"count={summary['routes']['count']}, "
        f"fallback_owner_count={summary['routes']['fallback_owner_count']}"
    )


if __name__ == "__main__":
    raise SystemExit(main())
