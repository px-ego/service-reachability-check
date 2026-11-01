from __future__ import annotations

from typing import Any, Callable

from scripts import feishu_notify
from scripts.alert_router import resolve_alert_route
from scripts.diagnosis_engine import DiagnosisResult, diagnose_reachability
from scripts.feishu_event_parser import parse_feishu_event
from scripts.feishu_notify import (
    FeishuSendResult,
    build_feishu_diagnostic_message,
    build_feishu_route_error_message,
)
from scripts.probe_executor import CommandRunner, ProbeExecutionError, execute_route_probes


Sender = Callable[[dict[str, Any], dict[str, Any]], FeishuSendResult]


def run_manual_diagnosis(
    *,
    event: dict[str, Any],
    config: dict[str, Any],
    routes_config: dict[str, Any],
    runner: CommandRunner,
    send_feishu: bool = False,
    sender: Sender | None = None,
) -> dict[str, Any]:
    resolved_sender = sender or feishu_notify.send_diagnostic_message
    parse_result = parse_feishu_event(event, config.get("feishu", {}))
    if parse_result.status != "parsed" or parse_result.alert is None:
        return parse_result.to_dict()

    route_result = resolve_alert_route(parse_result.alert, routes_config)
    if route_result.status == "error":
        notification = build_feishu_route_error_message(route_result)
        result = route_result.to_dict()
        result["notification"] = notification.to_dict()
        _maybe_send(result, notification.payload, config, send_feishu, resolved_sender)
        return result

    try:
        probe_outcomes = execute_route_probes(route_result, config, runner)
    except ProbeExecutionError as exc:
        diagnosis = DiagnosisResult(
            status="error",
            should_notify=False,
            reason="probe_execution_error",
            alert=route_result.alert,
            route=route_result.route,
            error_details={"message": str(exc)},
        )
    else:
        diagnosis = diagnose_reachability(route_result, probe_outcomes)

    notification = build_feishu_diagnostic_message(diagnosis)
    result = diagnosis.to_dict()
    result["notification"] = notification.to_dict()
    _maybe_send(result, notification.payload, config, send_feishu, resolved_sender)
    return result


def _maybe_send(
    result: dict[str, Any],
    payload: dict[str, Any] | None,
    config: dict[str, Any],
    send_feishu: bool,
    sender: Sender,
) -> None:
    if not send_feishu:
        result["send_result"] = {
            "success": False,
            "reason": "send_not_requested",
        }
        return
    if payload is None:
        result["send_result"] = {
            "success": False,
            "reason": "no_sendable_payload",
        }
        return
    result["send_result"] = sender(payload, config.get("feishu", {})).to_dict()
