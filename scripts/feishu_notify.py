from __future__ import annotations

import base64
import copy
import hashlib
import html
import hmac
import json
import os
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable

from scripts.alert_router import RouteResolutionResult
from scripts.diagnosis_engine import DiagnosisResult, ProbeOutcome


@dataclass(frozen=True)
class FeishuEnvStatus:
    enabled: bool
    webhook_env: str
    webhook_configured: bool
    secret_env: str
    secret_configured: bool


@dataclass(frozen=True)
class FeishuMessageBuildResult:
    should_send: bool
    reason: str
    payload: dict[str, Any] | None = None
    private_payload: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "should_send": self.should_send,
            "reason": self.reason,
        }
        if self.payload is not None:
            data["payload"] = self.payload
        if self.private_payload is not None:
            data["private_payload"] = self.private_payload
        return data


@dataclass(frozen=True)
class FeishuHttpResponse:
    status_code: int
    body: str = ""


@dataclass(frozen=True)
class FeishuSendResult:
    success: bool
    reason: str
    status_code: int | None = None
    response_body: Any | None = None

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "success": self.success,
            "reason": self.reason,
        }
        if self.status_code is not None:
            data["status_code"] = self.status_code
        if self.response_body is not None:
            data["response_body"] = self.response_body
        return data


@dataclass(frozen=True)
class FeishuFanoutResult:
    success: bool
    reason: str
    group_result: FeishuSendResult
    private_requested: int
    private_results: tuple[FeishuSendResult, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "reason": self.reason,
            "group": self.group_result.to_dict(),
            "private": {
                "requested": self.private_requested,
                "attempted": len(self.private_results),
                "succeeded": sum(result.success for result in self.private_results),
                "results": [result.to_dict() for result in self.private_results],
            },
        }


@dataclass(frozen=True)
class _FeishuAppSendContext:
    base_url: str
    auth_headers: dict[str, str]
    post: Callable[[str, dict[str, str], bytes, int], FeishuHttpResponse]
    timeout_seconds: int
    redaction_values: tuple[str, ...]


def describe_feishu_env(feishu_config: dict) -> FeishuEnvStatus:
    """Return non-sensitive Feishu environment status for config summaries."""

    webhook_env = feishu_config.get("webhook_env", "")
    secret_env = feishu_config.get("secret_env", "")
    return FeishuEnvStatus(
        enabled=bool(feishu_config.get("enabled", False)),
        webhook_env=webhook_env,
        webhook_configured=bool(webhook_env and os.getenv(webhook_env)),
        secret_env=secret_env,
        secret_configured=bool(secret_env and os.getenv(secret_env)),
    )


def build_feishu_diagnostic_message(
    diagnosis_result: DiagnosisResult,
) -> FeishuMessageBuildResult:
    if diagnosis_result.status == "normal":
        return FeishuMessageBuildResult(
            should_send=False,
            reason="normal_result",
        )
    if diagnosis_result.status == "abnormal" and not diagnosis_result.should_notify:
        return FeishuMessageBuildResult(
            should_send=False,
            reason="normal_result",
        )
    if diagnosis_result.alert is None:
        return FeishuMessageBuildResult(
            should_send=False,
            reason="incomplete_diagnosis_result",
        )

    alert = diagnosis_result.alert
    route = diagnosis_result.route
    if route is None:
        return FeishuMessageBuildResult(
            should_send=False,
            reason="incomplete_diagnosis_result",
        )

    service_name = _safe_text(route.service_name or alert.monitor_name)
    alert_time = _safe_text(alert.alert_time) or "上游未透传"
    alert_reason = _safe_text(alert.reason) or "上游未透传"
    if diagnosis_result.status == "error":
        elements = [
            _card_div(
                "**处理结论**\n诊断执行失败，未获得完整的双侧探测结果；"
                "系统没有将执行过程交给大模型补充。"
            ),
            _card_hr(),
            _card_div(
                f"**告警对象**：{_safe_text(alert.monitor_name)}\n"
                f"**告警时间**：{alert_time}\n"
                f"**失败原因**：{alert_reason}"
            ),
            _card_hr(),
            _card_div("**建议操作**：检查 probe SSH、命令依赖和运行配置后再重试。"),
        ]
        return _build_paired_owner_message(
            reason="diagnosis_execution_error",
            title=f"⚠️ 诊断执行异常｜{service_name}",
            template="orange",
            elements=elements,
            owners=route.owners,
        )

    if diagnosis_result.status != "abnormal":
        return FeishuMessageBuildResult(
            should_send=False,
            reason="non_abnormal_result",
        )

    elements = [
        _card_div(
            "**初步判断**\n"
            + (_safe_text(diagnosis_result.finding) or "当前探测结果异常，建议人工复核。")
        ),
        _card_hr(),
        _card_div(
            f"**告警对象**：{_safe_text(alert.monitor_name)}\n"
            f"**诊断类型**：{_safe_text(route.diagnosis.get('type', '')).upper()}\n"
            f"**告警时间**：{alert_time}\n"
            f"**失败原因**：{alert_reason}"
        ),
        _card_hr(),
    ]
    elements.extend(_probe_card_elements(diagnosis_result.probes, route.diagnosis))
    if diagnosis_result.suggested_checks:
        elements.extend(
            [
                _card_hr(),
                _card_div(
                    "**建议排查**\n"
                    + "\n".join(
                        f"• {_safe_text(check)}"
                        for check in diagnosis_result.suggested_checks
                    )
                ),
            ]
        )
    elements.extend([_card_hr(), _card_div(f"**路由**：{_safe_text(route.id)}")])

    return _build_paired_owner_message(
        reason="abnormal_diagnosis",
        title=f"🚨 服务可达性异常｜{service_name}",
        template="red",
        elements=elements,
        owners=route.owners,
    )


def build_feishu_route_error_message(
    route_result: RouteResolutionResult,
) -> FeishuMessageBuildResult:
    if route_result.status != "error" or route_result.reason not in (
        "route_not_found",
        "route_conflict",
    ):
        return FeishuMessageBuildResult(
            should_send=False,
            reason="not_route_error",
        )

    alert = route_result.alert
    error_label = (
        "映射缺失"
        if route_result.reason == "route_not_found"
        else "映射冲突"
    )
    conflict_text = ""
    if route_result.matched_route_ids:
        conflict_text = (
            "\n**冲突规则**："
            + ", ".join(_safe_text(route_id) for route_id in route_result.matched_route_ids)
        )

    elements = [
        _card_div(
            f"**错误类型**：{error_label}\n"
            "**处理结果**：未执行探测，请先补齐或修正告警映射表。"
            + conflict_text
        ),
        _card_hr(),
        _card_div(
            f"**告警对象**：{_safe_text(alert.monitor_name)}\n"
            f"**告警时间**：{_safe_text(alert.alert_time) or '上游未透传'}\n"
            f"**失败原因**：{_safe_text(alert.reason) or '上游未透传'}"
        ),
    ]

    return _build_paired_owner_message(
        reason=route_result.reason or "route_error",
        title=f"⚠️ 诊断配置异常｜{_safe_text(alert.monitor_name)}",
        template="orange",
        elements=elements,
        owners=route_result.fallback_owners,
    )


def build_feishu_runtime_error_message(
    monitor_name: str,
    owners: list[dict[str, str]] | tuple[dict[str, str], ...] = (),
) -> FeishuMessageBuildResult:
    """Build a concise fail-closed card without exposing exception details."""

    safe_monitor_name = _safe_text(monitor_name) or "未知监控对象"
    return _build_paired_owner_message(
        reason="runtime_error",
        title=f"⚠️ 诊断执行异常｜{safe_monitor_name}",
        template="orange",
        elements=[
            _card_div(
                "**处理结论**\n自动诊断未能完成，消息已被安全拦截，"
                "不会转交大模型生成回复。"
            ),
            _card_hr(),
            _card_div("**建议操作**：检查 Hermes Gateway 日志和诊断运行配置。"),
        ],
        owners=owners,
    )


def send_diagnostic_message(
    payload: dict[str, Any],
    feishu_config: dict[str, Any],
    *,
    timeout_seconds: int = 10,
    post_fn: Callable[[str, bytes, int], FeishuHttpResponse] | None = None,
    timestamp_fn: Callable[[], int] | None = None,
) -> FeishuSendResult:
    """Send a prepared Feishu custom bot payload without exposing secrets."""
    if not feishu_config.get("enabled", False):
        return FeishuSendResult(success=False, reason="feishu_disabled")

    if not _is_valid_payload(payload):
        return FeishuSendResult(success=False, reason="invalid_payload")

    webhook_env = str(feishu_config.get("webhook_env", "")).strip()
    secret_env = str(feishu_config.get("secret_env", "")).strip()
    webhook_url = os.getenv(webhook_env, "") if webhook_env else ""
    secret = os.getenv(secret_env, "") if secret_env else ""
    redaction_values = tuple(value for value in (webhook_url, secret) if value)

    if not webhook_url:
        return FeishuSendResult(success=False, reason="missing_webhook")

    send_payload = copy.deepcopy(payload)
    if secret:
        timestamp = str((timestamp_fn or _current_timestamp)())
        send_payload["timestamp"] = timestamp
        send_payload["sign"] = _build_feishu_sign(timestamp, secret)

    try:
        request_body = json.dumps(send_payload, ensure_ascii=False).encode("utf-8")
    except (TypeError, ValueError):
        return FeishuSendResult(success=False, reason="invalid_payload")

    post = post_fn or _post_json
    try:
        response = post(webhook_url, request_body, timeout_seconds)
    except (TimeoutError, socket.timeout) as exc:
        return FeishuSendResult(
            success=False,
            reason="request_timeout",
            response_body=_redact_text(str(exc), redaction_values),
        )
    except urllib.error.URLError as exc:
        return FeishuSendResult(
            success=False,
            reason="request_failed",
            response_body=_redact_text(str(exc.reason), redaction_values),
        )
    except ValueError as exc:
        return FeishuSendResult(
            success=False,
            reason="request_failed",
            response_body=_redact_text(str(exc), redaction_values),
        )
    except OSError as exc:
        return FeishuSendResult(
            success=False,
            reason="request_failed",
            response_body=_redact_text(str(exc), redaction_values),
        )

    response_body = _parse_response_body(response.body, redaction_values)
    if response.status_code < 200 or response.status_code >= 300:
        return FeishuSendResult(
            success=False,
            reason="http_error",
            status_code=response.status_code,
            response_body=response_body,
        )

    business_code = _extract_business_code(response_body)
    if business_code is not None and business_code != 0:
        return FeishuSendResult(
            success=False,
            reason="feishu_error",
            status_code=response.status_code,
            response_body=response_body,
        )

    return FeishuSendResult(
        success=True,
        reason="sent",
        status_code=response.status_code,
        response_body=response_body,
    )


def send_app_diagnostic_message(
    payload: dict[str, Any],
    app_config: dict[str, Any],
    *,
    chat_id: str,
    reply_to_message_id: str = "",
    timeout_seconds: int = 10,
    post_fn: Callable[
        [str, dict[str, str], bytes, int], FeishuHttpResponse
    ]
    | None = None,
) -> FeishuSendResult:
    """Compatibility wrapper that sends only the group card."""

    if not _is_interactive_payload(payload):
        return FeishuSendResult(success=False, reason="invalid_payload")
    if not isinstance(chat_id, str) or not chat_id.strip():
        return FeishuSendResult(success=False, reason="missing_chat_id")

    context = _create_app_send_context(
        app_config,
        timeout_seconds=timeout_seconds,
        post_fn=post_fn,
    )
    if isinstance(context, FeishuSendResult):
        return context
    return _send_group_with_context(
        context,
        payload,
        chat_id=chat_id,
        reply_to_message_id=reply_to_message_id,
    )


def send_app_notification_fanout(
    payload: dict[str, Any],
    private_payload: dict[str, Any],
    app_config: dict[str, Any],
    *,
    chat_id: str,
    owner_open_ids: list[str] | tuple[str, ...],
    reply_to_message_id: str = "",
    timeout_seconds: int = 10,
    post_fn: Callable[
        [str, dict[str, str], bytes, int], FeishuHttpResponse
    ]
    | None = None,
) -> FeishuFanoutResult:
    """Send one group card and one private card per unique owner Open ID."""

    unique_owner_ids = tuple(
        dict.fromkeys(
            owner_id.strip()
            for owner_id in owner_open_ids
            if isinstance(owner_id, str) and owner_id.strip()
        )
    )
    if not _is_interactive_payload(payload):
        group_result = FeishuSendResult(success=False, reason="invalid_payload")
    elif not isinstance(chat_id, str) or not chat_id.strip():
        group_result = FeishuSendResult(success=False, reason="missing_chat_id")
    else:
        group_result = None

    private_payload_valid = _is_interactive_payload(private_payload)
    context = _create_app_send_context(
        app_config,
        timeout_seconds=timeout_seconds,
        post_fn=post_fn,
        extra_redaction_values=unique_owner_ids,
    )
    if isinstance(context, FeishuSendResult):
        return FeishuFanoutResult(
            success=False,
            reason="failed",
            group_result=group_result or context,
            private_requested=len(unique_owner_ids),
        )

    if group_result is None:
        group_result = _send_group_with_context(
            context,
            payload,
            chat_id=chat_id,
            reply_to_message_id=reply_to_message_id,
        )

    private_results: list[FeishuSendResult] = []
    for owner_open_id in unique_owner_ids:
        if not private_payload_valid:
            private_results.append(
                FeishuSendResult(success=False, reason="invalid_private_payload")
            )
            continue
        private_results.append(
            _send_private_with_context(
                context,
                private_payload,
                owner_open_id=owner_open_id,
            )
        )

    if not unique_owner_ids:
        aggregate_reason = "missing_private_recipients"
        success = False
    else:
        successes = int(group_result.success) + sum(
            result.success for result in private_results
        )
        expected = 1 + len(private_results)
        success = successes == expected
        if success:
            aggregate_reason = "sent"
        elif successes:
            aggregate_reason = "partial_failure"
        else:
            aggregate_reason = "failed"

    return FeishuFanoutResult(
        success=success,
        reason=aggregate_reason,
        group_result=group_result,
        private_requested=len(unique_owner_ids),
        private_results=tuple(private_results),
    )


def _create_app_send_context(
    app_config: dict[str, Any],
    *,
    timeout_seconds: int,
    post_fn: Callable[
        [str, dict[str, str], bytes, int], FeishuHttpResponse
    ]
    | None,
    extra_redaction_values: tuple[str, ...] = (),
) -> _FeishuAppSendContext | FeishuSendResult:
    if not app_config.get("enabled", False):
        return FeishuSendResult(success=False, reason="feishu_app_disabled")

    app_id_env = str(app_config.get("app_id_env", "")).strip()
    app_secret_env = str(app_config.get("app_secret_env", "")).strip()
    domain_env = str(app_config.get("domain_env", "")).strip()
    app_id = os.getenv(app_id_env, "").strip() if app_id_env else ""
    app_secret = os.getenv(app_secret_env, "").strip() if app_secret_env else ""
    domain = os.getenv(domain_env, "").strip() if domain_env else ""
    redaction_values = tuple(
        value
        for value in (app_id, app_secret, *extra_redaction_values)
        if value
    )

    if not app_id or not app_secret:
        return FeishuSendResult(success=False, reason="missing_app_credentials")

    base_url = _feishu_open_api_base(domain)
    post = post_fn or _post_json_with_headers
    token_body = json.dumps(
        {"app_id": app_id, "app_secret": app_secret},
        ensure_ascii=False,
    ).encode("utf-8")
    token_result = _call_app_api(
        post,
        f"{base_url}/open-apis/auth/v3/tenant_access_token/internal",
        {"Content-Type": "application/json; charset=utf-8"},
        token_body,
        timeout_seconds,
        redaction_values,
        error_prefix="token",
    )
    if isinstance(token_result, FeishuSendResult):
        return token_result

    token_response, token_payload = token_result
    access_token = ""
    if isinstance(token_payload, dict):
        access_token = str(token_payload.get("tenant_access_token", "")).strip()
    if not _api_response_succeeded(token_response, token_payload) or not access_token:
        safe_token_payload = _sanitize_response_value(
            token_payload,
            redaction_values + ((access_token,) if access_token else ()),
        )
        return FeishuSendResult(
            success=False,
            reason="token_error",
            status_code=token_response.status_code,
            response_body=safe_token_payload,
        )

    return _FeishuAppSendContext(
        base_url=base_url,
        auth_headers={
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json; charset=utf-8",
        },
        post=post,
        timeout_seconds=timeout_seconds,
        redaction_values=redaction_values + (access_token,),
    )


def _send_group_with_context(
    context: _FeishuAppSendContext,
    payload: dict[str, Any],
    *,
    chat_id: str,
    reply_to_message_id: str,
) -> FeishuSendResult:
    card_content = json.dumps(payload["card"], ensure_ascii=False)
    message_payload = {
        "msg_type": "interactive",
        "content": card_content,
    }

    if reply_to_message_id:
        reply_url = (
            f"{context.base_url}/open-apis/im/v1/messages/"
            f"{urllib.parse.quote(reply_to_message_id, safe='')}/reply"
        )
        reply_result = _call_app_api(
            context.post,
            reply_url,
            context.auth_headers,
            json.dumps(message_payload, ensure_ascii=False).encode("utf-8"),
            context.timeout_seconds,
            context.redaction_values,
            error_prefix="reply",
        )
        if isinstance(reply_result, FeishuSendResult):
            # An ambiguous network failure may already have delivered the reply.
            # Do not fall back and risk sending a duplicate top-level card.
            return reply_result
        reply_response, reply_payload = reply_result
        if _api_response_succeeded(reply_response, reply_payload):
            return FeishuSendResult(
                success=True,
                reason="sent",
                status_code=reply_response.status_code,
                response_body=_sanitize_response_value(
                    reply_payload,
                    context.redaction_values,
                ),
            )

    top_level_body = {
        "receive_id": chat_id.strip(),
        **message_payload,
    }
    send_result = _call_app_api(
        context.post,
        f"{context.base_url}/open-apis/im/v1/messages?receive_id_type=chat_id",
        context.auth_headers,
        json.dumps(top_level_body, ensure_ascii=False).encode("utf-8"),
        context.timeout_seconds,
        context.redaction_values,
        error_prefix="send",
    )
    if isinstance(send_result, FeishuSendResult):
        return send_result
    response, response_payload = send_result
    if not _api_response_succeeded(response, response_payload):
        return FeishuSendResult(
            success=False,
            reason="feishu_app_error",
            status_code=response.status_code,
            response_body=_sanitize_response_value(
                response_payload,
                context.redaction_values,
            ),
        )
    return FeishuSendResult(
        success=True,
        reason="sent_after_reply_failure" if reply_to_message_id else "sent",
        status_code=response.status_code,
        response_body=_sanitize_response_value(
            response_payload,
            context.redaction_values,
        ),
    )


def _send_private_with_context(
    context: _FeishuAppSendContext,
    payload: dict[str, Any],
    *,
    owner_open_id: str,
) -> FeishuSendResult:
    request_body = {
        "receive_id": owner_open_id,
        "msg_type": "interactive",
        "content": json.dumps(payload["card"], ensure_ascii=False),
    }
    send_result = _call_app_api(
        context.post,
        f"{context.base_url}/open-apis/im/v1/messages?receive_id_type=open_id",
        context.auth_headers,
        json.dumps(request_body, ensure_ascii=False).encode("utf-8"),
        context.timeout_seconds,
        context.redaction_values,
        error_prefix="private",
    )
    if isinstance(send_result, FeishuSendResult):
        return send_result
    response, response_payload = send_result
    if not _api_response_succeeded(response, response_payload):
        return FeishuSendResult(
            success=False,
            reason="feishu_app_error",
            status_code=response.status_code,
            response_body=_sanitize_response_value(
                response_payload,
                context.redaction_values,
            ),
        )
    return FeishuSendResult(
        success=True,
        reason="sent",
        status_code=response.status_code,
        response_body=_sanitize_response_value(
            response_payload,
            context.redaction_values,
        ),
    )


def _call_app_api(
    post: Callable[[str, dict[str, str], bytes, int], FeishuHttpResponse],
    url: str,
    headers: dict[str, str],
    body: bytes,
    timeout_seconds: int,
    redaction_values: tuple[str, ...],
    *,
    error_prefix: str,
) -> tuple[FeishuHttpResponse, Any] | FeishuSendResult:
    try:
        response = post(url, headers, body, timeout_seconds)
    except (TimeoutError, socket.timeout) as exc:
        return FeishuSendResult(
            success=False,
            reason=f"{error_prefix}_request_timeout",
            response_body=_redact_text(str(exc), redaction_values),
        )
    except urllib.error.URLError as exc:
        return FeishuSendResult(
            success=False,
            reason=f"{error_prefix}_request_failed",
            response_body=_redact_text(str(exc.reason), redaction_values),
        )
    except (ValueError, OSError) as exc:
        return FeishuSendResult(
            success=False,
            reason=f"{error_prefix}_request_failed",
            response_body=_redact_text(str(exc), redaction_values),
        )

    payload = _parse_response_body(response.body, redaction_values)
    return response, payload


def _api_response_succeeded(response: FeishuHttpResponse, payload: Any) -> bool:
    if response.status_code < 200 or response.status_code >= 300:
        return False
    business_code = _extract_business_code(payload)
    return business_code is None or business_code == 0


def _feishu_open_api_base(domain: str) -> str:
    normalized = domain.strip().lower()
    if normalized in {"lark", "larksuite", "open.larksuite.com"}:
        return "https://open.larksuite.com"
    return "https://open.feishu.cn"


def _post_json(webhook_url: str, request_body: bytes, timeout_seconds: int) -> FeishuHttpResponse:
    request = urllib.request.Request(
        webhook_url,
        data=request_body,
        headers={"Content-Type": "application/json; charset=utf-8"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            body = response.read().decode("utf-8", errors="replace")
            return FeishuHttpResponse(
                status_code=response.getcode(),
                body=body,
            )
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        return FeishuHttpResponse(status_code=exc.code, body=body)


def _post_json_with_headers(
    url: str,
    headers: dict[str, str],
    request_body: bytes,
    timeout_seconds: int,
) -> FeishuHttpResponse:
    request = urllib.request.Request(
        url,
        data=request_body,
        headers=headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            body = response.read().decode("utf-8", errors="replace")
            return FeishuHttpResponse(
                status_code=response.getcode(),
                body=body,
            )
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        return FeishuHttpResponse(status_code=exc.code, body=body)


def _text_payload(text: str) -> dict[str, Any]:
    return {
        "msg_type": "text",
        "content": {
            "text": text,
        },
    }


def _interactive_payload(
    *,
    title: str,
    template: str,
    elements: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "msg_type": "interactive",
        "card": {
            "config": {"wide_screen_mode": True},
            "header": {
                "template": template,
                "title": {
                    "tag": "plain_text",
                    "content": title,
                },
            },
            "elements": elements,
        },
    }


def _card_div(content: str) -> dict[str, Any]:
    return {
        "tag": "div",
        "text": {
            "tag": "lark_md",
            "content": content,
        },
    }


def _card_hr() -> dict[str, str]:
    return {"tag": "hr"}


def _build_paired_owner_message(
    *,
    reason: str,
    title: str,
    template: str,
    elements: list[dict[str, Any]],
    owners: list[dict[str, str]] | tuple[dict[str, str], ...],
) -> FeishuMessageBuildResult:
    group_elements = copy.deepcopy(elements)
    private_elements = copy.deepcopy(elements)
    owner_names = _owner_names(owners) or "临时负责人"
    owner_mentions = _owner_mentions(owners) or owner_names
    for target_elements, owner_text in (
        (group_elements, owner_mentions),
        (private_elements, owner_names),
    ):
        target_elements.extend(
            [
                _card_hr(),
                _card_div(f"**负责人**：{owner_text}"),
            ]
        )
    return FeishuMessageBuildResult(
        should_send=True,
        reason=reason,
        payload=_interactive_payload(
            title=title,
            template=template,
            elements=group_elements,
        ),
        private_payload=_interactive_payload(
            title=title,
            template=template,
            elements=private_elements,
        ),
    )


def _owner_names(
    owners: list[dict[str, str]] | tuple[dict[str, str], ...],
) -> str:
    names: list[str] = []
    for owner in owners:
        name = str(owner.get("name", "")).strip()
        if name:
            names.append(_safe_text(name, limit=80))
    return "、".join(names)


def _owner_mentions(
    owners: list[dict[str, str]] | tuple[dict[str, str], ...],
) -> str:
    mentions: list[str] = []
    seen_ids: set[str] = set()
    for owner in owners:
        owner_id = str(owner.get("feishu_user_id", "")).strip()
        if not owner_id or owner_id in seen_ids:
            continue
        seen_ids.add(owner_id)
        safe_owner_id = html.escape(owner_id[:160], quote=True)
        mentions.append(f"<at id={safe_owner_id}></at>")
    return " ".join(mentions)


def _target_text(diagnosis: dict[str, Any]) -> str:
    diagnosis_type = diagnosis.get("type")
    targets = diagnosis.get("targets")
    if isinstance(targets, dict):
        rendered_targets = []
        for perspective in ("internal", "external"):
            target = targets.get(perspective)
            if isinstance(target, dict):
                rendered_targets.append(
                    f"{perspective}={_target_text({'type': diagnosis_type, **target})}"
                )
        if rendered_targets:
            return "; ".join(rendered_targets)

    if diagnosis_type == "tcp":
        host = _safe_text(diagnosis.get("host", ""))
        port = _safe_text(diagnosis.get("port", ""))
        return f"TCP {host}:{port}"
    if diagnosis_type == "http":
        return f"HTTP {_safe_text(diagnosis.get('url', ''))}"
    return _safe_text(diagnosis_type or "unknown")


def _target_for_perspective(diagnosis: dict[str, Any], perspective: str) -> str:
    targets = diagnosis.get("targets")
    if isinstance(targets, dict) and isinstance(targets.get(perspective), dict):
        return _target_text(
            {"type": diagnosis.get("type"), **targets[perspective]}
        )
    return _target_text(diagnosis)


def _probe_card_elements(
    probes: tuple[ProbeOutcome, ...],
    diagnosis: dict[str, Any],
) -> list[dict[str, Any]]:
    if not probes:
        return [_card_div("**探测结果**\n未获得探测结果")]

    elements: list[dict[str, Any]] = []
    order = {"internal": 0, "external": 1}
    ordered = sorted(probes, key=lambda probe: order.get(probe.perspective, 99))
    for probe in ordered:
        label = "内网视角" if probe.perspective == "internal" else "外网视角"
        status = "✅ 成功" if probe.success else "❌ 失败"
        evidence = (
            _safe_text(probe.evidence, limit=240)
            if probe.success
            else _safe_text(probe.final_error or probe.evidence, limit=240)
        )
        elements.append(
            _card_div(
                f"**{label}**　{status}\n"
                f"**目标**：{_target_for_perspective(diagnosis, probe.perspective)}\n"
                f"**尝试**：{probe.attempts} 次\n"
                f"**证据**：{evidence or '未提供'}"
            )
        )
    return elements


def _safe_text(value: Any, limit: int = 500) -> str:
    text = "" if value is None else str(value)
    if len(text) > limit:
        text = text[:limit] + "...[truncated]"
    return html.escape(text, quote=False)


def _is_valid_payload(payload: Any) -> bool:
    return (
        isinstance(payload, dict)
        and bool(payload)
        and isinstance(payload.get("msg_type"), str)
        and ("content" in payload or "card" in payload)
    )


def _is_interactive_payload(payload: Any) -> bool:
    return (
        _is_valid_payload(payload)
        and payload.get("msg_type") == "interactive"
        and isinstance(payload.get("card"), dict)
        and bool(payload.get("card"))
    )


def _current_timestamp() -> int:
    return int(time.time())


def _build_feishu_sign(timestamp: str, secret: str) -> str:
    string_to_sign = f"{timestamp}\n{secret}"
    digest = hmac.new(
        string_to_sign.encode("utf-8"),
        b"",
        digestmod=hashlib.sha256,
    ).digest()
    return base64.b64encode(digest).decode("utf-8")


def _parse_response_body(body: str, redaction_values: tuple[str, ...]) -> Any:
    sanitized_body = _redact_text(body, redaction_values)
    if not sanitized_body:
        return ""
    try:
        parsed = json.loads(sanitized_body)
    except json.JSONDecodeError:
        return _truncate_text(sanitized_body)
    return _sanitize_response_value(parsed, redaction_values)


def _extract_business_code(response_body: Any) -> int | None:
    if not isinstance(response_body, dict):
        return None
    for key in ("code", "StatusCode", "status_code"):
        if key not in response_body:
            continue
        value = response_body[key]
        if type(value) is int:
            return value
        if isinstance(value, str) and value.strip().lstrip("-").isdigit():
            return int(value)
    return None


def _sanitize_response_value(value: Any, redaction_values: tuple[str, ...]) -> Any:
    if isinstance(value, dict):
        return {
            str(key): _sanitize_response_value(item, redaction_values)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_sanitize_response_value(item, redaction_values) for item in value]
    if isinstance(value, str):
        return _truncate_text(_redact_text(value, redaction_values))
    return value


def _redact_text(text: str, redaction_values: tuple[str, ...]) -> str:
    redacted = text
    for value in redaction_values:
        if value:
            redacted = redacted.replace(value, "[redacted]")
    return redacted


def _truncate_text(text: str, limit: int = 1000) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + "...[truncated]"
