from __future__ import annotations

import base64
import copy
import hashlib
import hmac
import json
import os
import socket
import subprocess
import sys
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

from scripts.alert_router import ResolvedRoute, RouteResolutionResult
from scripts.diagnosis_engine import DiagnosisResult, ProbeOutcome
from scripts.feishu_event_parser import ParsedAlert
from scripts.feishu_notify import (
    FeishuHttpResponse,
    build_feishu_diagnostic_message,
    build_feishu_route_error_message,
    build_feishu_runtime_error_message,
    send_app_diagnostic_message,
    send_app_notification_fanout,
    send_diagnostic_message,
)


OWNER = {"name": "运维人员A", "feishu_user_id": "ou_owner_a"}
FALLBACK_OWNER = {"name": "值班运维", "feishu_user_id": "ou_fallback"}


def card_text(payload: dict[str, object]) -> str:
    return json.dumps(payload.get("card", {}), ensure_ascii=False)


def parsed_alert(
    *,
    monitor_name: str = "示例数据服务｜端口8002",
    reason: str = "Request timeout",
) -> ParsedAlert:
    return ParsedAlert(
        source_bot="拨测通知机器人",
        status="fault",
        monitor_name=monitor_name,
        reason=reason,
        alert_time="2026-07-07 23:35:20",
        raw_text="raw alert text",
    )


def route(*, owners: list[dict[str, str]] | None = None) -> ResolvedRoute:
    return ResolvedRoute(
        id="data-release-prod-8002",
        match_type="exact",
        service_name="示例数据服务",
        diagnosis={
            "type": "tcp",
            "host": "data-release.internal.example",
            "port": 8002,
        },
        owners=owners if owners is not None else [OWNER],
    )


def abnormal_result(*, owners: list[dict[str, str]] | None = None) -> DiagnosisResult:
    return DiagnosisResult(
        status="abnormal",
        should_notify=True,
        classification="external_path_issue_likely",
        finding="外网视角失败，更可能是外部访问路径问题。",
        suggested_checks=(
            "建议优先检查公网入口、防火墙、安全组和公网 DNS。",
        ),
        alert=parsed_alert(),
        route=route(owners=owners),
        probes=(
            ProbeOutcome(
                perspective="internal",
                success=True,
                attempts=1,
                evidence="tcping succeeded",
            ),
            ProbeOutcome(
                perspective="external",
                success=False,
                attempts=3,
                final_error="connection timed out",
                evidence="tcping timed out after 3 attempts",
            ),
        ),
    )


class FeishuDiagnosticMessageTests(unittest.TestCase):
    def test_abnormal_diagnosis_builds_structured_red_card(self) -> None:
        result = build_feishu_diagnostic_message(abnormal_result())

        self.assertTrue(result.should_send)
        self.assertEqual(result.reason, "abnormal_diagnosis")
        self.assertIsNotNone(result.payload)
        payload = result.payload or {}
        text = card_text(payload)

        self.assertEqual(payload["msg_type"], "interactive")
        self.assertEqual(payload["card"]["header"]["template"], "red")
        self.assertIn("🚨 服务可达性异常", text)
        self.assertIn("示例数据服务｜端口8002", text)
        self.assertIn("Request timeout", text)
        self.assertIn("2026-07-07 23:35:20", text)
        self.assertIn("示例数据服务", text)
        self.assertIn("TCP data-release.internal.example:8002", text)
        self.assertIn("内网视角", text)
        self.assertIn("外网视角", text)
        self.assertIn("✅ 成功", text)
        self.assertIn("❌ 失败", text)
        self.assertIn("**尝试**：3 次", text)
        self.assertIn("connection timed out", text)
        self.assertIn("更可能", text)
        self.assertIn("建议优先检查", text)
        self.assertNotIn("|---", text)
        self.assertNotIn("```", text)
        self.assertNotIn("测试总结", text)

    def test_group_uses_real_at_and_private_card_uses_plain_name(self) -> None:
        result = build_feishu_diagnostic_message(abnormal_result())
        group_text = card_text(result.payload or {})
        private_text = card_text(result.private_payload or {})

        self.assertIn("<at id=ou_owner_a></at>", group_text)
        self.assertIn("运维人员A", private_text)
        self.assertNotIn("ou_owner_a", private_text)
        self.assertNotIn("<at", private_text)

    def test_normal_result_does_not_build_payload(self) -> None:
        result = build_feishu_diagnostic_message(
            DiagnosisResult(
                status="normal",
                should_notify=False,
                classification="recovered_or_transient",
                alert=parsed_alert(),
                route=route(),
            )
        )

        self.assertFalse(result.should_send)
        self.assertEqual(result.reason, "normal_result")
        self.assertIsNone(result.payload)
        self.assertIsNone(result.private_payload)

    def test_should_notify_false_does_not_build_payload(self) -> None:
        result = build_feishu_diagnostic_message(
            DiagnosisResult(
                status="abnormal",
                should_notify=False,
                alert=parsed_alert(),
                route=route(),
            )
        )

        self.assertFalse(result.should_send)
        self.assertEqual(result.reason, "normal_result")
        self.assertIsNone(result.payload)

    def test_empty_owner_list_still_builds_without_at_tag(self) -> None:
        result = build_feishu_diagnostic_message(abnormal_result(owners=[]))
        text = card_text(result.payload or {})

        self.assertTrue(result.should_send)
        self.assertIn("临时负责人", text)
        self.assertNotIn("<at", text)

    def test_special_characters_are_escaped_without_breaking_at_tag(self) -> None:
        result = build_feishu_diagnostic_message(
            DiagnosisResult(
                status="abnormal",
                should_notify=True,
                finding="更可能是外部路径问题 <check>",
                suggested_checks=("建议优先检查 A&B <route>",),
                alert=parsed_alert(
                    monitor_name="服务<alpha>&beta",
                    reason="Request <timeout> & failed",
                ),
                route=ResolvedRoute(
                    id="route-special",
                    match_type="exact",
                    service_name="核心<服务>&A",
                    diagnosis={
                        "type": "http",
                        "url": "https://example.com/a?x=1&y=<bad>",
                    },
                    owners=[
                        {
                            "name": "运维<A>&B",
                            "feishu_user_id": 'ou_"bad"&id',
                        }
                    ],
                ),
                probes=(
                    ProbeOutcome(
                        perspective="internal",
                        success=False,
                        attempts=1,
                        final_error="bad <err>&value",
                        evidence="curl <502>&failed",
                    ),
                    ProbeOutcome(
                        perspective="external",
                        success=True,
                        attempts=1,
                        evidence="curl 200",
                    ),
                ),
            )
        )
        group_text = card_text(result.payload or {})
        private_text = card_text(result.private_payload or {})

        self.assertIn("服务&lt;alpha&gt;&amp;beta", group_text)
        self.assertIn("Request &lt;timeout&gt; &amp; failed", group_text)
        self.assertIn("核心&lt;服务&gt;&amp;A", group_text)
        self.assertIn("https://example.com/a?x=1&amp;y=&lt;bad&gt;", group_text)
        self.assertIn("&amp;id></at>", group_text)
        self.assertIn("运维&lt;A&gt;&amp;B", private_text)
        self.assertNotIn("<at", private_text)

    def test_missing_upstream_fields_are_explicit(self) -> None:
        diagnosis = abnormal_result()
        alert = parsed_alert(reason="")
        alert = ParsedAlert(
            source_bot=alert.source_bot,
            status="fault",
            monitor_name=alert.monitor_name,
            reason="",
            alert_time="",
            raw_text=alert.raw_text,
        )
        result = build_feishu_diagnostic_message(
            DiagnosisResult(
                status=diagnosis.status,
                should_notify=diagnosis.should_notify,
                classification=diagnosis.classification,
                finding=diagnosis.finding,
                suggested_checks=diagnosis.suggested_checks,
                alert=alert,
                route=diagnosis.route,
                probes=diagnosis.probes,
            )
        )

        text = card_text(result.payload or {})
        self.assertGreaterEqual(text.count("上游未透传"), 2)

    def test_execution_error_builds_orange_card_without_exception_details(self) -> None:
        result = build_feishu_diagnostic_message(
            DiagnosisResult(
                status="error",
                should_notify=False,
                reason="probe_execution_error",
                alert=parsed_alert(),
                route=route(),
                error_details={"message": "C:/secret/private-key"},
            )
        )

        self.assertTrue(result.should_send)
        self.assertEqual(result.reason, "diagnosis_execution_error")
        payload = result.payload or {}
        self.assertEqual(payload["card"]["header"]["template"], "orange")
        self.assertNotIn("private-key", card_text(payload))

    def test_building_message_does_not_call_sender(self) -> None:
        with mock.patch(
            "scripts.feishu_notify.send_diagnostic_message",
            wraps=send_diagnostic_message,
        ) as sender:
            build_feishu_diagnostic_message(abnormal_result())

        sender.assert_not_called()


class FeishuRouteErrorMessageTests(unittest.TestCase):
    def test_route_not_found_uses_fallback_owners(self) -> None:
        result = build_feishu_route_error_message(
            RouteResolutionResult(
                status="error",
                reason="route_not_found",
                alert=parsed_alert(),
                fallback_owners=(FALLBACK_OWNER,),
            )
        )

        self.assertTrue(result.should_send)
        self.assertEqual(result.reason, "route_not_found")
        self.assertIsNotNone(result.payload)
        payload = result.payload or {}
        text = card_text(payload)
        private_text = card_text(result.private_payload or {})

        self.assertEqual(payload["msg_type"], "interactive")
        self.assertEqual(payload["card"]["header"]["template"], "orange")
        self.assertIn("诊断配置异常", text)
        self.assertIn("映射缺失", text)
        self.assertIn("未执行探测", text)
        self.assertIn("<at id=ou_fallback></at>", text)
        self.assertIn("值班运维", private_text)
        self.assertNotIn("<at", private_text)

    def test_route_conflict_includes_conflicting_route_ids(self) -> None:
        result = build_feishu_route_error_message(
            RouteResolutionResult(
                status="error",
                reason="route_conflict",
                alert=parsed_alert(),
                matched_route_ids=("route-a", "route-b"),
                fallback_owners=(FALLBACK_OWNER,),
            )
        )
        text = card_text(result.payload or {})

        self.assertTrue(result.should_send)
        self.assertIn("映射冲突", text)
        self.assertIn("route-a, route-b", text)
        self.assertIn("未执行探测", text)

    def test_non_route_error_does_not_build_payload(self) -> None:
        result = build_feishu_route_error_message(
            RouteResolutionResult(
                status="matched",
                alert=parsed_alert(),
                route=route(),
            )
        )

        self.assertFalse(result.should_send)
        self.assertEqual(result.reason, "not_route_error")
        self.assertIsNone(result.payload)

    def test_runtime_error_card_is_concise_and_orange(self) -> None:
        result = build_feishu_runtime_error_message(
            "示例网关",
            owners=[FALLBACK_OWNER],
        )

        self.assertTrue(result.should_send)
        payload = result.payload or {}
        self.assertEqual(payload["card"]["header"]["template"], "orange")
        text = card_text(payload)
        self.assertIn("示例网关", text)
        self.assertIn("不会转交大模型", text)
        self.assertIn("<at id=ou_fallback></at>", text)
        self.assertNotIn("<at", card_text(result.private_payload or {}))
        self.assertNotIn("Traceback", text)


class RecordingPost:
    def __init__(self, response: FeishuHttpResponse | None = None) -> None:
        self.response = response or FeishuHttpResponse(
            status_code=200,
            body='{"code": 0, "msg": "success"}',
        )
        self.calls: list[dict[str, object]] = []

    def __call__(
        self,
        webhook_url: str,
        request_body: bytes,
        timeout_seconds: int,
    ) -> FeishuHttpResponse:
        self.calls.append(
            {
                "webhook_url": webhook_url,
                "request_body": request_body,
                "payload": json.loads(request_body.decode("utf-8")),
                "timeout_seconds": timeout_seconds,
            }
        )
        return self.response


class RecordingAppPost:
    def __init__(self, responses: list[FeishuHttpResponse]) -> None:
        self.responses = list(responses)
        self.calls: list[dict[str, object]] = []

    def __call__(
        self,
        url: str,
        headers: dict[str, str],
        request_body: bytes,
        timeout_seconds: int,
    ) -> FeishuHttpResponse:
        self.calls.append(
            {
                "url": url,
                "headers": dict(headers),
                "payload": json.loads(request_body.decode("utf-8")),
                "timeout_seconds": timeout_seconds,
            }
        )
        return self.responses.pop(0)


class FeishuAppSenderTests(unittest.TestCase):
    def setUp(self) -> None:
        message = build_feishu_diagnostic_message(abnormal_result())
        self.payload = message.payload or {}
        self.private_payload = message.private_payload or {}
        self.config = {
            "enabled": True,
            "app_id_env": "FEISHU_APP_ID",
            "app_secret_env": "FEISHU_APP_SECRET",
            "domain_env": "FEISHU_DOMAIN",
        }
        self.env = {
            "FEISHU_APP_ID": "cli_test_app_id",
            "FEISHU_APP_SECRET": "cli_test_app_secret",
            "FEISHU_DOMAIN": "feishu",
        }

    def test_reply_sends_interactive_card_as_app_bot(self) -> None:
        post = RecordingAppPost(
            [
                FeishuHttpResponse(
                    200,
                    '{"code":0,"tenant_access_token":"tenant-token"}',
                ),
                FeishuHttpResponse(200, '{"code":0,"data":{"message_id":"om_reply"}}'),
            ]
        )

        with mock.patch.dict(os.environ, self.env, clear=True):
            result = send_app_diagnostic_message(
                self.payload,
                self.config,
                chat_id="oc_alert_group",
                reply_to_message_id="om_alert",
                post_fn=post,
            )

        self.assertTrue(result.success)
        self.assertEqual(result.reason, "sent")
        self.assertEqual(len(post.calls), 2)
        self.assertTrue(str(post.calls[1]["url"]).endswith("/om_alert/reply"))
        sent = post.calls[1]["payload"]
        self.assertEqual(sent["msg_type"], "interactive")
        card = json.loads(sent["content"])
        self.assertEqual(card["header"]["template"], "red")
        serialized_result = json.dumps(result.to_dict(), ensure_ascii=False)
        self.assertNotIn("tenant-token", serialized_result)
        self.assertNotIn("cli_test_app_secret", serialized_result)

    def test_explicit_reply_failure_falls_back_to_group(self) -> None:
        post = RecordingAppPost(
            [
                FeishuHttpResponse(
                    200,
                    '{"code":0,"tenant_access_token":"tenant-token"}',
                ),
                FeishuHttpResponse(400, '{"code":230001,"msg":"message missing"}'),
                FeishuHttpResponse(200, '{"code":0,"data":{"message_id":"om_top"}}'),
            ]
        )

        with mock.patch.dict(os.environ, self.env, clear=True):
            result = send_app_diagnostic_message(
                self.payload,
                self.config,
                chat_id="oc_alert_group",
                reply_to_message_id="om_missing",
                post_fn=post,
            )

        self.assertTrue(result.success)
        self.assertEqual(result.reason, "sent_after_reply_failure")
        self.assertEqual(len(post.calls), 3)
        self.assertIn("receive_id_type=chat_id", str(post.calls[2]["url"]))
        self.assertEqual(post.calls[2]["payload"]["receive_id"], "oc_alert_group")

    def test_ambiguous_reply_timeout_does_not_duplicate_top_level_card(self) -> None:
        calls = 0

        def timeout_on_reply(
            _url: str,
            _headers: dict[str, str],
            _body: bytes,
            _timeout: int,
        ) -> FeishuHttpResponse:
            nonlocal calls
            calls += 1
            if calls == 1:
                return FeishuHttpResponse(
                    200,
                    '{"code":0,"tenant_access_token":"tenant-token"}',
                )
            raise socket.timeout("request may have completed")

        with mock.patch.dict(os.environ, self.env, clear=True):
            result = send_app_diagnostic_message(
                self.payload,
                self.config,
                chat_id="oc_alert_group",
                reply_to_message_id="om_alert",
                post_fn=timeout_on_reply,
            )

        self.assertFalse(result.success)
        self.assertEqual(result.reason, "reply_request_timeout")
        self.assertEqual(calls, 2)

    def test_missing_credentials_and_non_card_payload_fail_before_send(self) -> None:
        post = mock.Mock()
        with mock.patch.dict(os.environ, {}, clear=True):
            missing = send_app_diagnostic_message(
                self.payload,
                self.config,
                chat_id="oc_alert_group",
                post_fn=post,
            )
        invalid = send_app_diagnostic_message(
            {"msg_type": "text", "content": {"text": "bad"}},
            self.config,
            chat_id="oc_alert_group",
            post_fn=post,
        )

        self.assertEqual(missing.reason, "missing_app_credentials")
        self.assertEqual(invalid.reason, "invalid_payload")
        post.assert_not_called()

    def test_fanout_reuses_token_and_deduplicates_private_recipients(self) -> None:
        post = RecordingAppPost(
            [
                FeishuHttpResponse(
                    200,
                    '{"code":0,"tenant_access_token":"tenant-token"}',
                ),
                FeishuHttpResponse(200, '{"code":0,"data":{"message_id":"om_reply"}}'),
                FeishuHttpResponse(
                    200,
                    '{"code":0,"data":{"message_id":"om_dm","receive_id":"ou_owner_a"}}',
                ),
            ]
        )

        with mock.patch.dict(os.environ, self.env, clear=True):
            result = send_app_notification_fanout(
                self.payload,
                self.private_payload,
                self.config,
                chat_id="oc_alert_group",
                owner_open_ids=("ou_owner_a", "ou_owner_a"),
                reply_to_message_id="om_alert",
                post_fn=post,
            )

        self.assertTrue(result.success)
        self.assertEqual(result.reason, "sent")
        self.assertEqual(result.private_requested, 1)
        self.assertEqual(len(post.calls), 3)
        self.assertIn("receive_id_type=open_id", str(post.calls[2]["url"]))
        self.assertEqual(post.calls[2]["payload"]["receive_id"], "ou_owner_a")
        private_card = json.loads(post.calls[2]["payload"]["content"])
        self.assertNotIn("<at", json.dumps(private_card, ensure_ascii=False))
        serialized = json.dumps(result.to_dict(), ensure_ascii=False)
        self.assertNotIn("ou_owner_a", serialized)
        self.assertNotIn("tenant-token", serialized)

    def test_fanout_continues_private_send_after_group_timeout(self) -> None:
        calls = 0

        def timeout_group_only(
            _url: str,
            _headers: dict[str, str],
            _body: bytes,
            _timeout: int,
        ) -> FeishuHttpResponse:
            nonlocal calls
            calls += 1
            if calls == 1:
                return FeishuHttpResponse(
                    200,
                    '{"code":0,"tenant_access_token":"tenant-token"}',
                )
            if calls == 2:
                raise socket.timeout("reply outcome unknown")
            return FeishuHttpResponse(200, '{"code":0,"data":{"message_id":"om_dm"}}')

        with mock.patch.dict(os.environ, self.env, clear=True):
            result = send_app_notification_fanout(
                self.payload,
                self.private_payload,
                self.config,
                chat_id="oc_alert_group",
                owner_open_ids=("ou_owner_a",),
                reply_to_message_id="om_alert",
                post_fn=timeout_group_only,
            )

        self.assertFalse(result.success)
        self.assertEqual(result.reason, "partial_failure")
        self.assertEqual(result.group_result.reason, "reply_request_timeout")
        self.assertTrue(result.private_results[0].success)
        self.assertEqual(calls, 3)

    def test_fanout_reports_partial_private_failure_and_token_failure(self) -> None:
        partial_post = RecordingAppPost(
            [
                FeishuHttpResponse(
                    200,
                    '{"code":0,"tenant_access_token":"tenant-token"}',
                ),
                FeishuHttpResponse(200, '{"code":0,"data":{"message_id":"om_group"}}'),
                FeishuHttpResponse(200, '{"code":0,"data":{"message_id":"om_dm_a"}}'),
                FeishuHttpResponse(400, '{"code":230001,"msg":"not available"}'),
            ]
        )
        with mock.patch.dict(os.environ, self.env, clear=True):
            partial = send_app_notification_fanout(
                self.payload,
                self.private_payload,
                self.config,
                chat_id="oc_alert_group",
                owner_open_ids=("ou_owner_a", "ou_owner_b"),
                post_fn=partial_post,
            )

        self.assertEqual(partial.reason, "partial_failure")
        self.assertEqual(sum(item.success for item in partial.private_results), 1)

        token_post = RecordingAppPost(
            [FeishuHttpResponse(400, '{"code":10003,"msg":"bad app"}')]
        )
        with mock.patch.dict(os.environ, self.env, clear=True):
            token_failure = send_app_notification_fanout(
                self.payload,
                self.private_payload,
                self.config,
                chat_id="oc_alert_group",
                owner_open_ids=("ou_owner_a",),
                post_fn=token_post,
            )

        self.assertFalse(token_failure.success)
        self.assertEqual(token_failure.reason, "failed")
        self.assertEqual(token_failure.group_result.reason, "token_error")
        self.assertEqual(token_failure.private_results, ())


class FeishuSenderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.payload = {
            "msg_type": "text",
            "content": {"text": "stage 8 acceptance message"},
        }
        self.config = {
            "enabled": True,
            "webhook_env": "FEISHU_WEBHOOK_URL",
            "secret_env": "FEISHU_SECRET",
        }

    def test_disabled_config_does_not_send(self) -> None:
        post = mock.Mock()
        result = send_diagnostic_message(
            self.payload,
            {**self.config, "enabled": False},
            post_fn=post,
        )

        self.assertFalse(result.success)
        self.assertEqual(result.reason, "feishu_disabled")
        post.assert_not_called()

    def test_missing_webhook_env_is_structured_error(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=True):
            result = send_diagnostic_message(
                self.payload,
                self.config,
                post_fn=RecordingPost(),
            )

        self.assertFalse(result.success)
        self.assertEqual(result.reason, "missing_webhook")

    def test_unsigned_send_posts_original_payload(self) -> None:
        post = RecordingPost()
        original = copy.deepcopy(self.payload)

        with mock.patch.dict(
            os.environ,
            {"FEISHU_WEBHOOK_URL": "https://example.invalid/webhook-secret"},
            clear=True,
        ):
            result = send_diagnostic_message(
                self.payload,
                self.config,
                timeout_seconds=7,
                post_fn=post,
            )

        self.assertTrue(result.success)
        self.assertEqual(result.reason, "sent")
        self.assertEqual(result.status_code, 200)
        self.assertEqual(len(post.calls), 1)
        self.assertEqual(post.calls[0]["payload"], original)
        self.assertEqual(post.calls[0]["timeout_seconds"], 7)
        self.assertEqual(self.payload, original)

    def test_signed_send_adds_timestamp_and_sign_without_mutating_payload(self) -> None:
        post = RecordingPost()
        original = copy.deepcopy(self.payload)
        timestamp = 1234567890
        secret = "super-secret-value"
        expected_sign = base64.b64encode(
            hmac.new(
                f"{timestamp}\n{secret}".encode("utf-8"),
                b"",
                digestmod=hashlib.sha256,
            ).digest()
        ).decode("utf-8")

        with mock.patch.dict(
            os.environ,
            {
                "FEISHU_WEBHOOK_URL": "https://example.invalid/webhook-secret",
                "FEISHU_SECRET": secret,
            },
            clear=True,
        ):
            result = send_diagnostic_message(
                self.payload,
                self.config,
                post_fn=post,
                timestamp_fn=lambda: timestamp,
            )

        sent_payload = post.calls[0]["payload"]
        self.assertTrue(result.success)
        self.assertEqual(sent_payload["timestamp"], str(timestamp))
        self.assertEqual(sent_payload["sign"], expected_sign)
        self.assertEqual(self.payload, original)
        result_json = json.dumps(result.to_dict(), ensure_ascii=False)
        self.assertNotIn("super-secret-value", result_json)
        self.assertNotIn("webhook-secret", result_json)

    def test_http_error_is_structured_failure(self) -> None:
        post = RecordingPost(
            FeishuHttpResponse(status_code=500, body='{"code": 999, "msg": "bad"}')
        )

        with mock.patch.dict(
            os.environ,
            {"FEISHU_WEBHOOK_URL": "https://example.invalid/webhook-secret"},
            clear=True,
        ):
            result = send_diagnostic_message(self.payload, self.config, post_fn=post)

        self.assertFalse(result.success)
        self.assertEqual(result.reason, "http_error")
        self.assertEqual(result.status_code, 500)

    def test_feishu_business_error_is_structured_failure(self) -> None:
        post = RecordingPost(
            FeishuHttpResponse(
                status_code=200,
                body='{"code": 19024, "msg": "signature check failed"}',
            )
        )

        with mock.patch.dict(
            os.environ,
            {"FEISHU_WEBHOOK_URL": "https://example.invalid/webhook-secret"},
            clear=True,
        ):
            result = send_diagnostic_message(self.payload, self.config, post_fn=post)

        self.assertFalse(result.success)
        self.assertEqual(result.reason, "feishu_error")
        self.assertEqual(result.status_code, 200)

    def test_timeout_and_url_errors_are_structured_without_secret_leakage(self) -> None:
        def timeout_post(*_args: object) -> FeishuHttpResponse:
            raise socket.timeout("timed out for https://example.invalid/webhook-secret")

        with mock.patch.dict(
            os.environ,
            {"FEISHU_WEBHOOK_URL": "https://example.invalid/webhook-secret"},
            clear=True,
        ):
            timeout_result = send_diagnostic_message(
                self.payload,
                self.config,
                post_fn=timeout_post,
            )

        self.assertFalse(timeout_result.success)
        self.assertEqual(timeout_result.reason, "request_timeout")
        self.assertNotIn(
            "webhook-secret",
            json.dumps(timeout_result.to_dict(), ensure_ascii=False),
        )

        def url_error_post(*_args: object) -> FeishuHttpResponse:
            raise urllib.error.URLError(
                "failed for https://example.invalid/webhook-secret"
            )

        with mock.patch.dict(
            os.environ,
            {"FEISHU_WEBHOOK_URL": "https://example.invalid/webhook-secret"},
            clear=True,
        ):
            url_error_result = send_diagnostic_message(
                self.payload,
                self.config,
                post_fn=url_error_post,
            )

        self.assertFalse(url_error_result.success)
        self.assertEqual(url_error_result.reason, "request_failed")
        self.assertNotIn(
            "webhook-secret",
            json.dumps(url_error_result.to_dict(), ensure_ascii=False),
        )

        def value_error_post(*_args: object) -> FeishuHttpResponse:
            raise ValueError("unknown url type: https://example.invalid/webhook-secret")

        with mock.patch.dict(
            os.environ,
            {"FEISHU_WEBHOOK_URL": "https://example.invalid/webhook-secret"},
            clear=True,
        ):
            value_error_result = send_diagnostic_message(
                self.payload,
                self.config,
                post_fn=value_error_post,
            )

        self.assertFalse(value_error_result.success)
        self.assertEqual(value_error_result.reason, "request_failed")
        self.assertNotIn(
            "webhook-secret",
            json.dumps(value_error_result.to_dict(), ensure_ascii=False),
        )

    def test_invalid_payload_is_rejected_before_post(self) -> None:
        post = mock.Mock()
        with mock.patch.dict(
            os.environ,
            {"FEISHU_WEBHOOK_URL": "https://example.invalid/webhook-secret"},
            clear=True,
        ):
            result = send_diagnostic_message({}, self.config, post_fn=post)

        self.assertFalse(result.success)
        self.assertEqual(result.reason, "invalid_payload")
        post.assert_not_called()


def cli_test_config(*, feishu_enabled: bool) -> dict:
    return {
        "runtime": {
            "dry_run": True,
            "alert_routes_path": "config/alert_routes.example.yaml",
        },
        "feishu": {
            "enabled": feishu_enabled,
            "webhook_env": "FEISHU_WEBHOOK_URL",
            "secret_env": "FEISHU_SECRET",
            "alert_bot": {"allowed_names": ["bot"], "self_names": ["Hermes"]},
        },
        "probes": {
            "retry_count": 3,
            "retry_interval_seconds": 2,
            "ssh_timeout_seconds": 10,
            "command_timeout_seconds": 10,
            "internal": {
                "name": "internal-probe",
                "host": "",
                "port": 22,
                "user": "",
                "key_path_env": "INTERNAL_PROBE_SSH_KEY_PATH",
            },
            "external": {
                "name": "external-probe",
                "host": "",
                "port": 22,
                "user": "",
                "key_path_env": "EXTERNAL_PROBE_SSH_KEY_PATH",
            },
        },
        "diagnosis": {
            "tcp_timeout_seconds": 5,
            "http_timeout_seconds": 10,
            "http_success_status": 200,
        },
    }


def cli_test_env() -> dict[str, str]:
    env = os.environ.copy()
    env.pop("FEISHU_WEBHOOK_URL", None)
    env.pop("FEISHU_SECRET", None)
    env["SERVICE_REACHABILITY_FEISHU_OWNER_OPEN_ID"] = "ou_test_owner"
    return env


class FeishuSendCliTests(unittest.TestCase):
    def test_send_payload_cli_disabled_config_outputs_structured_result(self) -> None:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            suffix=".yaml",
            delete=False,
        ) as config_file:
            json.dump(cli_test_config(feishu_enabled=False), config_file, ensure_ascii=False)
            config_path = Path(config_file.name)
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            suffix=".json",
            delete=False,
        ) as file:
            json.dump(
                {"msg_type": "text", "content": {"text": "disabled send test"}},
                file,
                ensure_ascii=False,
            )
            payload_path = Path(file.name)

        try:
            completed = subprocess.run(
                [
                    sys.executable,
                    "scripts/service_reachability_check.py",
                    "--config",
                    str(config_path),
                    "--send-feishu-payload-json",
                    str(payload_path),
                ],
                cwd=Path(__file__).resolve().parents[1],
                check=True,
                capture_output=True,
                encoding="utf-8",
                text=True,
                env=cli_test_env(),
            )
        finally:
            config_path.unlink(missing_ok=True)
            payload_path.unlink(missing_ok=True)

        result = json.loads(completed.stdout)
        self.assertEqual(result, {"success": False, "reason": "feishu_disabled"})

    def test_send_payload_cli_missing_webhook_outputs_structured_result(self) -> None:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            suffix=".yaml",
            delete=False,
        ) as config_file:
            json.dump(cli_test_config(feishu_enabled=True), config_file, ensure_ascii=False)
            config_path = Path(config_file.name)
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            suffix=".json",
            delete=False,
        ) as payload_file:
            json.dump(
                {"msg_type": "text", "content": {"text": "missing webhook test"}},
                payload_file,
                ensure_ascii=False,
            )
            payload_path = Path(payload_file.name)

        env = cli_test_env()
        try:
            completed = subprocess.run(
                [
                    sys.executable,
                    "scripts/service_reachability_check.py",
                    "--config",
                    str(config_path),
                    "--send-feishu-payload-json",
                    str(payload_path),
                ],
                cwd=Path(__file__).resolve().parents[1],
                check=True,
                capture_output=True,
                encoding="utf-8",
                text=True,
                env=env,
            )
        finally:
            config_path.unlink(missing_ok=True)
            payload_path.unlink(missing_ok=True)

        result = json.loads(completed.stdout)
        self.assertEqual(result, {"success": False, "reason": "missing_webhook"})


if __name__ == "__main__":
    unittest.main()
