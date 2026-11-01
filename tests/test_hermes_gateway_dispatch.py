from __future__ import annotations

import os
import unittest
from types import SimpleNamespace
from unittest import mock

from scripts.feishu_notify import FeishuFanoutResult, FeishuSendResult
from scripts import hermes_gateway_dispatch as dispatch


BOT_ID = "ou_alert_bot"
CHAT_ID = "oc_alert_group"
OWNER_ID = "ou_owner"


def successful_fanout() -> FeishuFanoutResult:
    return FeishuFanoutResult(
        success=True,
        reason="sent",
        group_result=FeishuSendResult(True, "sent", 200),
        private_requested=1,
        private_results=(FeishuSendResult(True, "sent", 200),),
    )


def event(
    text: str,
    *,
    message_id: str = "om_alert_1",
    bot_id: str = BOT_ID,
    chat_id: str = CHAT_ID,
    is_bot: bool = True,
) -> SimpleNamespace:
    return SimpleNamespace(
        text=text,
        message_id=message_id,
        timestamp="2026-07-22T15:00:00",
        source=SimpleNamespace(
            platform=SimpleNamespace(value="feishu"),
            chat_id=chat_id,
            user_id=bot_id,
            user_name="拨测通知机器人",
            is_bot=is_bot,
        ),
    )


class HermesGatewayDispatchTests(unittest.TestCase):
    def setUp(self) -> None:
        dispatch.reset_dispatch_state_for_tests()
        self.env = {
            dispatch.ALERT_BOT_ID_ENV: BOT_ID,
            dispatch.ALERT_CHAT_ID_ENV: CHAT_ID,
        }

    def test_register_wires_pre_dispatch_hook(self) -> None:
        ctx = mock.Mock()

        dispatch.register(ctx)

        ctx.register_hook.assert_called_once_with(
            "pre_gateway_dispatch",
            dispatch.pre_gateway_dispatch,
        )

    def test_recovered_alert_is_skipped_without_scheduling(self) -> None:
        with mock.patch.dict(os.environ, self.env, clear=False), mock.patch.object(
            dispatch, "_schedule_fault"
        ) as schedule:
            result = dispatch.pre_gateway_dispatch(
                event=event("监控告警: [✅ 正常] 示例HTTP服务")
            )

        self.assertEqual(result, {"action": "skip", "reason": "recovered_alert"})
        schedule.assert_not_called()

    def test_fault_is_scheduled_once_and_duplicate_is_suppressed(self) -> None:
        alert = event("监控告警: [🔴 故障] 示例HTTP服务")
        with mock.patch.dict(os.environ, self.env, clear=False), mock.patch.object(
            dispatch, "_schedule_fault"
        ) as schedule:
            first = dispatch.pre_gateway_dispatch(event=alert)
            duplicate = dispatch.pre_gateway_dispatch(event=alert)

        self.assertEqual(
            first,
            {"action": "skip", "reason": "fault_diagnosis_scheduled"},
        )
        self.assertEqual(
            duplicate,
            {"action": "skip", "reason": "duplicate_alert"},
        )
        schedule.assert_called_once()
        normalized = schedule.call_args.kwargs["event"]
        self.assertEqual(normalized["sender_id"], BOT_ID)
        self.assertEqual(normalized["text"], alert.text)

    def test_target_chat_human_other_bot_and_unrelated_message_are_silent(self) -> None:
        cases = [
            event("请帮忙看一下", is_bot=False),
            event("监控告警: [🔴 故障] 示例HTTP服务", bot_id="ou_other_bot"),
            event("机器人运行正常"),
        ]
        with mock.patch.dict(os.environ, self.env, clear=False), mock.patch.object(
            dispatch, "_schedule_fault"
        ) as schedule:
            results = [dispatch.pre_gateway_dispatch(event=item) for item in cases]

        self.assertEqual(
            results,
            [
                {"action": "skip", "reason": "alert_chat_non_target_message"},
                {"action": "skip", "reason": "alert_chat_non_target_message"},
                {"action": "skip", "reason": "alert_chat_non_target_message"},
            ],
        )
        schedule.assert_not_called()

    def test_other_chat_is_left_to_normal_hermes_routing(self) -> None:
        with mock.patch.dict(os.environ, self.env, clear=False):
            result = dispatch.pre_gateway_dispatch(
                event=event(
                    "监控告警: [🔴 故障] 示例HTTP服务",
                    chat_id="oc_other_group",
                )
            )

        self.assertIsNone(result)

    def test_missing_dispatch_config_fails_closed_for_bot_alert(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=True), mock.patch.object(
            dispatch, "_schedule_fault"
        ) as schedule:
            result = dispatch.pre_gateway_dispatch(
                event=event("监控告警: [🔴 故障] 示例HTTP服务")
            )

        self.assertEqual(
            result,
            {"action": "skip", "reason": "alert_dispatch_config_missing"},
        )
        schedule.assert_not_called()

    def test_normal_diagnosis_does_not_send_app_message(self) -> None:
        loaded = SimpleNamespace(
            config={"feishu": {"app_notify": {"enabled": True}}},
            routes={},
        )
        with mock.patch.object(dispatch, "load_config", return_value=loaded), mock.patch.object(
            dispatch,
            "run_manual_diagnosis",
            return_value={
                "status": "normal",
                "classification": "recovered_or_transient",
                "notification": {
                    "should_send": False,
                    "reason": "normal_result",
                },
            },
        ), mock.patch.object(dispatch, "send_app_notification_fanout") as sender:
            dispatch._run_fault_job_sync(
                event={},
                chat_id=CHAT_ID,
                message_id="om_alert",
                monitor_name="示例HTTP服务",
            )

        sender.assert_not_called()

    def test_abnormal_diagnosis_sends_exactly_one_card_reply(self) -> None:
        payload = {"msg_type": "interactive", "card": {"header": {}}}
        private_payload = {"msg_type": "interactive", "card": {"header": {}}}
        loaded = SimpleNamespace(
            config={"feishu": {"app_notify": {"enabled": True}}},
            routes={},
        )
        with mock.patch.object(dispatch, "load_config", return_value=loaded), mock.patch.object(
            dispatch,
            "run_manual_diagnosis",
            return_value={
                "status": "abnormal",
                "notification": {
                    "should_send": True,
                    "reason": "abnormal_diagnosis",
                    "payload": payload,
                    "private_payload": private_payload,
                },
                "route": {
                    "owners": [
                        {
                            "name": "告警值班负责人",
                            "feishu_user_id": OWNER_ID,
                        }
                    ]
                },
            },
        ), mock.patch.object(
            dispatch,
            "send_app_notification_fanout",
            return_value=successful_fanout(),
        ) as sender:
            dispatch._run_fault_job_sync(
                event={},
                chat_id=CHAT_ID,
                message_id="om_alert",
                monitor_name="示例HTTP服务",
            )

        sender.assert_called_once_with(
            payload,
            private_payload,
            {"enabled": True},
            chat_id=CHAT_ID,
            owner_open_ids=(OWNER_ID,),
            reply_to_message_id="om_alert",
        )

    def test_route_error_uses_fallback_owner_for_group_and_private(self) -> None:
        payload = {"msg_type": "interactive", "card": {"header": {}}}
        private_payload = {"msg_type": "interactive", "card": {"header": {}}}
        loaded = SimpleNamespace(
            config={"feishu": {"app_notify": {"enabled": True}}},
            routes={},
        )
        with mock.patch.object(dispatch, "load_config", return_value=loaded), mock.patch.object(
            dispatch,
            "run_manual_diagnosis",
            return_value={
                "status": "error",
                "reason": "route_not_found",
                "fallback_owners": [
                    {
                        "name": "告警值班负责人",
                        "feishu_user_id": OWNER_ID,
                    }
                ],
                "notification": {
                    "should_send": True,
                    "reason": "route_not_found",
                    "payload": payload,
                    "private_payload": private_payload,
                },
            },
        ), mock.patch.object(
            dispatch,
            "send_app_notification_fanout",
            return_value=successful_fanout(),
        ) as sender:
            dispatch._run_fault_job_sync(
                event={},
                chat_id=CHAT_ID,
                message_id="om_alert",
                monitor_name="未配置服务",
            )

        self.assertEqual(sender.call_args.kwargs["owner_open_ids"], (OWNER_ID,))

    def test_unexpected_failure_sends_concise_runtime_card_without_model_fallback(self) -> None:
        with mock.patch.object(
            dispatch,
            "load_config",
            side_effect=RuntimeError("secret exception detail"),
        ), mock.patch.object(
            dispatch,
            "send_app_notification_fanout",
            return_value=successful_fanout(),
        ) as sender, mock.patch.dict(
            os.environ,
            {dispatch.FALLBACK_OWNER_ID_ENV: OWNER_ID},
            clear=False,
        ):
            dispatch._run_fault_job_sync(
                event={},
                chat_id=CHAT_ID,
                message_id="om_alert",
                monitor_name="示例HTTP服务",
            )

        sender.assert_called_once()
        group_payload, private_payload = sender.call_args.args[:2]
        serialized = str(group_payload)
        self.assertIn("不会转交大模型", serialized)
        self.assertIn("<at id=ou_owner></at>", serialized)
        self.assertNotIn("<at", str(private_payload))
        self.assertNotIn("secret exception detail", serialized)
        self.assertEqual(sender.call_args.kwargs["owner_open_ids"], (OWNER_ID,))


if __name__ == "__main__":
    unittest.main()
