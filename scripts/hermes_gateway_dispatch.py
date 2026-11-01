from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import threading
import time
from collections import OrderedDict
from typing import Any

from scripts.config_loader import load_config
from scripts.feishu_event_parser import TITLE_PATTERN
from scripts.feishu_notify import (
    build_feishu_runtime_error_message,
    send_app_notification_fanout,
)
from scripts.manual_diagnosis_pipeline import run_manual_diagnosis
from scripts.probe_executor import ParamikoSSHCommandRunner


LOGGER = logging.getLogger("service_reachability_dispatch")
ALERT_BOT_ID_ENV = "SERVICE_REACHABILITY_ALERT_BOT_ID"
ALERT_CHAT_ID_ENV = "SERVICE_REACHABILITY_ALERT_CHAT_ID"
FALLBACK_OWNER_ID_ENV = "SERVICE_REACHABILITY_FEISHU_OWNER_OPEN_ID"
SEEN_MESSAGE_TTL_SECONDS = 24 * 60 * 60
SEEN_MESSAGE_LIMIT = 1024

_seen_message_ids: OrderedDict[str, float] = OrderedDict()
_seen_lock = threading.Lock()
_diagnosis_lock = threading.Lock()
_background_tasks: set[asyncio.Task[None]] = set()


def register(ctx: Any) -> None:
    ctx.register_hook("pre_gateway_dispatch", pre_gateway_dispatch)


def pre_gateway_dispatch(
    *,
    event: Any,
    gateway: Any = None,
    session_store: Any = None,
    **_kwargs: Any,
) -> dict[str, str] | None:
    """Deterministically handle alert-group messages before agent dispatch."""

    del gateway, session_store
    source = getattr(event, "source", None)
    if source is None or _platform_name(getattr(source, "platform", None)) != "feishu":
        return None

    text = str(getattr(event, "text", "") or "")
    title = TITLE_PATTERN.search(text)
    configured_bot_id = os.getenv(ALERT_BOT_ID_ENV, "").strip()
    configured_chat_id = os.getenv(ALERT_CHAT_ID_ENV, "").strip()
    source_is_bot = bool(getattr(source, "is_bot", False))

    if not configured_bot_id or not configured_chat_id:
        if source_is_bot and title:
            LOGGER.error(
                "Alert message suppressed because deterministic dispatch configuration is incomplete"
            )
            return {"action": "skip", "reason": "alert_dispatch_config_missing"}
        return None

    if str(getattr(source, "chat_id", "") or "") != configured_chat_id:
        return None

    # The configured alert group is deliberately not a general chat surface.
    # Human messages, other bots, self-messages and unrelated content stay silent.
    if (
        not source_is_bot
        or str(getattr(source, "user_id", "") or "") != configured_bot_id
        or title is None
    ):
        return {"action": "skip", "reason": "alert_chat_non_target_message"}

    state = title.group("state").strip()
    if "正常" in state or "[恢复正常]" in text:
        return {"action": "skip", "reason": "recovered_alert"}
    if "故障" not in state and "[发生故障]" not in text:
        return {"action": "skip", "reason": "non_fault_alert"}

    message_key = _message_key(event)
    if not _claim_message(message_key):
        return {"action": "skip", "reason": "duplicate_alert"}

    normalized_event = {
        "sender_name": str(getattr(source, "user_name", "") or ""),
        "sender_id": str(getattr(source, "user_id", "") or ""),
        "sender_type": "bot",
        "text": text,
    }
    monitor_name = title.group("monitor_name").strip()
    try:
        _schedule_fault(
            event=normalized_event,
            chat_id=configured_chat_id,
            message_id=str(getattr(event, "message_id", "") or ""),
            monitor_name=monitor_name,
        )
    except RuntimeError:
        LOGGER.error("Alert diagnosis could not be scheduled; message remains suppressed")
        return {"action": "skip", "reason": "alert_schedule_failed"}

    return {"action": "skip", "reason": "fault_diagnosis_scheduled"}


def _schedule_fault(
    *,
    event: dict[str, Any],
    chat_id: str,
    message_id: str,
    monitor_name: str,
) -> None:
    loop = asyncio.get_running_loop()
    task = loop.create_task(
        _run_fault_job(
            event=event,
            chat_id=chat_id,
            message_id=message_id,
            monitor_name=monitor_name,
        ),
        name="service-reachability-diagnosis",
    )
    _background_tasks.add(task)
    task.add_done_callback(_background_task_done)


async def _run_fault_job(
    *,
    event: dict[str, Any],
    chat_id: str,
    message_id: str,
    monitor_name: str,
) -> None:
    await asyncio.to_thread(
        _run_fault_job_sync,
        event=event,
        chat_id=chat_id,
        message_id=message_id,
        monitor_name=monitor_name,
    )


def _run_fault_job_sync(
    *,
    event: dict[str, Any],
    chat_id: str,
    message_id: str,
    monitor_name: str,
) -> None:
    with _diagnosis_lock:
        try:
            loaded = load_config()
            result = run_manual_diagnosis(
                event=event,
                config=loaded.config,
                routes_config=loaded.routes,
                runner=ParamikoSSHCommandRunner(),
                send_feishu=False,
            )
            notification = result.get("notification", {})
            payload = notification.get("payload") if isinstance(notification, dict) else None
            private_payload = (
                notification.get("private_payload")
                if isinstance(notification, dict)
                else None
            )
            if not isinstance(payload, dict) or not isinstance(private_payload, dict):
                LOGGER.info(
                    "Alert diagnosis completed without notification: status=%s classification=%s",
                    result.get("status", "unknown"),
                    result.get("classification", "none"),
                )
                return
            owner_open_ids = _owner_open_ids(_owners_from_result(result))
            send_result = send_app_notification_fanout(
                payload,
                private_payload,
                loaded.config.get("feishu", {}).get("app_notify", {}),
                chat_id=chat_id,
                owner_open_ids=owner_open_ids,
                reply_to_message_id=message_id,
            )
            LOGGER.info(
                "Alert diagnosis notification completed: status=%s success=%s reason=%s",
                result.get("status", "unknown"),
                send_result.success,
                send_result.reason,
            )
        except Exception as exc:  # Defensive boundary: never hand the event to the LLM.
            LOGGER.error(
                "Alert diagnosis failed safely: error_type=%s",
                type(exc).__name__,
            )
            fallback_owner = _runtime_fallback_owners()
            runtime_card = build_feishu_runtime_error_message(
                monitor_name,
                owners=fallback_owner,
            )
            if runtime_card.payload is None or runtime_card.private_payload is None:
                return
            send_result = send_app_notification_fanout(
                runtime_card.payload,
                runtime_card.private_payload,
                _fallback_app_config(),
                chat_id=chat_id,
                owner_open_ids=_owner_open_ids(fallback_owner),
                reply_to_message_id=message_id,
            )
            LOGGER.info(
                "Runtime-error notification completed: success=%s reason=%s",
                send_result.success,
                send_result.reason,
            )


def _background_task_done(task: asyncio.Task[None]) -> None:
    _background_tasks.discard(task)
    if task.cancelled():
        LOGGER.warning("Alert diagnosis task was cancelled")
        return
    exception = task.exception()
    if exception is not None:
        LOGGER.error(
            "Alert diagnosis background task failed: error_type=%s",
            type(exception).__name__,
        )


def _platform_name(platform: Any) -> str:
    value = getattr(platform, "value", platform)
    return str(value or "").strip().lower()


def _message_key(event: Any) -> str:
    message_id = str(getattr(event, "message_id", "") or "").strip()
    if message_id:
        return message_id
    source = getattr(event, "source", None)
    timestamp = str(getattr(event, "timestamp", "") or "")
    material = "|".join(
        (
            str(getattr(source, "chat_id", "") or ""),
            str(getattr(event, "text", "") or ""),
            timestamp,
        )
    )
    return "generated:" + hashlib.sha256(material.encode("utf-8")).hexdigest()


def _claim_message(message_key: str, now: float | None = None) -> bool:
    current = time.monotonic() if now is None else now
    with _seen_lock:
        expired = [
            key
            for key, seen_at in _seen_message_ids.items()
            if current - seen_at > SEEN_MESSAGE_TTL_SECONDS
        ]
        for key in expired:
            _seen_message_ids.pop(key, None)
        if message_key in _seen_message_ids:
            return False
        _seen_message_ids[message_key] = current
        while len(_seen_message_ids) > SEEN_MESSAGE_LIMIT:
            _seen_message_ids.popitem(last=False)
        return True


def _fallback_app_config() -> dict[str, Any]:
    return {
        "enabled": True,
        "app_id_env": "FEISHU_APP_ID",
        "app_secret_env": "FEISHU_APP_SECRET",
        "domain_env": "FEISHU_DOMAIN",
    }


def _owners_from_result(result: dict[str, Any]) -> list[dict[str, str]]:
    route = result.get("route")
    if isinstance(route, dict) and isinstance(route.get("owners"), list):
        return [
            owner
            for owner in route["owners"]
            if isinstance(owner, dict)
        ]
    fallback_owners = result.get("fallback_owners")
    if isinstance(fallback_owners, list):
        return [
            owner
            for owner in fallback_owners
            if isinstance(owner, dict)
        ]
    return []


def _owner_open_ids(owners: list[dict[str, str]]) -> tuple[str, ...]:
    return tuple(
        dict.fromkeys(
            owner_id
            for owner in owners
            if (owner_id := str(owner.get("feishu_user_id", "")).strip())
        )
    )


def _runtime_fallback_owners() -> list[dict[str, str]]:
    owner_open_id = os.getenv(FALLBACK_OWNER_ID_ENV, "").strip()
    if not owner_open_id:
        return []
    return [
        {
            "name": "告警值班负责人",
            "feishu_user_id": owner_open_id,
        }
    ]


def reset_dispatch_state_for_tests() -> None:
    with _seen_lock:
        _seen_message_ids.clear()
    _background_tasks.clear()
