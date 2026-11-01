from __future__ import annotations

import os
import re
from dataclasses import asdict, dataclass
from typing import Any, Literal


ParseStatus = Literal["parsed", "ignored", "error"]


@dataclass(frozen=True)
class ParsedAlert:
    source_bot: str
    status: Literal["fault"]
    monitor_name: str
    reason: str
    alert_time: str
    raw_text: str


@dataclass(frozen=True)
class EventParseResult:
    status: ParseStatus
    reason: str | None = None
    alert: ParsedAlert | None = None

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"status": self.status}
        if self.reason:
            payload["reason"] = self.reason
        if self.alert:
            payload["alert"] = asdict(self.alert)
        return payload


TITLE_PATTERN = re.compile(
    r"^\s*监控告警:\s*\[(?P<state>[^\]]+)\]\s*(?P<monitor_name>.+?)\s*$",
    re.MULTILINE,
)
FAULT_REASON_PATTERN = re.compile(r"^\s*\[发生故障\]\s*(?P<reason>.*?)\s*$", re.MULTILINE)
ALERT_TIME_PATTERN = re.compile(
    r"^\s*告警时间:\s*(?P<alert_time>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s*$",
    re.MULTILINE,
)


def parse_feishu_event(event: dict[str, Any], feishu_config: dict[str, Any]) -> EventParseResult:
    sender_name = _string_field(event, "sender_name")
    sender_id = _string_field(event, "sender_id")
    raw_text = _string_field(event, "text")

    alert_bot_config = feishu_config.get("alert_bot", {})
    allowed_names = _string_set(alert_bot_config.get("allowed_names", []))
    self_names = _string_set(alert_bot_config.get("self_names", []))
    allowed_sender_id_env = _string_value(
        alert_bot_config.get("allowed_sender_id_env")
    )
    allowed_sender_id = (
        os.getenv(allowed_sender_id_env, "").strip()
        if allowed_sender_id_env
        else ""
    )

    if sender_name in self_names:
        return EventParseResult(status="ignored", reason="self_message")

    sender_name_matches = sender_name in allowed_names
    sender_id_matches = bool(allowed_sender_id and sender_id == allowed_sender_id)
    if not sender_name_matches and not sender_id_matches:
        return EventParseResult(status="ignored", reason="non_alert_bot")

    title_match = TITLE_PATTERN.search(raw_text)
    if not title_match:
        return EventParseResult(status="ignored", reason="non_alert_format")

    title_state = title_match.group("state").strip()
    monitor_name = title_match.group("monitor_name").strip()

    if _is_recovered_alert(title_state, raw_text):
        return EventParseResult(status="ignored", reason="recovered_alert")

    if not _is_fault_alert(title_state, raw_text):
        return EventParseResult(status="ignored", reason="non_fault_alert")

    alert_time_match = ALERT_TIME_PATTERN.search(raw_text)
    reason_match = FAULT_REASON_PATTERN.search(raw_text)
    reason = reason_match.group("reason").strip() if reason_match else ""

    alert = ParsedAlert(
        source_bot=sender_name,
        status="fault",
        monitor_name=monitor_name,
        reason=reason,
        alert_time=alert_time_match.group("alert_time") if alert_time_match else "",
        raw_text=raw_text,
    )
    return EventParseResult(status="parsed", alert=alert)


def _string_field(mapping: dict[str, Any], key: str) -> str:
    value = mapping.get(key, "")
    return value if isinstance(value, str) else ""


def _string_value(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _string_set(values: Any) -> set[str]:
    if not isinstance(values, list):
        return set()
    return {value for value in values if isinstance(value, str)}


def _is_recovered_alert(title_state: str, raw_text: str) -> bool:
    return "正常" in title_state or "[恢复正常]" in raw_text


def _is_fault_alert(title_state: str, raw_text: str) -> bool:
    return "故障" in title_state or "[发生故障]" in raw_text
