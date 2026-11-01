from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from typing import Any, Literal

from scripts.feishu_event_parser import ParsedAlert


MatchType = Literal["exact", "regex"]
ResolutionStatus = Literal["matched", "error"]


@dataclass(frozen=True)
class ResolvedRoute:
    id: str
    match_type: MatchType
    service_name: str
    diagnosis: dict[str, Any]
    owners: list[dict[str, str]]


@dataclass(frozen=True)
class RouteResolutionResult:
    status: ResolutionStatus
    alert: ParsedAlert
    reason: str | None = None
    route: ResolvedRoute | None = None
    matched_route_ids: tuple[str, ...] = ()
    fallback_owners: tuple[dict[str, str], ...] = ()

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "status": self.status,
        }
        if self.reason:
            payload["reason"] = self.reason
        payload["alert"] = asdict(self.alert)
        if self.route:
            payload["route"] = asdict(self.route)
        if self.matched_route_ids:
            payload["matched_route_ids"] = list(self.matched_route_ids)
        if self.status == "error":
            payload["fallback_owners"] = [
                dict(owner) for owner in self.fallback_owners
            ]
        return payload


def resolve_alert_route(
    alert: ParsedAlert,
    routes_config: dict[str, Any],
) -> RouteResolutionResult:
    route_items = routes_config.get("routes", [])
    fallback_owners = tuple(
        dict(owner)
        for owner in routes_config.get("fallback", {}).get("owners", [])
    )

    exact_matches = [
        route
        for route in route_items
        if route["match"].get("monitor_name") == alert.monitor_name
    ]
    if exact_matches:
        return _result_for_matches(
            alert,
            exact_matches,
            "exact",
            fallback_owners,
        )

    regex_matches = [
        route
        for route in route_items
        if (
            "monitor_name_regex" in route["match"]
            and re.fullmatch(
                route["match"]["monitor_name_regex"],
                alert.monitor_name,
            )
        )
    ]
    if regex_matches:
        return _result_for_matches(
            alert,
            regex_matches,
            "regex",
            fallback_owners,
        )

    return RouteResolutionResult(
        status="error",
        reason="route_not_found",
        alert=alert,
        fallback_owners=fallback_owners,
    )


def _result_for_matches(
    alert: ParsedAlert,
    matches: list[dict[str, Any]],
    match_type: MatchType,
    fallback_owners: tuple[dict[str, str], ...],
) -> RouteResolutionResult:
    if len(matches) > 1:
        return RouteResolutionResult(
            status="error",
            reason="route_conflict",
            alert=alert,
            matched_route_ids=tuple(route["id"] for route in matches),
            fallback_owners=fallback_owners,
        )

    route = matches[0]
    resolved = ResolvedRoute(
        id=route["id"],
        match_type=match_type,
        service_name=route["service_name"],
        diagnosis=dict(route["diagnosis"]),
        owners=[dict(owner) for owner in route["owners"]],
    )
    return RouteResolutionResult(
        status="matched",
        alert=alert,
        route=resolved,
    )
