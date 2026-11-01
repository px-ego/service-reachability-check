from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Iterable, Literal

from scripts.alert_router import ResolvedRoute, RouteResolutionResult
from scripts.feishu_event_parser import ParsedAlert


ProbePerspective = Literal["internal", "external"]
DiagnosisStatus = Literal["normal", "abnormal", "error"]


@dataclass(frozen=True)
class ProbeOutcome:
    perspective: ProbePerspective
    success: bool
    attempts: int
    final_error: str = ""
    evidence: str = ""
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "perspective": self.perspective,
            "success": self.success,
            "attempts": self.attempts,
            "final_error": self.final_error,
            "evidence": self.evidence,
            "details": dict(self.details),
        }


@dataclass(frozen=True)
class DiagnosisResult:
    status: DiagnosisStatus
    should_notify: bool
    reason: str | None = None
    classification: str | None = None
    finding: str | None = None
    suggested_checks: tuple[str, ...] = ()
    alert: ParsedAlert | None = None
    route: ResolvedRoute | None = None
    probes: tuple[ProbeOutcome, ...] = ()
    error_details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "status": self.status,
            "should_notify": self.should_notify,
        }
        if self.reason:
            payload["reason"] = self.reason
        if self.classification:
            payload["classification"] = self.classification
        if self.finding:
            payload["finding"] = self.finding
        if self.suggested_checks:
            payload["suggested_checks"] = list(self.suggested_checks)
        if self.alert:
            payload["alert"] = asdict(self.alert)
        if self.route:
            payload["route"] = asdict(self.route)
        if self.probes:
            payload["probes"] = {
                outcome.perspective: outcome.to_dict()
                for outcome in self.probes
            }
        if self.error_details:
            payload["error_details"] = dict(self.error_details)
        return payload


def diagnose_reachability(
    route_result: RouteResolutionResult,
    probe_outcomes: Iterable[ProbeOutcome],
) -> DiagnosisResult:
    if route_result.status != "matched" or route_result.route is None:
        return DiagnosisResult(
            status="error",
            should_notify=False,
            reason="route_not_matched",
            alert=route_result.alert,
            error_details={"route_status": route_result.status},
        )

    normalized = _normalize_probe_outcomes(probe_outcomes)
    if isinstance(normalized, DiagnosisResult):
        return DiagnosisResult(
            status=normalized.status,
            should_notify=normalized.should_notify,
            reason=normalized.reason,
            alert=route_result.alert,
            route=route_result.route,
            error_details=normalized.error_details,
        )

    internal = normalized["internal"]
    external = normalized["external"]
    classification, status, should_notify, finding, suggested_checks = (
        _classify_probe_pair(internal, external)
    )

    return DiagnosisResult(
        status=status,
        should_notify=should_notify,
        classification=classification,
        finding=finding,
        suggested_checks=suggested_checks,
        alert=route_result.alert,
        route=route_result.route,
        probes=(internal, external),
    )


def _normalize_probe_outcomes(
    probe_outcomes: Iterable[ProbeOutcome],
) -> dict[ProbePerspective, ProbeOutcome] | DiagnosisResult:
    outcomes: dict[ProbePerspective, ProbeOutcome] = {}

    for outcome in probe_outcomes:
        if outcome.perspective not in ("internal", "external"):
            return _input_error(
                "invalid_probe_perspective",
                {"perspective": outcome.perspective},
            )
        if outcome.perspective in outcomes:
            return _input_error(
                "duplicate_probe_perspective",
                {"perspective": outcome.perspective},
            )
        if type(outcome.attempts) is not int or outcome.attempts <= 0:
            return _input_error(
                "invalid_probe_attempts",
                {
                    "perspective": outcome.perspective,
                    "attempts": outcome.attempts,
                },
            )
        outcomes[outcome.perspective] = outcome

    missing = [
        perspective
        for perspective in ("internal", "external")
        if perspective not in outcomes
    ]
    if missing:
        return _input_error(
            "missing_probe_result",
            {"missing_perspectives": missing},
        )

    return outcomes


def _classify_probe_pair(
    internal: ProbeOutcome,
    external: ProbeOutcome,
) -> tuple[str, DiagnosisStatus, bool, str, tuple[str, ...]]:
    if internal.success and external.success:
        return (
            "recovered_or_transient",
            "normal",
            False,
            "内外两个视角当前探测均成功，更可能是告警已恢复或瞬时抖动。",
            (),
        )

    if internal.success and not external.success:
        return (
            "external_path_issue_likely",
            "abnormal",
            True,
            "内网视角成功、外网视角失败，更可能是外部访问路径问题。",
            (
                "建议优先检查公网入口、外网防火墙、安全组、公网 DNS 和外部访问链路。",
            ),
        )

    if not internal.success and external.success:
        return (
            "internal_path_issue_likely",
            "abnormal",
            True,
            "内网视角失败、外网视角成功，更可能是内部访问路径问题。",
            (
                "建议优先检查内网 DNS、内网 ACL、路由和内部访问链路。",
            ),
        )

    return (
        "service_or_common_dependency_issue_likely",
        "abnormal",
        True,
        "内外两个视角均失败，更可能是服务本身、目标侧或共同依赖问题。",
        (
            "建议优先检查服务进程、目标主机、端口监听、目标侧防火墙和共同依赖。",
        ),
    )


def _input_error(reason: str, details: dict[str, Any]) -> DiagnosisResult:
    return DiagnosisResult(
        status="error",
        should_notify=False,
        reason=reason,
        error_details=details,
    )
