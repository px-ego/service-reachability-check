from __future__ import annotations

import unittest

from scripts.alert_router import RouteResolutionResult, resolve_alert_route
from scripts.diagnosis_engine import ProbeOutcome, diagnose_reachability
from scripts.feishu_event_parser import ParsedAlert


OWNER = {"name": "owner-a", "feishu_user_id": "ou_owner_a"}


def parsed_alert() -> ParsedAlert:
    return ParsedAlert(
        source_bot="alert-bot",
        status="fault",
        monitor_name="service-a-port-8002",
        reason="Request timeout",
        alert_time="2026-07-07 23:35:20",
        raw_text="raw alert text",
    )


def route_config() -> dict:
    return {
        "routes": [
            {
                "id": "service-a",
                "match": {"monitor_name": "service-a-port-8002"},
                "service_name": "Service A",
                "diagnosis": {
                    "type": "tcp",
                    "host": "service-a.internal.example",
                    "port": 8002,
                },
                "owners": [OWNER],
            }
        ],
        "fallback": {"owners": []},
    }


def matched_route() -> RouteResolutionResult:
    return resolve_alert_route(parsed_alert(), route_config())


def missing_route() -> RouteResolutionResult:
    return resolve_alert_route(
        parsed_alert(),
        {"routes": [], "fallback": {"owners": []}},
    )


def outcome(
    perspective: str,
    *,
    success: bool,
    attempts: int = 3,
    final_error: str = "",
    evidence: str | None = None,
) -> ProbeOutcome:
    return ProbeOutcome(
        perspective=perspective,  # type: ignore[arg-type]
        success=success,
        attempts=attempts,
        final_error=final_error,
        evidence=(
            evidence
            if evidence is not None
            else f"{perspective} probe success={success}"
        ),
        details={"exit_code": 0 if success else 1},
    )


class DiagnosisEngineTests(unittest.TestCase):
    def test_four_probe_combinations_have_expected_classification(self) -> None:
        cases = [
            (
                True,
                True,
                "normal",
                False,
                "recovered_or_transient",
            ),
            (
                True,
                False,
                "abnormal",
                True,
                "external_path_issue_likely",
            ),
            (
                False,
                True,
                "abnormal",
                True,
                "internal_path_issue_likely",
            ),
            (
                False,
                False,
                "abnormal",
                True,
                "service_or_common_dependency_issue_likely",
            ),
        ]

        for internal_success, external_success, status, notify, classification in cases:
            with self.subTest(classification=classification):
                result = diagnose_reachability(
                    matched_route(),
                    (
                        outcome("internal", success=internal_success),
                        outcome("external", success=external_success),
                    ),
                ).to_dict()

                self.assertEqual(result["status"], status)
                self.assertEqual(result["should_notify"], notify)
                self.assertEqual(result["classification"], classification)
                self.assertIn("更可能", result["finding"])

    def test_result_keeps_alert_route_owners_and_probe_evidence(self) -> None:
        result = diagnose_reachability(
            matched_route(),
            (
                outcome("internal", success=True, evidence="tcping succeeded"),
                outcome(
                    "external",
                    success=False,
                    final_error="connection timed out",
                    evidence="tcping timed out after 3 attempts",
                ),
            ),
        ).to_dict()

        self.assertEqual(result["alert"]["monitor_name"], "service-a-port-8002")
        self.assertEqual(result["route"]["id"], "service-a")
        self.assertEqual(result["route"]["diagnosis"]["port"], 8002)
        self.assertEqual(result["route"]["owners"], [OWNER])
        self.assertEqual(result["probes"]["internal"]["evidence"], "tcping succeeded")
        self.assertEqual(
            result["probes"]["external"]["final_error"],
            "connection timed out",
        )
        self.assertIn("建议优先检查", result["suggested_checks"][0])

    def test_probe_failure_is_business_result_not_input_error(self) -> None:
        result = diagnose_reachability(
            matched_route(),
            (
                outcome(
                    "internal",
                    success=False,
                    final_error="dns lookup failed",
                ),
                outcome("external", success=True),
            ),
        ).to_dict()

        self.assertEqual(result["status"], "abnormal")
        self.assertEqual(result["classification"], "internal_path_issue_likely")
        self.assertEqual(result["probes"]["internal"]["final_error"], "dns lookup failed")

    def test_unmatched_route_returns_structured_error(self) -> None:
        result = diagnose_reachability(
            missing_route(),
            (
                outcome("internal", success=True),
                outcome("external", success=True),
            ),
        ).to_dict()

        self.assertEqual(result["status"], "error")
        self.assertFalse(result["should_notify"])
        self.assertEqual(result["reason"], "route_not_matched")
        self.assertEqual(result["alert"]["monitor_name"], "service-a-port-8002")
        self.assertNotIn("classification", result)

    def test_missing_probe_result_returns_structured_error(self) -> None:
        result = diagnose_reachability(
            matched_route(),
            (outcome("internal", success=True),),
        ).to_dict()

        self.assertEqual(result["status"], "error")
        self.assertEqual(result["reason"], "missing_probe_result")
        self.assertEqual(result["error_details"]["missing_perspectives"], ["external"])
        self.assertEqual(result["route"]["id"], "service-a")

    def test_duplicate_probe_perspective_returns_structured_error(self) -> None:
        result = diagnose_reachability(
            matched_route(),
            (
                outcome("internal", success=True),
                outcome("internal", success=False),
            ),
        ).to_dict()

        self.assertEqual(result["status"], "error")
        self.assertEqual(result["reason"], "duplicate_probe_perspective")
        self.assertEqual(result["error_details"]["perspective"], "internal")

    def test_invalid_attempts_returns_structured_error(self) -> None:
        result = diagnose_reachability(
            matched_route(),
            (
                outcome("internal", success=True, attempts=0),
                outcome("external", success=True),
            ),
        ).to_dict()

        self.assertEqual(result["status"], "error")
        self.assertEqual(result["reason"], "invalid_probe_attempts")
        self.assertEqual(result["error_details"]["attempts"], 0)


if __name__ == "__main__":
    unittest.main()
