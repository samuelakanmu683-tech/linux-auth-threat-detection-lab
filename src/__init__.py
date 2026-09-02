from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import timedelta

from .parser import AuthEvent

@dataclass(frozen=True)
class Alert:
    rule_id: str
    name: str
    severity: str
    message: str
    source_ip: str | None = None
    user: str | None = None
    evidence_count: int = 0

def detect_bruteforce(
    events: list[AuthEvent],
    threshold: int = 5,
    window_minutes: int = 5,
) -> list[Alert]:
    """AUTH-001: detect repeated failures against the same account."""

    failures = [event for event in events if event.action == "failed"]
    alerts: list[Alert] = []
    alerted_pairs: set[tuple[str, str]] = set()

    for i, event in enumerate(failures):
        key = (event.source_ip, event.user)

        if key in alerted_pairs:
            continue

        window_end = event.timestamp + timedelta(minutes=window_minutes)

        window = [
            candidate
            for candidate in failures[i:]
            if candidate.timestamp <= window_end
            and candidate.source_ip == event.source_ip
            and candidate.user == event.user
        ]

        if len(window) >= threshold:
            alerts.append(
                Alert(
                    rule_id="AUTH-001",
                    name="SSH Brute Force",
                    severity="HIGH",
                    message=(
                        f"{len(window)} failed authentication attempts "
                        f"from {event.source_ip} targeting {event.user}"
                    ),
                    source_ip=event.source_ip,
                    user=event.user,
                    evidence_count=len(window),
                )
            )

            alerted_pairs.add(key)

    return alerts

def detect_success_after_failures(events: list[AuthEvent], threshold: int = 3, window_minutes: int = 10) -> list[Alert]:
    alerts: list[Alert] = []

    for i, event in enumerate(events):
        if event.action != "accepted":
            continue

        start = event.timestamp - timedelta(minutes=window_minutes)
        prior_failures = [
            candidate for candidate in events[:i]
            if candidate.action == "failed"
            and candidate.source_ip == event.source_ip
            and candidate.user == event.user
            and start <= candidate.timestamp < event.timestamp
        ]

        if len(prior_failures) >= threshold:
            alerts.append(Alert(
                rule_id="AUTH-002",
                name="Successful Login Following Repeated Failures",
                severity="HIGH",
                message=f"Successful login for {event.user} from {event.source_ip} followed {len(prior_failures)} failures",
                source_ip=event.source_ip,
                user=event.user,
                evidence_count=len(prior_failures) + 1,
            ))
    return alerts

def detect_multiple_sources(events: list[AuthEvent], minimum_sources: int = 3) -> list[Alert]:
    sources_by_user: dict[str, set[str]] = defaultdict(set)

    for event in events:
        if event.action == "failed":
            sources_by_user[event.user].add(event.source_ip)

    alerts: list[Alert] = []
    for user, sources in sorted(sources_by_user.items()):
        if len(sources) >= minimum_sources:
            alerts.append(Alert(
                rule_id="AUTH-003",
                name="Multiple Sources Targeting Account",
                severity="MEDIUM",
                message=f"{len(sources)} source IPs generated failed authentication events for {user}",
                user=user,
                evidence_count=len(sources),
            ))
    return alerts


def detect_privileged_accounts(
    events: list[AuthEvent],
    privileged_users: set[str] | None = None,
) -> list[Alert]:
    """AUTH-004: summarize authentication activity involving privileged accounts."""
    privileged_users = privileged_users or {"root", "administrator", "admin"}

    activity: dict[tuple[str, str], list[AuthEvent]] = defaultdict(list)

    for event in events:
        if event.user in privileged_users:
            activity[(event.user, event.source_ip)].append(event)

    alerts: list[Alert] = []

    for (user, source_ip), account_events in sorted(activity.items()):
        failures = sum(event.action == "failed" for event in account_events)
        successes = sum(event.action == "accepted" for event in account_events)

        alerts.append(
            Alert(
                rule_id="AUTH-004",
                name="Privileged Account Authentication Activity",
                severity="MEDIUM",
                message=(
                    f"Privileged account {user} generated "
                    f"{len(account_events)} authentication events from "
                    f"{source_ip}: {failures} failed, {successes} successful"
                ),
                source_ip=source_ip,
                user=user,
                evidence_count=len(account_events),
            )
        )

    return alerts

def run_detections(events: list[AuthEvent]) -> list[Alert]:
    alerts = []
    alerts.extend(detect_bruteforce(events))
    alerts.extend(detect_success_after_failures(events))
    alerts.extend(detect_multiple_sources(events))
    alerts.extend(detect_privileged_accounts(events))
    return alerts
