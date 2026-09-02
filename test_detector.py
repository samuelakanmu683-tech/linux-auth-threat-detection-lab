from datetime import datetime, timezone

from src.detector import detect_bruteforce, detect_multiple_sources, detect_success_after_failures
from src.parser import AuthEvent

def event(minute: int, action: str, user: str, source_ip: str) -> AuthEvent:
    return AuthEvent(
        timestamp=datetime(2026, 9, 1, 8, minute, tzinfo=timezone.utc),
        action=action,
        method="password",
        user=user,
        source_ip=source_ip,
        port=50000 + minute,
        pid=1000 + minute,
        raw="synthetic",
    )

def test_bruteforce_detection():
    events = [event(i, "failed", "admin", "203.0.113.50") for i in range(5)]
    alerts = detect_bruteforce(events, threshold=5)
    assert len(alerts) == 1
    assert alerts[0].rule_id == "AUTH-001"
    assert alerts[0].severity == "HIGH"

def test_success_after_repeated_failures():
    events = [
        event(0, "failed", "admin", "203.0.113.50"),
        event(1, "failed", "admin", "203.0.113.50"),
        event(2, "failed", "admin", "203.0.113.50"),
        event(3, "accepted", "admin", "203.0.113.50"),
    ]
    alerts = detect_success_after_failures(events, threshold=3)
    assert len(alerts) == 1
    assert alerts[0].rule_id == "AUTH-002"

def test_multiple_sources():
    events = [
        event(0, "failed", "administrator", "198.51.100.20"),
        event(1, "failed", "administrator", "198.51.100.21"),
        event(2, "failed", "administrator", "198.51.100.22"),
    ]
    alerts = detect_multiple_sources(events, minimum_sources=3)
    assert len(alerts) == 1
    assert alerts[0].rule_id == "AUTH-003"
