from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

AUTH_PATTERN = re.compile(
    r"^(?P<timestamp>\S+)\s+sshd\[(?P<pid>\d+)\]:\s+"
    r"(?P<action>Accepted|Failed)\s+(?P<method>\w+)\s+for\s+"
    r"(?:(?:invalid user)\s+)?(?P<user>\S+)\s+from\s+"
    r"(?P<source_ip>\S+)\s+port\s+(?P<port>\d+)"
)

@dataclass(frozen=True)
class AuthEvent:
    timestamp: datetime
    action: str
    method: str
    user: str
    source_ip: str
    port: int
    pid: int
    raw: str

def parse_line(line: str) -> AuthEvent | None:
    match = AUTH_PATTERN.match(line.strip())
    if not match:
        return None

    data = match.groupdict()
    timestamp = datetime.fromisoformat(data["timestamp"].replace("Z", "+00:00"))

    return AuthEvent(
        timestamp=timestamp.astimezone(timezone.utc),
        action=data["action"].lower(),
        method=data["method"].lower(),
        user=data["user"],
        source_ip=data["source_ip"],
        port=int(data["port"]),
        pid=int(data["pid"]),
        raw=line.strip(),
    )

def load_events(path: str | Path) -> list[AuthEvent]:
    path = Path(path)
    events: list[AuthEvent] = []

    for line in path.read_text(encoding="utf-8").splitlines():
        event = parse_line(line)
        if event:
            events.append(event)

    return sorted(events, key=lambda event: event.timestamp)
