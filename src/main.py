from pathlib import Path

from .detector import run_detections
from .parser import load_events

def main() -> None:
    data_path = Path(__file__).resolve().parents[1] / "data" / "auth.log"
    events = load_events(data_path)
    alerts = run_detections(events)

    print("=" * 60)
    print("SOC SENTINEL")
    print("Linux Authentication Threat Detection")
    print("=" * 60)
    print(f"Events processed: {len(events)}")
    print(f"Alerts generated: {len(alerts)}")
    print()

    for alert in alerts:
        print(f"[{alert.severity}] {alert.rule_id} - {alert.name}")
        if alert.source_ip:
            print(f"Source: {alert.source_ip}")
        if alert.user:
            print(f"Target: {alert.user}")
        print(f"Evidence count: {alert.evidence_count}")
        print(f"Assessment: {alert.message}")
        print("-" * 60)

if __name__ == "__main__":
    main()
