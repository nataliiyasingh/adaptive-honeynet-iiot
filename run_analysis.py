
from collections import defaultdict

from eventlog.storage import EventStore
from detection.behaviour import AttackerState, process_event


def analyse_events():
    store = EventStore()
    events = store.read_all()

    if not events:
        print("No events found. Run test_logger.py first.")
        return

    attackers = defaultdict(
        lambda: None
    )

    for event in events:
        source_ip = event.get("source_ip", "unknown")

        if attackers[source_ip] is None:
            attackers[source_ip] = AttackerState(source_ip=source_ip)

        state = attackers[source_ip]
        process_event(state, event)

    print("\n=== IIoT Honeynet Behaviour Analysis ===")
    print(f"Events processed: {len(events)}")

    for source_ip, state in attackers.items():
        print(f"\nAttacker: {source_ip}")
        print(f"Events observed: {len(state.observed_events)}")
        print(f"Behaviour score: {state.score}")
        print(f"Classification: {state.classification}")
        print(f"Deception mode: {state.deception_mode}")


if __name__ == "__main__":
    analyse_events()
