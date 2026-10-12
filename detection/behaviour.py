
from dataclasses import dataclass, field


# Points assigned to observed behaviours.
EVENT_SCORES = {
    "port_scan": 1,
    "service_enumeration": 2,
    "modbus_connection": 3,
    "register_enumeration": 3,
    "authentication_failure": 2,
    "register_write_attempt": 5,
    "repeated_commands": 3,
}


@dataclass
class AttackerState:
    source_ip: str
    score: int = 0
    observed_events: list[str] = field(default_factory=list)
    classification: str = "unknown"
    deception_mode: str = "baseline"


def classify_behaviour(score: int) -> tuple[str, str]:
    if score >= 16:
        return "high-risk manipulation", "high_deception"
    if score >= 10:
        return "ics_focused", "engagement"
    if score >= 5:
        return "reconnaissance", "engagement"
    if score >= 1:
        return "low_interest", "baseline"
    return "unknown", "baseline"


def process_event(state: AttackerState, event: dict) -> AttackerState:
    event_type = event.get("event_type", "unknown")
    points = EVENT_SCORES.get(event_type, 0)

    state.score += points
    state.observed_events.append(event_type)

    state.classification, state.deception_mode = classify_behaviour(
        state.score
    )

    return state
