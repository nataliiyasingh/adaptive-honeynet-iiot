
from detection.behaviour import AttackerState, process_event

attacker = AttackerState(source_ip="192.0.2.10")

scenario = [
    {"event_type": "port_scan"},
    {"event_type": "service_enumeration"},
    {"event_type": "modbus_connection"},
    {"event_type": "register_enumeration"},
    {"event_type": "register_write_attempt"},
]

for event in scenario:
    process_event(attacker, event)
    print(
        f"Event: {event['event_type']:<25} "
        f"Score: {attacker.score:<3} "
        f"Classification: {attacker.classification:<22} "
        f"Mode: {attacker.deception_mode}"
    )
