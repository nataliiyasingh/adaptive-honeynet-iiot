
from eventlog.schema import SecurityEvent
from eventlog.storage import EventStore

store = EventStore()

event = SecurityEvent.create(
    source_ip="192.0.2.10",
    asset="plc-01",
    protocol="modbus",
    event_type="register_enumeration",
    severity=3,
    details={"function_code": 3, "register_count": 10},
)

store.append(event)

print("Recorded event:")
print(event.to_json())
print("Total stored events:", len(store.read_all()))
