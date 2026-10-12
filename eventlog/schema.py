
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any
import json


@dataclass
class SecurityEvent:
    timestamp: str
    source_ip: str
    asset: str
    protocol: str
    event_type: str
    severity: int
    details: dict[str, Any]

    @classmethod
    def create(
        cls,
        source_ip: str,
        asset: str,
        protocol: str,
        event_type: str,
        severity: int = 1,
        details: dict[str, Any] | None = None,
    ) -> "SecurityEvent":
        return cls(
            timestamp=datetime.now(timezone.utc).isoformat(),
            source_ip=source_ip,
            asset=asset,
            protocol=protocol,
            event_type=event_type,
            severity=max(1, min(severity, 5)),
            details=details or {},
        )

    def to_json(self) -> str:
        return json.dumps(asdict(self))
