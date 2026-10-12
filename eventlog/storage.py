
import json
from pathlib import Path
from .schema import SecurityEvent


class EventStore:
    def __init__(self, path: str = "data/events.jsonl"):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, event: SecurityEvent) -> None:
        with self.path.open("a", encoding="utf-8") as file:
            file.write(event.to_json() + "\n")

    def read_all(self) -> list[dict]:
        if not self.path.exists():
            return []

        with self.path.open("r", encoding="utf-8") as file:
            return [json.loads(line) for line in file if line.strip()]
