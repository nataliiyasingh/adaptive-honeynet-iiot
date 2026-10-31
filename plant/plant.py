
"""Time-based tank process model for the IIoT honeynet.

Register units:
  0: tank level, tenths of a percent (0–1000)
  1: filling enabled (0 or 1)
  2: draining enabled (0 or 1)

Rates are simulation parameters, not measured industrial values.
"""

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable


@dataclass
class TankPlant:
    level: int = 420
    fill_rate: float = 5.0
    drain_rate: float = 3.0
    minimum: int = 0
    maximum: int = 1000
    filling: bool = True
    draining: bool = False
    clock: Callable[[], float] = field(
        default=time.monotonic, repr=False, compare=False
    )
    _last_update: float = field(init=False, repr=False)

    def __post_init__(self):
        if self.minimum >= self.maximum:
            raise ValueError("minimum must be less than maximum")
        if not self.minimum <= self.level <= self.maximum:
            raise ValueError("initial level is outside configured bounds")
        if self.fill_rate < 0 or self.drain_rate < 0:
            raise ValueError("rates cannot be negative")
        self._last_update = self.clock()

    def advance(self, elapsed_seconds: float | None = None) -> int:
        """Advance using elapsed time, or time since the previous update."""
        if elapsed_seconds is None:
            now = self.clock()
            elapsed_seconds = now - self._last_update
            if elapsed_seconds < 0:
                raise ValueError("clock moved backwards")
            self._last_update = now
        elif elapsed_seconds < 0:
            raise ValueError("elapsed time cannot be negative")
        else:
            # Explicit time advancement is useful for deterministic tests.
            self._last_update = self.clock()

        net_rate = (
            (self.fill_rate if self.filling else 0.0)
            - (self.drain_rate if self.draining else 0.0)
        )
        updated = round(self.level + net_rate * elapsed_seconds)
        self.level = max(self.minimum, min(self.maximum, updated))
        return self.level

    def read_register(self, address: int) -> int:
        self.advance()
        if address == 0:
            return self.level
        if address == 1:
            return int(self.filling)
        if address == 2:
            return int(self.draining)
        raise ValueError(f"Unsupported simulated register: {address}")

    def write_register(self, address: int, value: int) -> None:
        self.advance()

        if not isinstance(value, int) or not 0 <= value <= 0xFFFF:
            raise ValueError("register value must be a 16-bit integer")

        if address == 0:
            if not self.minimum <= value <= self.maximum:
                raise ValueError("tank level is outside configured bounds")
            self.level = value
        elif address == 1:
            if value not in (0, 1):
                raise ValueError("filling control must be 0 or 1")
            self.filling = bool(value)
        elif address == 2:
            if value not in (0, 1):
                raise ValueError("draining control must be 0 or 1")
            self.draining = bool(value)
        else:
            raise ValueError(f"Unsupported simulated register: {address}")

    def save(self, path: str | Path) -> None:
        """Save the current simulated process state as JSON."""
        self.advance()
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "level": self.level,
            "filling": self.filling,
            "draining": self.draining,
        }
        temporary = target.with_suffix(target.suffix + ".tmp")
        temporary.write_text(json.dumps(payload, indent=2) + "\n")
        temporary.replace(target)

    def load(self, path: str | Path) -> None:
        """Restore process state from a previously saved JSON file."""
        payload = json.loads(Path(path).read_text())
        level = payload["level"]
        filling = payload["filling"]
        draining = payload["draining"]

        if not isinstance(level, int) or not self.minimum <= level <= self.maximum:
            raise ValueError("saved tank level is outside configured bounds")
        if not isinstance(filling, bool) or not isinstance(draining, bool):
            raise ValueError("saved control states must be booleans")

        self.level = level
        self.filling = filling
        self.draining = draining
        self._last_update = self.clock()

