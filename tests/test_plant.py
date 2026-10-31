
import json
import tempfile
import unittest
from pathlib import Path

from plant.plant import TankPlant


class FakeClock:
    def __init__(self):
        self.now = 100.0

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


class TestTankPlant(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()
        self.plant = TankPlant(clock=self.clock)

    def test_level_advances_with_elapsed_time(self):
        self.clock.advance(2)
        self.assertEqual(self.plant.read_register(0), 430)

    def test_level_does_not_advance_without_elapsed_time(self):
        self.assertEqual(self.plant.read_register(0), 420)

    def test_drain_rate(self):
        self.plant.filling = False
        self.plant.draining = True
        self.clock.advance(2)
        self.assertEqual(self.plant.read_register(0), 414)

    def test_level_is_clamped_at_maximum(self):
        self.plant.level = 998
        self.clock.advance(2)
        self.assertEqual(self.plant.read_register(0), 1000)

    def test_control_write_updates_readback(self):
        self.plant.write_register(1, 0)
        self.assertEqual(self.plant.read_register(1), 0)
        self.clock.advance(10)
        self.assertEqual(self.plant.read_register(0), 420)

    def test_level_write_updates_readback(self):
        self.plant.write_register(0, 650)
        self.assertEqual(self.plant.read_register(0), 650)

    def test_invalid_level_write_is_rejected(self):
        with self.assertRaises(ValueError):
            self.plant.write_register(0, 1200)

    def test_unsupported_register_is_rejected(self):
        with self.assertRaises(ValueError):
            self.plant.read_register(99)

    def test_save_and_load_state(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "tank.json"
            self.plant.write_register(0, 650)
            self.plant.write_register(1, 0)
            self.plant.save(path)

            restored = TankPlant(clock=self.clock)
            restored.load(path)

            self.assertEqual(restored.read_register(0), 650)
            self.assertEqual(restored.read_register(1), 0)

    def test_saved_state_is_valid_json(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "tank.json"
            self.plant.save(path)
            self.assertEqual(json.loads(path.read_text())["level"], 420)


if __name__ == "__main__":
    unittest.main()

