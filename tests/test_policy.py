
import unittest

from deception.policy import select_policy


class TestPolicy(unittest.TestCase):

    def test_baseline_for_zero_score(self):
        decision = select_policy(0)
        self.assertEqual(decision.classification, "unknown")
        self.assertEqual(decision.deception_mode, "baseline")

    def test_low_interest_threshold(self):
        decision = select_policy(1)
        self.assertEqual(decision.classification, "low_interest")
        self.assertEqual(decision.deception_mode, "baseline")

    def test_reconnaissance_threshold(self):
        decision = select_policy(5)
        self.assertEqual(decision.classification, "reconnaissance")
        self.assertEqual(decision.deception_mode, "engagement")

    def test_ics_focused_threshold(self):
        decision = select_policy(10)
        self.assertEqual(decision.classification, "ics_focused")
        self.assertEqual(decision.deception_mode, "engagement")

    def test_high_deception_threshold(self):
        decision = select_policy(16)
        self.assertEqual(
            decision.classification, "high-risk manipulation"
        )
        self.assertEqual(decision.deception_mode, "high_deception")

    def test_negative_score_is_rejected(self):
        with self.assertRaises(ValueError):
            select_policy(-1)


if __name__ == "__main__":
    unittest.main()

