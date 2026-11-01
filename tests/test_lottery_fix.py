"""
Regression tests for the lottery spam false-negative fix.

Verifies:
  1. The exact bug-report lottery message is classified as SPAM.
  2. A legitimate university announcement with 'free', 'offer', and URLs stays HAM.
  3. Ordinary URL-containing messages are not automatically SPAM.
  4. Informational lottery mentions (no URL, no CTA) are not SPAM.
  5. The scam rule fires only when all three conditions co-occur.
"""
import unittest
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from detection.spam_rules import SpamRuleEngine
from detection.analyzer import MessageAnalyzer


class TestLotteryFix(unittest.TestCase):
    def setUp(self):
        self.engine = SpamRuleEngine()
        self.analyzer = MessageAnalyzer()

    # ------------------------------------------------------------------
    # 1. Bug-report message must now be SPAM
    # ------------------------------------------------------------------
    def test_lottery_scam_message_classified_as_spam(self):
        """The bug-report lottery message must be classified as SPAM."""
        msg = (
            "hello you won a lottery collect your prize as soon as possible "
            "by clicking on the given link www.prize.com"
        )
        res = self.analyzer.analyze_message(msg)
        self.assertEqual(res["status"], "success")
        self.assertEqual(
            res["prediction"], "SPAM",
            "Expected SPAM but got %s (spam_prob=%s%%)" % (
                res["prediction"], res["spam_probability"])
        )

    def test_lottery_keyword_triggers_promotional(self):
        """'lottery' must now trigger PROMOTIONAL_LANGUAGE."""
        res = self.engine.analyze_rules("I won a lottery today")
        self.assertTrue(res["rule_stats"]["has_promotional_keywords"])
        types = [i["type"] for i in res["indicators"]]
        self.assertIn("PROMOTIONAL_LANGUAGE", types)

    def test_strong_lottery_scam_rule_fires_for_bug_message(self):
        """Rule engine must flag the bug-report message with STRONG_LOTTERY_SCAM_PATTERN."""
        msg = (
            "hello you won a lottery collect your prize as soon as possible "
            "by clicking on the given link www.prize.com"
        )
        res = self.engine.analyze_rules(msg)
        self.assertTrue(
            res["rule_stats"]["is_strong_lottery_scam"],
            "is_strong_lottery_scam must be True for the bug-report message"
        )
        types = [i["type"] for i in res["indicators"]]
        self.assertIn("STRONG_LOTTERY_SCAM_PATTERN", types)

    # ------------------------------------------------------------------
    # 2. Legitimate university announcement must stay HAM
    # ------------------------------------------------------------------
    def test_university_announcement_stays_ham(self):
        """Legitimate university announcement with free/offer/URLs must stay HAM."""
        msg = (
            "Dear students, we are pleased to offer a free workshop on career development "
            "this Friday at 3 PM. Register at https://university.edu/workshop and check "
            "https://university.edu/faq for more information."
        )
        res = self.analyzer.analyze_message(msg)
        self.assertEqual(res["status"], "success")
        self.assertEqual(
            res["prediction"], "HAM",
            "Expected HAM but got %s (spam_prob=%s%%)" % (
                res["prediction"], res["spam_probability"])
        )

    def test_scam_rule_silent_for_university_announcement(self):
        """STRONG_LOTTERY_SCAM_PATTERN must NOT fire for a university announcement."""
        msg = (
            "Dear students, we are pleased to offer a free workshop on career development "
            "this Friday at 3 PM. Register at https://university.edu/workshop."
        )
        res = self.engine.analyze_rules(msg)
        self.assertFalse(
            res["rule_stats"]["is_strong_lottery_scam"],
            "is_strong_lottery_scam must NOT fire for a university announcement"
        )

    # ------------------------------------------------------------------
    # 3. Ordinary URL message must not be SPAM
    # ------------------------------------------------------------------
    def test_ordinary_url_message_not_spam(self):
        """A plain message with a URL and no spam language must not be SPAM."""
        msg = "Please check out the project docs at https://docs.example.com"
        res = self.analyzer.analyze_message(msg)
        self.assertEqual(
            res["prediction"], "HAM",
            "Expected HAM for plain URL message (spam_prob=%s%%)" % res["spam_probability"]
        )
        rule_res = self.engine.analyze_rules(msg)
        self.assertFalse(rule_res["rule_stats"]["is_strong_lottery_scam"])

    # ------------------------------------------------------------------
    # 4. Informational lottery mention (no URL, no CTA) must not be SPAM
    # ------------------------------------------------------------------
    def test_informational_lottery_rule_silent(self):
        """Informational lottery text without URL/CTA must NOT trigger the scam rule."""
        msg = "The national lottery results are published every Saturday evening at 9 PM."
        res = self.engine.analyze_rules(msg)
        self.assertFalse(
            res["rule_stats"]["is_strong_lottery_scam"],
            "Informational lottery text must not trigger is_strong_lottery_scam"
        )

    def test_informational_lottery_stays_ham(self):
        """Informational lottery announcement without a URL must not be SPAM."""
        msg = "The national lottery results are published every Saturday evening at 9 PM."
        res = self.analyzer.analyze_message(msg)
        self.assertEqual(
            res["prediction"], "HAM",
            "Expected HAM for informational lottery text but got %s" % res["prediction"]
        )

    # ------------------------------------------------------------------
    # 5. Three-condition gate: rule must not fire when one condition is missing
    # ------------------------------------------------------------------
    def test_rule_requires_url_present(self):
        """Prize/lottery + urgency without URL must NOT trigger the scam rule."""
        msg = "You won a lottery, collect your prize as soon as possible!"
        res = self.engine.analyze_rules(msg)
        self.assertFalse(
            res["rule_stats"]["is_strong_lottery_scam"],
            "Scam rule must NOT fire without a URL"
        )

    def test_rule_requires_prize_lottery_language(self):
        """URL + urgency without prize/lottery language must NOT trigger the scam rule."""
        msg = "Please act now and visit www.example.com as soon as possible!"
        res = self.engine.analyze_rules(msg)
        self.assertFalse(
            res["rule_stats"]["is_strong_lottery_scam"],
            "Scam rule must NOT fire without prize/lottery language"
        )


if __name__ == "__main__":
    unittest.main()
