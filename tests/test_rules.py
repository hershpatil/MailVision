import unittest
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from detection.spam_rules import SpamRuleEngine

class TestSpamRuleEngine(unittest.TestCase):
    def setUp(self):
        self.engine = SpamRuleEngine()

    def test_empty_input(self):
        res = self.engine.analyze_rules("")
        self.assertEqual(len(res['indicators']), 0)
        self.assertFalse(res['rule_stats']['has_promotional_keywords'])

    def test_promotional_keyword_rule(self):
        res = self.engine.analyze_rules("Congratulations! You won a free gift card prize!")
        types = [i['type'] for i in res['indicators']]
        self.assertIn("PROMOTIONAL_LANGUAGE", types)
        self.assertTrue(res['rule_stats']['has_promotional_keywords'])

    def test_urgency_rule(self):
        res = self.engine.analyze_rules("URGENT! Immediate action required. Claim now before it expires!")
        types = [i['type'] for i in res['indicators']]
        self.assertIn("URGENCY_LANGUAGE", types)
        self.assertTrue(res['rule_stats']['has_urgency'])

    def test_sensitive_information_rule(self):
        res = self.engine.analyze_rules("Security Alert: Please verify your account and credit card details.")
        types = [i['type'] for i in res['indicators']]
        self.assertIn("SENSITIVE_REQUEST", types)
        self.assertTrue(res['rule_stats']['has_sensitive_requests'])

    def test_suspicious_url_rule(self):
        res = self.engine.analyze_rules("Click here to log in: http://bit.ly/3xXyZ or http://192.168.1.1/login")
        types = [i['type'] for i in res['indicators']]
        self.assertIn("SUSPICIOUS_URL", types)
        self.assertTrue(res['rule_stats']['has_suspicious_urls'])

    def test_phone_number_rule(self):
        res = self.engine.analyze_rules("Call 0800123456 now to claim your cash bonus!")
        types = [i['type'] for i in res['indicators']]
        self.assertIn("CALL_TO_ACTION_PHONE", types)
        self.assertTrue(res['rule_stats']['has_phone_patterns'])

    def test_excessive_caps_rule(self):
        res = self.engine.analyze_rules("URGENT OFFER FOR YOU WINNER GET CASH INSTANTLY NOW")
        types = [i['type'] for i in res['indicators']]
        self.assertIn("EXCESSIVE_CAPS", types)
        self.assertTrue(res['rule_stats']['excessive_caps'])

    def test_excessive_punctuation_rule(self):
        res = self.engine.analyze_rules("Win big money now$$$ Click here!!! Are you ready???")
        types = [i['type'] for i in res['indicators']]
        self.assertIn("EXCESSIVE_PUNCTUATION", types)
        self.assertTrue(res['rule_stats']['excessive_punctuation'])

if __name__ == "__main__":
    unittest.main()
