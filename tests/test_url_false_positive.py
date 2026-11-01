"""
Regression tests for URL-related false-positive fix.

These tests verify that the presence of legitimate URLs alone does not cause
spam classification, while preserving existing spam-detection capabilities.
"""
import unittest
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from detection.spam_rules import SpamRuleEngine
from detection.analyzer import MessageAnalyzer


class TestURLFalsePositiveFix(unittest.TestCase):
    """
    Regression tests for the URL false-positive bug fix.

    Root cause fixed:
      1. spam_rules.py: substring matching caused 't.co' to match inside
         'gpt.com' / 'copilot.com' → now uses exact hostname comparison.
      2. spam_rules.py: len(urls) >= 2 alone triggered SUSPICIOUS_URL →
         removed; multiple URLs are not suspicious by themselves.
      3. text_preprocessor.py: each URL became a separate 'urltoken', so
         4 URLs → 4 tokens, biasing the Naive Bayes model toward SPAM →
         now all URLs collapse to a single 'urltoken'.
    """

    def setUp(self):
        self.engine = SpamRuleEngine()
        # Use a fresh instance so module-level reloads are reflected.
        self.analyzer = MessageAnalyzer()

    # ------------------------------------------------------------------
    # Test Case A — Legitimate multi-URL message (the original false positive)
    # ------------------------------------------------------------------
    def test_A_multi_url_legitimate_message_not_spam(self):
        """URLs from geeksforgeeks, github, gpt.com, copilot.com must not trigger spam."""
        msg = (
            "Check out these links for help:\n"
            "https://www.geeksforgeeks.org/\n"
            "https://github.com/\n"
            "www.gpt.com/\n"
            "www.copilot.com/\n"
            "Compare the results from these websites and shorten the letter."
        )
        res = self.analyzer.analyze_message(msg)
        self.assertEqual(res['status'], 'success')
        # Primary assertion: no longer falsely classified as spam.
        self.assertEqual(
            res['prediction'], 'HAM',
            f"Expected HAM but got SPAM (spam_prob={res['spam_probability']}%)"
        )
        # URL presence alone must not generate a SUSPICIOUS_URL indicator.
        indicator_types = [i['type'] for i in res['indicators']]
        self.assertNotIn(
            'SUSPICIOUS_URL', indicator_types,
            "SUSPICIOUS_URL indicator must not fire for legitimate multi-URL message"
        )

    def test_A_rule_engine_no_suspicious_url_for_legitimate_domains(self):
        """Rule engine must not flag geeksforgeeks/github/gpt/copilot as suspicious."""
        msg = (
            "Check out these links for help:\n"
            "https://www.geeksforgeeks.org/\n"
            "https://github.com/\n"
            "www.gpt.com/\n"
            "www.copilot.com/\n"
            "Compare the results from these websites and shorten the letter."
        )
        res = self.engine.analyze_rules(msg)
        self.assertFalse(
            res['rule_stats']['has_suspicious_urls'],
            "has_suspicious_urls must be False for legitimate multi-URL message"
        )
        indicator_types = [i['type'] for i in res['indicators']]
        self.assertNotIn('SUSPICIOUS_URL', indicator_types)

    def test_A_gpt_com_not_matched_as_shortener(self):
        """'gpt.com' must not match the 't.co' shortener via substring."""
        res = self.engine.analyze_rules("Visit www.gpt.com/ for more info.")
        self.assertFalse(
            res['rule_stats']['has_suspicious_urls'],
            "gpt.com incorrectly matched as URL shortener via 't.co' substring"
        )

    def test_A_copilot_com_not_matched_as_shortener(self):
        """'copilot.com' must not match the 't.co' shortener via substring."""
        res = self.engine.analyze_rules("Check out www.copilot.com/ today.")
        self.assertFalse(
            res['rule_stats']['has_suspicious_urls'],
            "copilot.com incorrectly matched as URL shortener via 't.co' substring"
        )

    # ------------------------------------------------------------------
    # Test Case B — Single legitimate URL
    # ------------------------------------------------------------------
    def test_B_single_legitimate_url_no_suspicious_indicator(self):
        """A single legitimate URL must not generate a SUSPICIOUS_URL indicator."""
        msg = "Please check this programming tutorial: https://www.geeksforgeeks.org/"
        res = self.engine.analyze_rules(msg)
        self.assertFalse(
            res['rule_stats']['has_suspicious_urls'],
            "Single legitimate URL must not be flagged as suspicious"
        )

    def test_B_single_url_no_suspicious_indicator_in_analyzer(self):
        """Analyzer must not produce SUSPICIOUS_URL for a single legitimate URL."""
        msg = "Please check this programming tutorial: https://www.geeksforgeeks.org/"
        res = self.analyzer.analyze_message(msg)
        self.assertEqual(res['status'], 'success')
        indicator_types = [i['type'] for i in res['indicators']]
        self.assertNotIn(
            'SUSPICIOUS_URL', indicator_types,
            "SUSPICIOUS_URL must not be raised for a single legitimate URL"
        )

    # ------------------------------------------------------------------
    # Test Case C — Suspicious content, no URL (existing detection preserved)
    # ------------------------------------------------------------------
    def test_C_suspicious_content_still_detected(self):
        """Phishing-style message without a URL must still be flagged."""
        msg = "Your account will be blocked immediately. Send your password and OTP using this link."
        res = self.engine.analyze_rules(msg)
        indicator_types = [i['type'] for i in res['indicators']]
        # Must detect at least one of: SENSITIVE_REQUEST or URGENCY_LANGUAGE
        self.assertTrue(
            'SENSITIVE_REQUEST' in indicator_types or 'URGENCY_LANGUAGE' in indicator_types,
            f"Expected SENSITIVE_REQUEST or URGENCY_LANGUAGE, got: {indicator_types}"
        )

    # ------------------------------------------------------------------
    # Test Case D — Deceptive lookalike domain
    # ------------------------------------------------------------------
    def test_D_deceptive_domain_password_request_flagged(self):
        """A message with a suspicious domain and password request must be flagged."""
        msg = "Verify your GitHub account at https://github-security-example.com/ and enter your password."
        res = self.engine.analyze_rules(msg)
        indicator_types = [i['type'] for i in res['indicators']]
        # The password-request rule must fire regardless of domain.
        self.assertIn(
            'SENSITIVE_REQUEST', indicator_types,
            "SENSITIVE_REQUEST must be flagged for a password-request phishing message"
        )

    def test_D_actual_shortener_still_flagged(self):
        """A real shortener domain (bit.ly) must still be detected as suspicious."""
        msg = "Click here to claim your prize: http://bit.ly/abc123"
        res = self.engine.analyze_rules(msg)
        self.assertTrue(
            res['rule_stats']['has_suspicious_urls'],
            "bit.ly shortener URL must still be flagged as suspicious"
        )
        indicator_types = [i['type'] for i in res['indicators']]
        self.assertIn('SUSPICIOUS_URL', indicator_types)

    def test_D_ip_address_url_still_flagged(self):
        """A raw-IP-address URL must still be detected as suspicious."""
        msg = "Log into your account at http://192.168.1.1/login to verify."
        res = self.engine.analyze_rules(msg)
        self.assertTrue(
            res['rule_stats']['has_suspicious_urls'],
            "IP-address URL must still be flagged as suspicious"
        )

    # ------------------------------------------------------------------
    # Test Case E — Spam without URL (existing capability preserved)
    # ------------------------------------------------------------------
    def test_E_spam_no_url_still_detected(self):
        """Classic spam without URLs must still be classified as SPAM."""
        msg = "Congratulations! You have won a prize. Send your bank details immediately to claim it."
        res = self.analyzer.analyze_message(msg)
        self.assertEqual(res['status'], 'success')
        self.assertEqual(
            res['prediction'], 'SPAM',
            f"Expected SPAM but got {res['prediction']} (spam_prob={res['spam_probability']}%)"
        )

    # ------------------------------------------------------------------
    # Additional: URL-plus-promotional still suspicious
    # ------------------------------------------------------------------
    def test_url_with_promotional_content_flagged(self):
        """A URL alongside promotional keywords must still raise a SUSPICIOUS_URL indicator."""
        msg = "Congratulations! You have won a free prize. Claim now at https://win-now.com"
        res = self.engine.analyze_rules(msg)
        indicator_types = [i['type'] for i in res['indicators']]
        self.assertIn(
            'SUSPICIOUS_URL', indicator_types,
            "URL embedded with promotional content should still be flagged"
        )


if __name__ == '__main__':
    unittest.main()
