import unittest
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from detection.analyzer import get_analyzer

class TestMessageAnalyzer(unittest.TestCase):
    def setUp(self):
        self.analyzer = get_analyzer()

    def test_empty_input(self):
        res = self.analyzer.analyze_message("")
        self.assertEqual(res['status'], 'error')
        self.assertIn('empty', res['message'].lower())

    def test_whitespace_input(self):
        res = self.analyzer.analyze_message("   \n\t   ")
        self.assertEqual(res['status'], 'error')

    def test_known_spam_message(self):
        msg = "WINNER!! You have won a $1,000 gift card! Claim now at http://bit.ly/claim-now or call 0800123456"
        res = self.analyzer.analyze_message(msg)
        self.assertEqual(res['status'], 'success')
        self.assertEqual(res['prediction'], 'SPAM')
        self.assertGreater(res['spam_probability'], 50.0)
        self.assertIn('indicators', res)
        self.assertIn('statistics', res)
        self.assertEqual(res['statistics']['url_count'], 1)

    def test_known_ham_message(self):
        msg = "Hey John, are we still meeting for lunch at 12:30 PM today? Let me know."
        res = self.analyzer.analyze_message(msg)
        self.assertEqual(res['status'], 'success')
        self.assertEqual(res['prediction'], 'HAM')
        self.assertGreater(res['ham_probability'], 50.0)
        self.assertIn('indicators', res)

if __name__ == "__main__":
    unittest.main()
