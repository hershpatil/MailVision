import unittest
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config
from database import db

class TestDatabase(unittest.TestCase):
    def setUp(self):
        db.init_db()
        db.clear_history()

    def test_log_and_retrieve_history(self):
        db.log_prediction("SPAM", 98.5, 98.5, 1.5, 25, 2)
        history = db.get_history()
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]['prediction'], "SPAM")
        self.assertEqual(history[0]['confidence'], 98.5)
        self.assertEqual(history[0]['word_count'], 25)
        self.assertEqual(history[0]['url_count'], 2)

    def test_clear_history(self):
        db.log_prediction("HAM", 99.1, 0.9, 99.1, 10, 0)
        db.log_prediction("SPAM", 95.0, 95.0, 5.0, 15, 1)
        self.assertEqual(len(db.get_history()), 2)
        db.clear_history()
        self.assertEqual(len(db.get_history()), 0)

if __name__ == "__main__":
    unittest.main()
