import unittest
import sys
import os
import json

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app import app
from database import db

class TestFlaskRoutes(unittest.TestCase):
    def setUp(self):
        self.app = app.test_client()
        self.app.testing = True
        db.init_db()
        db.clear_history()

    def test_predict_api_success_spam(self):
        payload = {"message": "WINNER!! You have won a $1,000 gift card! Claim now at http://win-now.com or call 0800123456"}
        response = self.app.post('/api/predict', data=json.dumps(payload), content_type='application/json')
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data['status'], 'success')
        self.assertEqual(data['prediction'], 'SPAM')
        self.assertGreater(data['confidence'], 50.0)

    def test_predict_api_success_ham(self):
        payload = {"message": "Hey Sarah, are we still meeting for coffee this afternoon?"}
        response = self.app.post('/api/predict', data=json.dumps(payload), content_type='application/json')
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data['status'], 'success')
        self.assertEqual(data['prediction'], 'HAM')

    def test_predict_api_empty_input(self):
        payload = {"message": "   "}
        response = self.app.post('/api/predict', data=json.dumps(payload), content_type='application/json')
        self.assertEqual(response.status_code, 400)
        data = response.get_json()
        self.assertEqual(data['status'], 'error')

    def test_history_api(self):
        # Insert a prediction
        payload = {"message": "Test spam message winner free cash call 0800123"}
        self.app.post('/api/predict', data=json.dumps(payload), content_type='application/json')

        response = self.app.get('/api/history')
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data['status'], 'success')
        self.assertEqual(len(data['history']), 1)

        # Clear history
        clear_res = self.app.post('/api/history/clear')
        self.assertEqual(clear_res.status_code, 200)

        response_after = self.app.get('/api/history')
        self.assertEqual(len(response_after.get_json()['history']), 0)

    def test_privacy_page_accessible(self):
        """Verify /privacy route is publicly accessible, returns 200, and contains Privacy Policy content."""
        response = self.app.get('/privacy')
        self.assertEqual(response.status_code, 200)
        html = response.get_data(as_text=True)
        self.assertIn("Privacy Policy", html)
        self.assertIn("gmail.readonly", html)
        self.assertIn("OAuth 2.0", html)
        self.assertIn("Disconnect Account", html)

    def test_terms_page_accessible(self):
        """Verify /terms route is publicly accessible, returns 200, and contains Terms of Service content."""
        response = self.app.get('/terms')
        self.assertEqual(response.status_code, 200)
        html = response.get_data(as_text=True)
        self.assertIn("Terms of Service", html)
        self.assertIn("Acceptable Use", html)
        self.assertIn("Limitations of Spam Detection Accuracy", html)
        self.assertIn("Disconnect Account", html)

    def test_vercel_rewrite_for_legal_pages(self):
        """Verify Vercel rewrite parameter (?path=...) resolves /privacy and /terms properly."""
        privacy_resp = self.app.get('/api/index?path=privacy')
        self.assertEqual(privacy_resp.status_code, 200)
        self.assertIn("Privacy Policy", privacy_resp.get_data(as_text=True))

        terms_resp = self.app.get('/api/index?path=terms')
        self.assertEqual(terms_resp.status_code, 200)
        self.assertIn("Terms of Service", terms_resp.get_data(as_text=True))

if __name__ == "__main__":
    unittest.main()
