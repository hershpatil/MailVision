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

if __name__ == "__main__":
    unittest.main()
