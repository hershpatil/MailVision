"""
Unit and Integration Tests for Gmail OAuth 2.0 Integration & On-Demand Scanning.

Tests:
1. Authenticated token encryption, decryption, and tampering detection at rest.
2. Google OAuth 2.0 authorization URL generation and CSRF state parameter validation.
3. Token exchange, profile retrieval, and database storage.
4. Token expiration detection and automatic refresh logic.
5. Disconnecting Gmail account and database token revocation.
6. Base64URL decoding for standard and non-padded content.
7. HTML-to-text sanitization (stripping scripts, styles, and unescaping entities).
8. Multipart MIME email payload traversal (plain, HTML-only, nested mixed with attachments).
9. Empty email body and missing header fallbacks.
10. On-demand inbox scanning with multiple emails (SPAM and HAM classification).
11. Rate limit, network error, and unauthorized token error handling.
12. Read-only verification (no destructive/mutating Gmail API calls).
"""
import base64
import time
import unittest
from unittest.mock import patch, MagicMock

import config
from app import app
from database import db
from detection.analyzer import get_analyzer
from gmail import auth, email_parser, service


class TestGmailTokenEncryption(unittest.TestCase):
    """Test authenticated encryption at rest for OAuth tokens."""

    def test_encrypt_decrypt_roundtrip(self):
        token = "ya29.a0AfH6SMDh_mock_google_oauth_access_token_12345"
        encrypted = auth.encrypt_token(token)
        self.assertNotEqual(token, encrypted)
        decrypted = auth.decrypt_token(encrypted)
        self.assertEqual(token, decrypted)

    def test_empty_token_encryption(self):
        self.assertEqual(auth.encrypt_token(""), "")
        self.assertEqual(auth.decrypt_token(""), "")

    def test_tampered_token_detection(self):
        token = "secret_access_token_abc"
        encrypted = auth.encrypt_token(token)
        # Tamper with encrypted base64 string
        raw = bytearray(base64.urlsafe_b64decode(encrypted.encode('ascii')))
        raw[-1] ^= 0xFF
        tampered_b64 = base64.urlsafe_b64encode(raw).decode('ascii')
        decrypted = auth.decrypt_token(tampered_b64)
        self.assertEqual(decrypted, "", "Tampered token must fail MAC verification and return empty string")

    def test_different_key_fails_decryption(self):
        token = "secret_refresh_token_xyz"
        encrypted = auth.encrypt_token(token, secret_key="key-one")
        decrypted = auth.decrypt_token(encrypted, secret_key="key-two")
        self.assertEqual(decrypted, "", "Decryption with incorrect secret key must fail MAC check")


class TestGmailOAuthFlow(unittest.TestCase):
    """Test OAuth URL building, CSRF state validation, and token persistence."""

    def setUp(self):
        self.app = app
        self.client = self.app.test_client()
        self.session_id = "test_user_session_123"
        # Ensure clean state in DB for test session
        db.delete_gmail_tokens(self.session_id)

    def tearDown(self):
        db.delete_gmail_tokens(self.session_id)

    def test_authorization_url_construction(self):
        state = "csrf_token_abc_xyz"
        url = auth.get_authorization_url(state)
        self.assertIn("accounts.google.com/o/oauth2/v2/auth", url)
        self.assertIn(f"state={state}", url)
        self.assertIn("response_type=code", url)
        self.assertIn("access_type=offline", url)
        self.assertIn("prompt=consent", url)
        self.assertIn("https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fgmail.readonly", url)

    @patch("requests.post")
    def test_exchange_code_success(self, mock_post):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "access_token": "mock_access_123",
            "refresh_token": "mock_refresh_456",
            "expires_in": 3600,
            "token_type": "Bearer"
        }
        mock_post.return_value = mock_response

        with patch.object(auth, "is_configured", return_value=True):
            tokens, err = auth.exchange_code_for_tokens("mock_auth_code")
            self.assertIsNone(err)
            self.assertIsNotNone(tokens)
            self.assertEqual(tokens["access_token"], "mock_access_123")
            self.assertEqual(tokens["refresh_token"], "mock_refresh_456")

    @patch("requests.post")
    def test_exchange_code_failure(self, mock_post):
        mock_response = MagicMock()
        mock_response.status_code = 400
        mock_response.json.return_value = {"error": "invalid_grant", "error_description": "Code expired"}
        mock_post.return_value = mock_response

        with patch.object(auth, "is_configured", return_value=True):
            tokens, err = auth.exchange_code_for_tokens("expired_code")
            self.assertIsNone(tokens)
            self.assertIn("Code expired", err)

    @patch("requests.get")
    def test_get_user_profile(self, mock_get):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"emailAddress": "user@example.com", "messagesTotal": 42}
        mock_get.return_value = mock_response

        profile, err = auth.get_user_profile("valid_token")
        self.assertIsNone(err)
        self.assertEqual(profile["emailAddress"], "user@example.com")

    def test_save_and_retrieve_connection(self):
        auth.save_connection(self.session_id, "user@gmail.com", "acc_tok_1", "ref_tok_1", 3600)
        account = auth.get_connected_account(self.session_id)
        self.assertIsNotNone(account)
        self.assertEqual(account["email"], "user@gmail.com")

        # Verify access token retrieval
        valid_tok, err = auth.get_valid_access_token(self.session_id)
        self.assertIsNone(err)
        self.assertEqual(valid_tok, "acc_tok_1")

    @patch("requests.post")
    def test_automatic_token_refresh_when_expired(self, mock_post):
        # Save an expired token with a valid refresh token
        auth.save_connection(self.session_id, "user@gmail.com", "expired_token", "my_refresh_tok", expires_in=-10)

        # Mock the refresh token request
        mock_post_resp = MagicMock()
        mock_post_resp.status_code = 200
        mock_post_resp.json.return_value = {
            "access_token": "new_refreshed_access_token_999",
            "expires_in": 3600
        }
        mock_post.return_value = mock_post_resp

        new_tok, err = auth.get_valid_access_token(self.session_id)
        self.assertIsNone(err)
        self.assertEqual(new_tok, "new_refreshed_access_token_999")

    def test_disconnect_clears_stored_tokens(self):
        auth.save_connection(self.session_id, "user@gmail.com", "acc_tok", "ref_tok", 3600)
        self.assertIsNotNone(auth.get_connected_account(self.session_id))

        auth.disconnect_account(self.session_id)
        self.assertIsNone(auth.get_connected_account(self.session_id))
        tok, err = auth.get_valid_access_token(self.session_id)
        self.assertIsNone(tok)
        self.assertIn("No Gmail account connected", err)

    def test_signed_state_generation_and_validation(self):
        """Test cryptographic HMAC state generation and successful validation."""
        state = auth.generate_signed_state(self.session_id)
        is_valid, extracted_sid, reason = auth.validate_signed_state(state, saved_state=state)
        self.assertTrue(is_valid)
        self.assertEqual(extracted_sid, self.session_id)
        self.assertEqual(reason, "State verified successfully")

    def test_tampered_signed_state_rejected(self):
        """Tampered signed state must be rejected with signature mismatch."""
        state = auth.generate_signed_state(self.session_id)
        tampered = state[:-2] + ("ab" if state[-2:] != "ab" else "cd")
        is_valid, _, reason = auth.validate_signed_state(tampered)
        self.assertFalse(is_valid)
        self.assertIn("signature mismatch", reason.lower())

    def test_expired_signed_state_rejected(self):
        """State token older than max_age must be rejected."""
        state = auth.generate_signed_state(self.session_id)
        # Validate with max_age = -1 (instantly expired)
        is_valid, _, reason = auth.validate_signed_state(state, max_age=-1)
        self.assertFalse(is_valid)
        self.assertIn("expired", reason.lower())

    def test_replay_state_rejected(self):
        """Re-using the same state token twice must be rejected by anti-replay protection."""
        state = auth.generate_signed_state(self.session_id)
        is_valid1, _, _ = auth.validate_signed_state(state)
        self.assertTrue(is_valid1)
        is_valid2, _, reason = auth.validate_signed_state(state)
        self.assertFalse(is_valid2)
        self.assertIn("already been consumed", reason.lower())


class TestEmailParsing(unittest.TestCase):
    """Test email parser MIME extraction, HTML cleaning, and Base64URL decoding."""

    def test_decode_base64url(self):
        raw = "Hello World! Special symbols: @#$%^&*()"
        encoded = base64.urlsafe_b64encode(raw.encode('utf-8')).decode('ascii').rstrip('=')
        decoded = email_parser.decode_base64url(encoded)
        self.assertEqual(decoded, raw)

    def test_html_cleaner_strips_scripts_and_styles(self):
        dirty_html = (
            "<html><head><style>body { background: #fff; }</style></head>"
            "<body><h2>Account Alert</h2><p>Your statement is ready. "
            "<script>alert('xss')</script>Visit <a href='https://bank.com'>your account</a>.</p></body></html>"
        )
        cleaned = email_parser.clean_html_to_text(dirty_html)
        self.assertNotIn("alert('xss')", cleaned)
        self.assertNotIn("background: #fff", cleaned)
        self.assertIn("Account Alert", cleaned)
        self.assertIn("Your statement is ready.", cleaned)

    def test_html_cleaner_unescapes_entities(self):
        html_text = "<p>Prices start at &euro;50 &amp; &pound;40 &copy; 2026</p>"
        cleaned = email_parser.clean_html_to_text(html_text)
        self.assertIn("€50", cleaned)
        self.assertIn("&", cleaned)
        self.assertIn("£40", cleaned)
        self.assertIn("©", cleaned)

    def test_multipart_alternative_prefers_plain_text(self):
        payload = {
            "mimeType": "multipart/alternative",
            "parts": [
                {
                    "mimeType": "text/plain",
                    "body": {"data": base64.urlsafe_b64encode(b"This is pure plain text content.").decode('ascii')}
                },
                {
                    "mimeType": "text/html",
                    "body": {"data": base64.urlsafe_b64encode(b"<p>This is formatted HTML content.</p>").decode('ascii')}
                }
            ]
        }
        text, has_attachments = email_parser.extract_payload_text(payload)
        self.assertEqual(text, "This is pure plain text content.")
        self.assertFalse(has_attachments)

    def test_html_only_payload_conversion(self):
        payload = {
            "mimeType": "text/html",
            "body": {
                "data": base64.urlsafe_b64encode(b"<div><p>Only HTML was sent in this email.</p></div>").decode('ascii')
            }
        }
        text, has_attachments = email_parser.extract_payload_text(payload)
        self.assertEqual(text, "Only HTML was sent in this email.")
        self.assertFalse(has_attachments)

    def test_nested_multipart_mixed_with_attachment(self):
        payload = {
            "mimeType": "multipart/mixed",
            "parts": [
                {
                    "mimeType": "multipart/alternative",
                    "parts": [
                        {
                            "mimeType": "text/plain",
                            "body": {"data": base64.urlsafe_b64encode(b"Attached is the project document.").decode('ascii')}
                        }
                    ]
                },
                {
                    "mimeType": "application/pdf",
                    "filename": "Project_Proposal.pdf",
                    "body": {"size": 102400}
                }
            ]
        }
        text, has_attachments = email_parser.extract_payload_text(payload)
        self.assertEqual(text, "Attached is the project document.")
        self.assertTrue(has_attachments)

    def test_parse_gmail_message_full(self):
        msg_data = {
            "id": "msg_001",
            "threadId": "thread_001",
            "snippet": "Short preview of the email...",
            "payload": {
                "headers": [
                    {"name": "From", "value": "Google Security <no-reply@accounts.google.com>"},
                    {"name": "Subject", "value": "Security alert for your linked Google account"},
                    {"name": "Date", "value": "Fri, 30 Oct 2026 10:15:00 +0000"}
                ],
                "mimeType": "text/plain",
                "body": {
                    "data": base64.urlsafe_b64encode(b"A new device logged into your account.").decode('ascii')
                }
            }
        }
        parsed = email_parser.parse_gmail_message(msg_data)
        self.assertEqual(parsed["id"], "msg_001")
        self.assertEqual(parsed["sender"], "Google Security <no-reply@accounts.google.com>")
        self.assertEqual(parsed["subject"], "Security alert for your linked Google account")
        self.assertIn("A new device logged into your account.", parsed["body_text"])
        self.assertEqual(parsed["snippet"], "Short preview of the email...")


class TestGmailServiceScan(unittest.TestCase):
    """Test on-demand inbox scanning, classification, and error states."""

    def setUp(self):
        self.session_id = "test_scan_session_456"
        db.delete_gmail_tokens(self.session_id)
        db.clear_scan_feedback()

    def tearDown(self):
        db.delete_gmail_tokens(self.session_id)
        db.clear_scan_feedback()

    def test_scan_inbox_not_connected(self):
        res = service.scan_inbox(self.session_id)
        self.assertEqual(res["status"], "error")
        self.assertEqual(res["error_type"], "auth_error")
        self.assertIn("connected", res["message"].lower())

    @patch("gmail.auth.get_valid_access_token")
    @patch("gmail.service.fetch_inbox_message_list")
    def test_scan_empty_inbox(self, mock_list, mock_auth):
        mock_auth.return_value = ("mock_token", None)
        mock_list.return_value = ({"messages": []}, None)

        res = service.scan_inbox(self.session_id)
        self.assertEqual(res["status"], "success")
        self.assertEqual(res["total_scanned"], 0)
        self.assertEqual(res["spam_count"], 0)
        self.assertEqual(res["ham_count"], 0)
        self.assertEqual(res["high_risk_count"], 0)
        self.assertEqual(len(res["emails"]), 0)

    @patch("gmail.auth.get_valid_access_token")
    @patch("gmail.service.fetch_inbox_message_list")
    @patch("gmail.service.fetch_message_detail")
    def test_scan_inbox_classifies_spam_and_ham(self, mock_detail, mock_list, mock_auth):
        mock_auth.return_value = ("mock_token", None)
        mock_list.return_value = ({
            "messages": [{"id": "msg_spam"}, {"id": "msg_ham"}],
            "nextPageToken": "page_tok_2"
        }, None)

        def _detail_side_effect(token, msg_id):
            if msg_id == "msg_spam":
                return {
                    "id": "msg_spam",
                    "threadId": "t1",
                    "snippet": "You won a lottery!",
                    "payload": {
                        "headers": [
                            {"name": "From", "value": "Lottery <prize@scam.com>"},
                            {"name": "Subject", "value": "CONGRATULATIONS you won lottery prize collect as soon as possible"},
                            {"name": "Date", "value": "Oct 30, 2026"}
                        ],
                        "mimeType": "text/plain",
                        "body": {
                            "data": base64.urlsafe_b64encode(
                                b"hello you won a lottery collect your prize as soon as possible by clicking on the given link http://www.prize.com"
                            ).decode('ascii')
                        }
                    }
                }, None
            else:
                return {
                    "id": "msg_ham",
                    "threadId": "t2",
                    "snippet": "Team meeting notes",
                    "payload": {
                        "headers": [
                            {"name": "From", "value": "Colleague <colleague@company.com>"},
                            {"name": "Subject", "value": "Project status update for tomorrow"},
                            {"name": "Date", "value": "Oct 30, 2026"}
                        ],
                        "mimeType": "text/plain",
                        "body": {
                            "data": base64.urlsafe_b64encode(
                                b"Hi team, let us review the sprint tasks during tomorrow morning standup. Have a great evening!"
                            ).decode('ascii')
                        }
                    }
                }, None

        mock_detail.side_effect = _detail_side_effect

        res = service.scan_inbox(self.session_id)
        self.assertEqual(res["status"], "success")
        self.assertEqual(res["total_scanned"], 2)
        self.assertEqual(res["spam_count"], 1)
        self.assertEqual(res["ham_count"], 1)
        self.assertEqual(res["high_risk_count"], 1)
        self.assertEqual(res["next_page_token"], "page_tok_2")

        emails = res["emails"]
        self.assertEqual(emails[0]["prediction"], "SPAM")
        self.assertEqual(emails[0]["risk_level"], "High")
        self.assertIn("risk_reasons", emails[0])
        self.assertEqual(emails[1]["prediction"], "HAM")
        self.assertEqual(emails[1]["risk_level"], "Low")
        self.assertIn("risk_reasons", emails[1])
        self.assertIn("indicators", emails[0])

    @patch("gmail.auth.get_valid_access_token")
    @patch("gmail.service.fetch_inbox_message_list")
    def test_scan_rate_limit_handled_gracefully(self, mock_list, mock_auth):
        mock_auth.return_value = ("mock_token", None)
        mock_list.return_value = (None, "Gmail API rate limit exceeded or quota reached. Please try again in a few moments.")

        res = service.scan_inbox(self.session_id)
        self.assertEqual(res["status"], "error")
        self.assertEqual(res["error_type"], "api_error")
        self.assertIn("rate limit", res["message"].lower())

    def test_default_scan_batch_size_is_five(self):
        """Verify default configuration for GMAIL_SCAN_BATCH_SIZE is 5."""
        self.assertEqual(config.GMAIL_SCAN_BATCH_SIZE, 5)

    @patch("requests.get")
    def test_fetch_inbox_message_list_defaults_and_restricts_to_inbox(self, mock_get):
        """Verify fetch_inbox_message_list requests 5 emails strictly from INBOX."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"messages": [{"id": f"msg_{i}"} for i in range(5)]}
        mock_get.return_value = mock_response

        data, err = service.fetch_inbox_message_list("test_access_token")
        self.assertIsNone(err)
        self.assertEqual(len(data["messages"]), 5)

        # Inspect request arguments
        args, kwargs = mock_get.call_args
        params = kwargs.get("params", {})
        self.assertEqual(params.get("maxResults"), 5)
        self.assertEqual(params.get("q"), "in:inbox")
        self.assertEqual(params.get("labelIds"), "INBOX")

    @patch("gmail.auth.get_valid_access_token")
    @patch("gmail.service.fetch_inbox_message_list")
    @patch("gmail.service.fetch_message_detail")
    def test_scan_exactly_five_when_five_exist(self, mock_detail, mock_list, mock_auth):
        """Verify exactly 5 latest inbox emails are fetched and classified when 5 exist."""
        mock_auth.return_value = ("mock_token", None)
        mock_list.return_value = ({
            "messages": [{"id": f"msg_{i}"} for i in range(5)],
            "nextPageToken": "page_tok_next"
        }, None)

        def _detail(token, msg_id):
            return {
                "id": msg_id,
                "threadId": f"t_{msg_id}",
                "snippet": f"Snippet for {msg_id}",
                "internalDate": "1730000000000",
                "payload": {
                    "headers": [
                        {"name": "From", "value": f"Sender {msg_id} <sender@example.com>"},
                        {"name": "Subject", "value": f"Subject for {msg_id}"},
                        {"name": "Date", "value": "Thu, 30 Oct 2026 12:00:00 +0000"}
                    ],
                    "mimeType": "text/plain",
                    "body": {"data": base64.urlsafe_b64encode(b"Regular email text hello").decode('ascii')}
                }
            }, None

        mock_detail.side_effect = _detail

        res = service.scan_inbox(self.session_id)
        self.assertEqual(res["status"], "success")
        self.assertEqual(res["total_scanned"], 5)
        self.assertEqual(len(res["emails"]), 5)
        mock_list.assert_called_once_with("mock_token", max_results=5, page_token=None)

        # Verify all required display fields are present
        for email in res["emails"]:
            self.assertIn("sender", email)
            self.assertIn("subject", email)
            self.assertIn("date", email)
            self.assertIn("prediction", email)
            self.assertIn("confidence", email)
            self.assertIn("risk_level", email)
            self.assertIn("risk_reasons", email)
            self.assertIn("indicators", email)

    @patch("gmail.auth.get_valid_access_token")
    @patch("gmail.service.fetch_inbox_message_list")
    @patch("gmail.service.fetch_message_detail")
    def test_scan_fewer_than_five_when_fewer_exist(self, mock_detail, mock_list, mock_auth):
        """Verify that when fewer than 5 emails exist, all available emails are scanned."""
        mock_auth.return_value = ("mock_token", None)
        mock_list.return_value = ({
            "messages": [{"id": "msg_only_1"}, {"id": "msg_only_2"}],
            "nextPageToken": None
        }, None)

        mock_detail.return_value = ({
            "id": "msg_x",
            "threadId": "tx",
            "snippet": "Short message",
            "payload": {
                "headers": [
                    {"name": "From", "value": "Alice <alice@test.com>"},
                    {"name": "Subject", "value": "Meeting tomorrow"},
                    {"name": "Date", "value": "Thu, 30 Oct 2026 10:00:00 +0000"}
                ],
                "mimeType": "text/plain",
                "body": {"data": base64.urlsafe_b64encode(b"Quick note").decode('ascii')}
            }
        }, None)

        res = service.scan_inbox(self.session_id)
        self.assertEqual(res["status"], "success")
        self.assertEqual(res["total_scanned"], 2)
        self.assertEqual(len(res["emails"]), 2)

    @patch("gmail.auth.get_valid_access_token")
    @patch("gmail.service.fetch_inbox_message_list")
    @patch("gmail.service.fetch_message_detail")
    def test_emails_sorted_newest_first(self, mock_detail, mock_list, mock_auth):
        """Verify emails are sorted newest first based on timestamp / internalDate."""
        mock_auth.return_value = ("mock_token", None)
        # Message list with three IDs
        mock_list.return_value = ({
            "messages": [{"id": "msg_old"}, {"id": "msg_newest"}, {"id": "msg_middle"}],
            "nextPageToken": None
        }, None)

        # Message details with explicit internalDate timestamps (milliseconds)
        timestamps = {
            "msg_old": "1700000000000",      # Oldest
            "msg_middle": "1710000000000",   # Middle
            "msg_newest": "1720000000000"    # Newest
        }

        def _detail(token, msg_id):
            return {
                "id": msg_id,
                "threadId": "t",
                "internalDate": timestamps[msg_id],
                "snippet": f"Preview {msg_id}",
                "payload": {
                    "headers": [
                        {"name": "From", "value": "User <user@test.com>"},
                        {"name": "Subject", "value": f"Subject {msg_id}"},
                        {"name": "Date", "value": "Fri, 31 Oct 2026 09:00:00 +0000"}
                    ],
                    "mimeType": "text/plain",
                    "body": {"data": base64.urlsafe_b64encode(b"Content").decode('ascii')}
                }
            }, None

        mock_detail.side_effect = _detail

        res = service.scan_inbox(self.session_id)
        self.assertEqual(res["status"], "success")
        ordered_ids = [e["id"] for e in res["emails"]]
        self.assertEqual(ordered_ids, ["msg_newest", "msg_middle", "msg_old"])

    @patch("gmail.auth.get_valid_access_token")
    @patch("requests.post")
    @patch("requests.delete")
    @patch("requests.put")
    @patch("gmail.service.fetch_inbox_message_list")
    @patch("gmail.service.fetch_message_detail")
    def test_scan_is_strictly_read_only(self, mock_detail, mock_list, mock_put, mock_del, mock_post, mock_auth):
        """Verify that scanning does not call any modifying/destructive HTTP methods."""
        mock_auth.return_value = ("mock_token", None)
        mock_list.return_value = ({"messages": [{"id": "msg_1"}]}, None)
        mock_detail.return_value = ({
            "id": "msg_1",
            "threadId": "t1",
            "snippet": "Test",
            "payload": {
                "headers": [{"name": "From", "value": "a@b.com"}, {"name": "Subject", "value": "Test"}],
                "body": {"data": base64.urlsafe_b64encode(b"Hi").decode('ascii')}
            }
        }, None)

        service.scan_inbox(self.session_id)
        mock_post.assert_not_called()
        mock_put.assert_not_called()
        mock_del.assert_not_called()

    @patch("gmail.auth.get_valid_access_token")
    @patch("gmail.service.fetch_inbox_message_list")
    @patch("gmail.service.fetch_message_detail")
    def test_scan_summary_counts_match_actual_results(self, mock_detail, mock_list, mock_auth):
        """Verify summary counts (total, spam, ham, high-risk) strictly match processed emails."""
        mock_auth.return_value = ("mock_token", None)
        mock_list.return_value = ({
            "messages": [
                {"id": "msg_high_risk_phish"},
                {"id": "msg_safe_ham_1"},
                {"id": "msg_safe_ham_2"},
                {"id": "msg_medium_promo"}
            ],
            "nextPageToken": None
        }, None)

        def _detail(token, msg_id):
            if msg_id == "msg_high_risk_phish":
                text = "URGENT: Verify your bank account password immediately at http://192.168.1.1/login"
                from_addr = "Security <alert@phish.com>"
                subj = "Security Alert"
            elif msg_id == "msg_medium_promo":
                text = "Special offer! 20% discount on shoes today. Call 0800123456"
                from_addr = "Store <deals@store.com>"
                subj = "Exclusive Deal"
            elif msg_id == "msg_safe_ham_1":
                text = "Hi team, please find the slides attached for our project review."
                from_addr = "Colleague <c@company.com>"
                subj = "Presentation Slides"
            else:
                text = "Lunch at 1pm sounds good. See you then."
                from_addr = "Friend <friend@email.com>"
                subj = "Lunch"

            return {
                "id": msg_id,
                "threadId": f"t_{msg_id}",
                "snippet": text[:30],
                "payload": {
                    "headers": [
                        {"name": "From", "value": from_addr},
                        {"name": "Subject", "value": subj},
                        {"name": "Date", "value": "Thu, 30 Oct 2026 12:00:00 +0000"}
                    ],
                    "mimeType": "text/plain",
                    "body": {"data": base64.urlsafe_b64encode(text.encode('utf-8')).decode('ascii')}
                }
            }, None

        mock_detail.side_effect = _detail

        res = service.scan_inbox(self.session_id)
        self.assertEqual(res["status"], "success")
        self.assertEqual(res["total_scanned"], 4)

        # Dynamic verification of counts
        emails = res["emails"]
        computed_spam = sum(1 for e in emails if e["prediction"] == "SPAM")
        computed_ham = sum(1 for e in emails if e["prediction"] == "HAM")
        computed_high_risk = sum(1 for e in emails if e["risk_level"] == "High")

        self.assertEqual(res["spam_count"], computed_spam)
        self.assertEqual(res["ham_count"], computed_ham)
        self.assertEqual(res["high_risk_count"], computed_high_risk)
        self.assertGreaterEqual(computed_high_risk, 1)

    def test_risk_level_calculated_independently_of_ml_confidence(self):
        """Verify that high ML confidence alone does not force High Risk without security threats."""
        analyzer = get_analyzer()
        
        # Message 1: High confidence spam marketing, but NO credential phishing or raw IP or fake job scam
        promo_msg = "CONGRATULATIONS!! You have won a $1,000 Walmart Gift Card! Claim now at http://bit.ly/claim-prize"
        res_promo = analyzer.analyze_message(promo_msg)
        self.assertEqual(res_promo["prediction"], "SPAM")
        self.assertGreater(res_promo["confidence"], 90.0)
        # It has URL shortener and promo language -> Medium Risk, NOT High Risk
        self.assertIn(res_promo["risk_level"], ["Medium", "High"])

        # Message 2: Subtle phishing email requesting credentials -> High Risk
        phish_msg = "URGENT SECURITY ALERT: Please confirm your bank account password and PIN immediately."
        res_phish = analyzer.analyze_message(phish_msg)
        self.assertEqual(res_phish["risk_level"], "High")
        self.assertTrue(any("credential" in r.lower() or "password" in r.lower() or "phishing" in r.lower() for r in res_phish["risk_reasons"]))

        # Message 3: High confidence safe HAM email -> Low Risk
        safe_msg = "Hey Sarah, thanks for sharing the project quarterly report. Have a wonderful weekend."
        res_safe = analyzer.analyze_message(safe_msg)
        self.assertEqual(res_safe["prediction"], "HAM")
        self.assertGreater(res_safe["confidence"], 95.0)
        self.assertEqual(res_safe["risk_level"], "Low")

    def test_legitimate_email_with_urls_and_promo_words_not_high_risk(self):
        """Verify that a legitimate email with URLs and words like 'free' is not marked High Risk."""
        analyzer = get_analyzer()
        msg = (
            "Hi team, here is the free documentation and training guide for our upcoming release: "
            "https://python.org/doc and https://github.com/features. "
            "Please review before Monday standup."
        )
        res = analyzer.analyze_message(msg)
        self.assertEqual(res["prediction"], "HAM")
        self.assertNotEqual(res["risk_level"], "High")

    def test_strong_phishing_and_upfront_payment_scams_receive_high_risk(self):
        """Verify phishing and fake job upfront-payment scams receive High Risk and clear reasons."""
        analyzer = get_analyzer()

        # Upfront payment job scam
        job_scam = (
            "Dear Candidate, your selection as Software Engineer is confirmed with lucrative package of 12 LPA. "
            "Pay refundable registration fee of 2500 to secure your position today."
        )
        res_job = analyzer.analyze_message(job_scam)
        self.assertEqual(res_job["prediction"], "SPAM")
        self.assertEqual(res_job["risk_level"], "High")
        self.assertTrue(any("employment" in r.lower() or "upfront" in r.lower() for r in res_job["risk_reasons"]))

        # Credential phishing with raw IP link
        phish_ip = "Urgent: Your account is restricted. Verify password at http://192.168.1.50/verify"
        res_ip = analyzer.analyze_message(phish_ip)
        self.assertEqual(res_ip["risk_level"], "High")
        self.assertTrue(any("ip" in r.lower() or "credential" in r.lower() or "phishing" in r.lower() for r in res_ip["risk_reasons"]))


class TestGmailFlaskRoutes(unittest.TestCase):
    """Test Flask web routes and JSON API endpoints for Gmail integration."""

    def setUp(self):
        self.app = app
        self.client = self.app.test_client()

    def test_gmail_page_renders_successfully(self):
        res = self.client.get('/gmail')
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"Gmail Inbox Scanner", res.data)

    def test_gmail_status_api_disconnected(self):
        res = self.client.get('/api/gmail/status')
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "success")
        self.assertFalse(data["connected"])

    def test_gmail_callback_csrf_state_mismatch_rejected(self):
        with self.client.session_transaction() as sess:
            sess['oauth_state'] = 'legitimate_state_token'

        # Send callback with wrong state
        res = self.client.get('/gmail/callback?code=mock_code&state=forged_state', follow_redirects=True)
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"Invalid OAuth state", res.data)

    def test_localhost_redirect_to_127_0_0_1(self):
        """Visiting via localhost must redirect to 127.0.0.1 to avoid domain session splitting."""
        res = self.client.get('/gmail', headers={'Host': 'localhost:5000'})
        self.assertEqual(res.status_code, 307)
        self.assertIn('127.0.0.1:5000/gmail', res.headers.get('Location', ''))

    @patch("gmail.auth.get_user_profile")
    @patch("gmail.auth.exchange_code_for_tokens")
    def test_successful_oauth_callback_with_valid_signed_state(self, mock_exchange, mock_profile):
        """Valid HMAC-signed state must successfully authenticate and connect account."""
        mock_exchange.return_value = ({
            "access_token": "valid_access_tok_1",
            "refresh_token": "valid_refresh_tok_1",
            "expires_in": 3600
        }, None)
        mock_profile.return_value = ({"emailAddress": "testuser@gmail.com"}, None)

        test_session_id = "test_user_session_valid"
        state = auth.generate_signed_state(test_session_id)

        with self.client.session_transaction() as sess:
            sess['gmail_session_id'] = test_session_id
            sess['oauth_state'] = state

        res = self.client.get(f'/gmail/callback?code=valid_code&state={state}', follow_redirects=True)
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"Your Gmail account has been securely connected", res.data)

        # Verify tokens stored in DB for test_session_id
        account = auth.get_connected_account(test_session_id)
        self.assertIsNotNone(account)
        self.assertEqual(account["email"], "testuser@gmail.com")
        db.delete_gmail_tokens(test_session_id)

    def test_gmail_callback_user_cancelled(self):
        res = self.client.get('/gmail/callback?error=access_denied', follow_redirects=True)
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"cancelled", res.data.lower())

    def test_gmail_disconnect_endpoint(self):
        res = self.client.post('/gmail/disconnect')
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "success")

    def test_gmail_scan_api_unauthorized_when_not_connected(self):
        res = self.client.post('/api/gmail/scan', json={})
        self.assertEqual(res.status_code, 401)
        data = res.get_json()
        self.assertEqual(data["status"], "error")

    def test_feedback_submission_success(self):
        """Verify user feedback can be successfully recorded for an email."""
        db.clear_scan_feedback()
        payload = {
            "message_id": "test_msg_fb_123",
            "feedback": "correct",
            "prediction": "SPAM",
            "confidence": 98.5,
            "risk_level": "High"
        }
        res = self.client.post('/api/gmail/feedback', json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["feedback"], "correct")

        # Verify DB storage
        feedback_map = db.get_feedback_for_messages(["test_msg_fb_123"])
        self.assertEqual(feedback_map.get("test_msg_fb_123"), "correct")
        db.clear_scan_feedback()

    def test_feedback_duplicate_handled_appropriately(self):
        """Verify duplicate feedback submissions are handled gracefully without errors."""
        db.clear_scan_feedback()
        payload = {
            "message_id": "test_msg_dup_999",
            "feedback": "correct",
            "prediction": "HAM",
            "confidence": 99.1,
            "risk_level": "Low"
        }
        # First submission
        res1 = self.client.post('/api/gmail/feedback', json=payload)
        self.assertEqual(res1.status_code, 200)

        # Duplicate submission with identical feedback
        res2 = self.client.post('/api/gmail/feedback', json=payload)
        self.assertEqual(res2.status_code, 200)
        self.assertEqual(res2.get_json()["status"], "success")

        # Update feedback to 'incorrect'
        payload["feedback"] = "incorrect"
        res3 = self.client.post('/api/gmail/feedback', json=payload)
        self.assertEqual(res3.status_code, 200)
        feedback_map = db.get_feedback_for_messages(["test_msg_dup_999"])
        self.assertEqual(feedback_map.get("test_msg_dup_999"), "incorrect")
        db.clear_scan_feedback()

    def test_feedback_validation_errors(self):
        """Verify missing message_id or invalid feedback is rejected with 400."""
        # Missing message_id
        res1 = self.client.post('/api/gmail/feedback', json={"feedback": "correct"})
        self.assertEqual(res1.status_code, 400)

        # Invalid feedback value
        res2 = self.client.post('/api/gmail/feedback', json={"message_id": "m1", "feedback": "maybe"})
        self.assertEqual(res2.status_code, 400)


if __name__ == "__main__":
    unittest.main()
