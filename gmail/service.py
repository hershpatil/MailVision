"""
Gmail Service Layer for On-Demand Inbox Scanning & Classification.

Provides:
- Inbox email list retrieval using official Gmail REST API.
- Individual message detail fetching with full MIME structure.
- Integration with MailVision MessageAnalyzer for spam classification.
- Robust error handling for rate limits, expired tokens, and network failures.
"""
import logging
import requests

import config
from detection.analyzer import get_analyzer
from database import db
from gmail import auth
from gmail import email_parser

logger = logging.getLogger(__name__)

GMAIL_MESSAGES_ENDPOINT = "https://gmail.googleapis.com/gmail/v1/users/me/messages"


def fetch_inbox_message_list(access_token: str, max_results: int = 5, page_token: str = None) -> tuple[dict | None, str | None]:
    """
    Query the Gmail API for messages strictly in the user's INBOX.
    Returns (data_dict, None) or (None, error_message).
    """
    if not access_token:
        return None, "Access token required."

    headers = {"Authorization": f"Bearer {access_token}"}
    params = {
        "q": "in:inbox",
        "labelIds": "INBOX",
        "maxResults": min(max(1, max_results), 50),
    }
    if page_token:
        params["pageToken"] = page_token

    try:
        response = requests.get(GMAIL_MESSAGES_ENDPOINT, headers=headers, params=params, timeout=15)
        if response.status_code == 401:
            return None, "UNAUTHORIZED"
        elif response.status_code == 429 or response.status_code == 403:
            return None, "Gmail API rate limit exceeded or quota reached. Please try again in a few moments."
        elif response.status_code != 200:
            return None, f"Gmail API returned error status {response.status_code}."

        return response.json(), None
    except requests.Timeout:
        return None, "Request timed out while connecting to Gmail API."
    except requests.RequestException as e:
        logger.error(f"Network error querying Gmail inbox: {e}")
        return None, "Network error communicating with Gmail API."


def fetch_message_detail(access_token: str, message_id: str) -> tuple[dict | None, str | None]:
    """
    Fetch full RFC 2822 payload for a single message by ID.
    Returns (message_dict, None) or (None, error_message).
    """
    if not access_token or not message_id:
        return None, "Access token and message ID required."

    headers = {"Authorization": f"Bearer {access_token}"}
    url = f"{GMAIL_MESSAGES_ENDPOINT}/{message_id}"
    params = {"format": "full"}

    try:
        response = requests.get(url, headers=headers, params=params, timeout=12)
        if response.status_code == 401:
            return None, "UNAUTHORIZED"
        elif response.status_code != 200:
            return None, f"Failed to retrieve message {message_id}: HTTP {response.status_code}"

        return response.json(), None
    except requests.RequestException as e:
        logger.warning(f"Error fetching message {message_id}: {e}")
        return None, f"Network error fetching message {message_id}."


def scan_inbox(session_id: str, max_results: int = None, page_token: str = None) -> dict:
    """
    Perform on-demand scan of the latest inbox messages for the connected Gmail account.
    1. Authenticates session and validates/refreshes token.
    2. Fetches message list.
    3. Fetches details for each email.
    4. Extracts clean text and runs MailVision spam analyzer.
    5. Returns structured results with spam/ham counts and risk indicators.
    """
    try:
        limit = int(max_results) if max_results is not None else config.GMAIL_SCAN_BATCH_SIZE
    except (ValueError, TypeError):
        limit = config.GMAIL_SCAN_BATCH_SIZE

    # 1. Obtain valid access token (refreshes if needed)
    access_token, err = auth.get_valid_access_token(session_id)
    if err or not access_token:
        return {
            "status": "error",
            "error_type": "auth_error",
            "message": err or "Gmail account not connected. Please connect your Gmail account."
        }

    # 2. Fetch message list from inbox
    list_data, list_err = fetch_inbox_message_list(access_token, max_results=limit, page_token=page_token)
    if list_err == "UNAUTHORIZED":
        # Force refresh and retry once
        logger.info("Access token expired during inbox scan; attempting refresh...")
        record = auth.get_connected_account(session_id)
        if record:
            access_token, retry_err = auth.get_valid_access_token(session_id)
            if not retry_err and access_token:
                list_data, list_err = fetch_inbox_message_list(access_token, max_results=limit, page_token=page_token)

    if list_err:
        return {
            "status": "error",
            "error_type": "api_error",
            "message": list_err
        }

    message_items = list_data.get("messages", [])
    next_page_token = list_data.get("nextPageToken")

    if not message_items:
        return {
            "status": "success",
            "emails": [],
            "total_scanned": 0,
            "spam_count": 0,
            "ham_count": 0,
            "high_risk_count": 0,
            "next_page_token": None,
            "message": "Inbox is empty or no messages match the query."
        }

    # 3. Retrieve and analyze each email
    analyzer = get_analyzer()
    scanned_emails = []
    spam_count = 0
    ham_count = 0

    for item in message_items:
        msg_id = item.get("id")
        if not msg_id:
            continue

        raw_msg, fetch_err = fetch_message_detail(access_token, msg_id)
        if fetch_err or not raw_msg:
            logger.warning(f"Skipping unretrievable message {msg_id}: {fetch_err}")
            continue

        # Parse message structure
        parsed = email_parser.parse_gmail_message(raw_msg)

        # Prepare text for analysis: combine Subject and Body
        subject_text = parsed["subject"] if parsed["subject"] != "(No Subject)" else ""
        analysis_input = f"{subject_text}\n\n{parsed['body_text']}".strip()

        # If analysis text is completely empty, classify as HAM safely
        if not analysis_input:
            classification = {
                "prediction": "HAM",
                "confidence": 99.0,
                "spam_probability": 1.0,
                "ham_probability": 99.0,
                "risk_level": "Low",
                "risk_reasons": ["Email body is empty or contains no detectable threat indicators."],
                "indicators": [],
                "statistics": {
                    "word_count": 0,
                    "character_count": 0,
                    "url_count": 0,
                    "keyword_count": 0
                }
            }
        else:
            try:
                res = analyzer.analyze_message(analysis_input)
                if res.get("status") == "success":
                    classification = {
                        "prediction": res.get("prediction", "HAM"),
                        "confidence": res.get("confidence", 50.0),
                        "spam_probability": res.get("spam_probability", 0.0),
                        "ham_probability": res.get("ham_probability", 100.0),
                        "risk_level": res.get("risk_level", "Low"),
                        "risk_reasons": res.get("risk_reasons", []),
                        "indicators": res.get("indicators", []),
                        "statistics": res.get("statistics", {})
                    }
                else:
                    classification = {
                        "prediction": "HAM",
                        "confidence": 50.0,
                        "spam_probability": 0.0,
                        "ham_probability": 100.0,
                        "risk_level": "Low",
                        "risk_reasons": ["Analysis unavailable for this message format."],
                        "indicators": [],
                        "statistics": {}
                    }
            except Exception as e:
                logger.error(f"Error analyzing email {msg_id}: {e}")
                classification = {
                    "prediction": "HAM",
                    "confidence": 50.0,
                    "spam_probability": 0.0,
                    "ham_probability": 100.0,
                    "risk_level": "Low",
                    "risk_reasons": ["Internal error evaluating security heuristics."],
                    "indicators": [],
                    "statistics": {}
                }

        is_spam = classification["prediction"] == "SPAM"
        if is_spam:
            spam_count += 1
        else:
            ham_count += 1

        email_entry = {
            "id": parsed["id"],
            "thread_id": parsed["thread_id"],
            "sender": parsed["sender"],
            "subject": parsed["subject"],
            "date": parsed["date"],
            "snippet": parsed["snippet"],
            "has_attachments": parsed["has_attachments"],
            "prediction": classification["prediction"],
            "confidence": classification["confidence"],
            "spam_probability": classification["spam_probability"],
            "ham_probability": classification["ham_probability"],
            "risk_level": classification.get("risk_level", "Low"),
            "risk_reasons": classification.get("risk_reasons", []),
            "indicators": classification["indicators"],
            "statistics": classification["statistics"],
            "timestamp": parsed.get("timestamp", 0.0)
        }
        scanned_emails.append(email_entry)

    # Ensure processed emails are ordered newest first
    scanned_emails.sort(key=lambda e: e.get("timestamp", 0.0), reverse=True)

    # Attach any previously submitted user feedback
    existing_feedback = db.get_feedback_for_messages([e["id"] for e in scanned_emails], session_id)
    for email_entry in scanned_emails:
        email_entry["user_feedback"] = existing_feedback.get(email_entry["id"])

    high_risk_count = sum(1 for e in scanned_emails if e.get("risk_level") == "High")

    return {
        "status": "success",
        "emails": scanned_emails,
        "total_scanned": len(scanned_emails),
        "spam_count": spam_count,
        "ham_count": ham_count,
        "high_risk_count": high_risk_count,
        "next_page_token": next_page_token
    }
