import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

EXCLUDED_PLACEHOLDERS_ID = {
    "your-google-client-id.apps.googleusercontent.com",
    "your-google-client-id",
    "<my actual google client id>",
    "<your-client-id>",
    "your-client-id.apps.googleusercontent.com",
    "your_client_id_here"
}

EXCLUDED_PLACEHOLDERS_SECRET = {
    "your-google-client-secret",
    "<my actual google client secret>",
    "<your-client-secret>",
    "your-client-secret",
    "your_client_secret_here"
}

def validate_client_id(val: str) -> tuple[bool, str, str]:
    """
    Validate and sanitize Google OAuth Client ID.
    Handles surrounding quotes, whitespace, trailing slashes, and URL prefixes.
    Returns (is_valid, sanitized_val, reason). Never reveals secret values.
    """
    if not val:
        return False, "", "Empty or missing"

    cleaned = val.strip()
    # Strip any enclosing quotes (single, double, or backticks)
    if (cleaned.startswith('"') and cleaned.endswith('"')) or (cleaned.startswith("'") and cleaned.endswith("'")):
        cleaned = cleaned[1:-1].strip()

    # Strip accidental URL prefix or protocol
    if cleaned.lower().startswith("https://"):
        cleaned = cleaned[8:]
    elif cleaned.lower().startswith("http://"):
        cleaned = cleaned[7:]

    # Strip trailing slash
    cleaned = cleaned.rstrip('/')

    if not cleaned:
        return False, "", "Empty after removing quotes/whitespace"

    if cleaned.lower() in EXCLUDED_PLACEHOLDERS_ID or (cleaned.startswith("<") and cleaned.endswith(">")):
        return False, cleaned, "Matches template placeholder (e.g. your-google-client-id)"

    return True, cleaned, "Valid format"

def validate_client_secret(val: str) -> tuple[bool, str, str]:
    """
    Validate and sanitize Google OAuth Client Secret.
    Handles surrounding quotes, whitespace, and template placeholders.
    Returns (is_valid, sanitized_val, reason). Never reveals secret values.
    """
    if not val:
        return False, "", "Empty or missing"

    cleaned = val.strip()
    if (cleaned.startswith('"') and cleaned.endswith('"')) or (cleaned.startswith("'") and cleaned.endswith("'")):
        cleaned = cleaned[1:-1].strip()

    cleaned = cleaned.rstrip('/')

    if not cleaned:
        return False, "", "Empty after removing quotes/whitespace"

    if cleaned.lower() in EXCLUDED_PLACEHOLDERS_SECRET or (cleaned.startswith("<") and cleaned.endswith(">")):
        return False, cleaned, "Matches template placeholder (e.g. your-google-client-secret)"

    return True, cleaned, "Valid format"

def _load_env_file():
    """Load key-value pairs from .env if present into os.environ with quote and comment sanitization."""
    env_path = os.path.join(BASE_DIR, ".env")
    if os.path.exists(env_path):
        try:
            from dotenv import load_dotenv
            load_dotenv(env_path, override=True)
            return
        except ImportError:
            pass

        try:
            with open(env_path, "r", encoding="utf-8-sig") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        k, v = line.split("=", 1)
                        k = k.strip()
                        v = v.strip()
                        if not ((v.startswith('"') and v.endswith('"')) or (v.startswith("'") and v.endswith("'"))):
                            if "#" in v:
                                v = v.split("#", 1)[0].strip()
                        if (v.startswith('"') and v.endswith('"')) or (v.startswith("'") and v.endswith("'")):
                            v = v[1:-1].strip()
                        if k:
                            os.environ[k] = v
        except Exception:
            pass

_load_env_file()

def reload_config():
    """Re-load .env and synchronize module-level configuration variables with sanitization."""
    _load_env_file()
    global FLASK_SECRET_KEY, GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_REDIRECT_URI, GMAIL_SCAN_BATCH_SIZE
    FLASK_SECRET_KEY = os.environ.get("FLASK_SECRET_KEY", "mailvision-secret-key-2026").strip().strip("'\"")

    raw_id = os.environ.get("GOOGLE_CLIENT_ID", "")
    _, clean_id, _ = validate_client_id(raw_id)
    GOOGLE_CLIENT_ID = clean_id

    raw_secret = os.environ.get("GOOGLE_CLIENT_SECRET", "")
    _, clean_secret, _ = validate_client_secret(raw_secret)
    GOOGLE_CLIENT_SECRET = clean_secret

    GOOGLE_REDIRECT_URI = os.environ.get("GOOGLE_REDIRECT_URI", "http://127.0.0.1:5000/gmail/callback").strip().strip("'\"")
    try:
        GMAIL_SCAN_BATCH_SIZE = int(os.environ.get("GMAIL_SCAN_BATCH_SIZE", "5"))
    except ValueError:
        GMAIL_SCAN_BATCH_SIZE = 5

def log_diagnostic_status(logger=None):
    """Safely log whether each OAuth environment variable is configured (True/False) with specific validation reasons. Never prints secrets."""
    reload_config()
    env_exists = os.path.exists(os.path.join(BASE_DIR, ".env"))

    raw_id = os.environ.get("GOOGLE_CLIENT_ID", "")
    id_valid, _, id_reason = validate_client_id(raw_id)

    raw_secret = os.environ.get("GOOGLE_CLIENT_SECRET", "")
    secret_valid, _, secret_reason = validate_client_secret(raw_secret)

    secret_key_set = bool(FLASK_SECRET_KEY and FLASK_SECRET_KEY != "mailvision-secret-key-change-in-production-2026")
    ready = id_valid and secret_valid

    diagnostic_msg = (
        "\n=======================================================\n"
        " [MailVision Configuration Diagnostics]\n"
        f"  - .env file detected: {env_exists}\n"
        f"  - FLASK_SECRET_KEY configured: {secret_key_set}\n"
        f"  - GOOGLE_CLIENT_ID configured: {id_valid} (present: {bool(raw_id.strip())}) -> {id_reason}\n"
        f"  - GOOGLE_CLIENT_SECRET configured: {secret_valid} (present: {bool(raw_secret.strip())}) -> {secret_reason}\n"
        f"  - GOOGLE_REDIRECT_URI: {GOOGLE_REDIRECT_URI}\n"
        f"  - Gmail OAuth Status: {'READY' if ready else 'SETUP REQUIRED'}\n"
        "======================================================="
    )
    print(diagnostic_msg)
    if logger:
        logger.info(diagnostic_msg)

DATA_DIR = os.path.join(BASE_DIR, "data")
DATASET_PATH = os.path.join(DATA_DIR, "SMSSpamCollection")
DATASET_URL = "https://archive.ics.uci.edu/static/public/228/sms+spam+collection.zip"

MODEL_DIR = os.path.join(BASE_DIR, "model")
MODEL_PATH = os.path.join(MODEL_DIR, "spam_model.pkl")
VECTORIZER_PATH = os.path.join(MODEL_DIR, "tfidf_vectorizer.pkl")
METRICS_PATH = os.path.join(MODEL_DIR, "metrics.json")

DATABASE_DIR = os.path.join(BASE_DIR, "database")
DATABASE_PATH = os.path.join(DATABASE_DIR, "predictions.db")

MAX_INPUT_LENGTH = 10000

# Google OAuth 2.0 & Gmail API Settings
FLASK_SECRET_KEY = os.environ.get("FLASK_SECRET_KEY", "mailvision-secret-key-2026")
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", "")
GOOGLE_REDIRECT_URI = os.environ.get("GOOGLE_REDIRECT_URI", "http://127.0.0.1:5000/gmail/callback")
GMAIL_READONLY_SCOPE = "https://www.googleapis.com/auth/gmail.readonly"
GMAIL_SCAN_BATCH_SIZE = int(os.environ.get("GMAIL_SCAN_BATCH_SIZE", "5"))
