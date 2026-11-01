"""
Google OAuth 2.0 Authentication & Secure Token Management for Gmail Integration.

Provides:
- OAuth authorization URL generation with CSRF state protection.
- Authorization code exchange for OAuth tokens.
- Automatic access token refresh using refresh tokens.
- Authenticated symmetric token encryption at rest.
- Session-associated token lifecycle management and secure disconnection.
"""
import base64
import hashlib
import hmac
import logging
import os
import secrets
import time
from urllib.parse import urlencode
import requests

import config
from database import db

logger = logging.getLogger(__name__)

# Google OAuth 2.0 Endpoints
GOOGLE_AUTH_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"
GMAIL_PROFILE_ENDPOINT = "https://gmail.googleapis.com/gmail/v1/users/me/profile"


# ----------------------------------------------------------------------
# Token Encryption at Rest (HMAC-SHA256 Authenticated Encryption)
# ----------------------------------------------------------------------
def _get_keystream(key: bytes, iv: bytes, length: int) -> bytes:
    """Derive deterministic keystream from key and IV using HMAC-SHA256."""
    stream = bytearray()
    counter = 0
    while len(stream) < length:
        h = hmac.new(key, iv + counter.to_bytes(4, 'big'), hashlib.sha256)
        stream.extend(h.digest())
        counter += 1
    return bytes(stream[:length])


def encrypt_token(plaintext: str, secret_key: str = None) -> str:
    """
    Encrypt a plaintext token using Encrypt-then-MAC (HMAC-SHA256 authenticated encryption).
    Returns a URL-safe Base64 encoded string: IV (16B) + MAC (32B) + Ciphertext.
    """
    if not plaintext:
        return ""
    secret = secret_key or config.FLASK_SECRET_KEY
    key = hashlib.sha256(secret.encode('utf-8')).digest()
    iv = secrets.token_bytes(16)
    data = plaintext.encode('utf-8')
    keystream = _get_keystream(key, iv, len(data))
    ciphertext = bytes(a ^ b for a, b in zip(data, keystream))
    mac = hmac.new(key, iv + ciphertext, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(iv + mac + ciphertext).decode('ascii')


def decrypt_token(token_b64: str, secret_key: str = None) -> str:
    """
    Decrypt and verify an encrypted token.
    Returns the original plaintext or empty string if tampered or invalid.
    """
    if not token_b64:
        return ""
    try:
        payload = base64.urlsafe_b64decode(token_b64.encode('ascii'))
        if len(payload) < 48:
            return ""
        iv = payload[:16]
        mac = payload[16:48]
        ciphertext = payload[48:]
        secret = secret_key or config.FLASK_SECRET_KEY
        key = hashlib.sha256(secret.encode('utf-8')).digest()
        expected_mac = hmac.new(key, iv + ciphertext, hashlib.sha256).digest()
        if not hmac.compare_digest(mac, expected_mac):
            logger.warning("Decryption failed: Token MAC mismatch (possible tampering or key change).")
            return ""
        keystream = _get_keystream(key, iv, len(ciphertext))
        decrypted = bytes(a ^ b for a, b in zip(ciphertext, keystream))
        return decrypted.decode('utf-8', errors='replace')
    except Exception as e:
        logger.warning(f"Error decrypting token: {e}")
        return ""


# ----------------------------------------------------------------------
# OAuth 2.0 Authorization Flow & Signed CSRF State Tokens
# ----------------------------------------------------------------------
_CONSUMED_NONCES = set()

def is_configured() -> bool:
    """Check whether Google Cloud credentials are configured and valid."""
    config.reload_config()
    id_valid, _, _ = config.validate_client_id(config.GOOGLE_CLIENT_ID or os.environ.get("GOOGLE_CLIENT_ID", ""))
    secret_valid, _, _ = config.validate_client_secret(config.GOOGLE_CLIENT_SECRET or os.environ.get("GOOGLE_CLIENT_SECRET", ""))
    return id_valid and secret_valid


def generate_signed_state(session_id: str = None, secret_key: str = None) -> str:
    """
    Generate a cryptographically signed, tamper-proof state token for CSRF protection.
    Format: <nonce>:<timestamp>:<session_id>:<hmac_signature>
    """
    secret = secret_key or config.FLASK_SECRET_KEY
    nonce = secrets.token_urlsafe(16)
    timestamp = str(int(time.time()))
    sid = session_id or ""
    payload = f"{nonce}:{timestamp}:{sid}"
    sig = hmac.new(secret.encode('utf-8'), payload.encode('utf-8'), hashlib.sha256).hexdigest()[:32]
    return f"{payload}:{sig}"


def validate_signed_state(returned_state: str, saved_state: str = None, secret_key: str = None, max_age: int = 600) -> tuple[bool, str, str]:
    """
    Validate returned OAuth state parameter against CSRF, forgery, expiration, and replay:
    1. Check presence and format.
    2. Verify HMAC-SHA256 signature using FLASK_SECRET_KEY.
    3. Check expiration (default 10 minutes / 600s).
    4. Anti-replay verification (consumed nonces rejected).
    5. Session comparison if saved_state is present.
    Returns (is_valid, session_id, reason).
    """
    if not returned_state or not isinstance(returned_state, str):
        return False, "", "State parameter is missing or empty"

    parts = returned_state.split(':')
    if len(parts) != 4:
        # Fallback to direct string comparison if simple state was used
        if saved_state and hmac.compare_digest(returned_state, saved_state):
            return True, "", "Legacy session state verified"
        return False, "", "State token format invalid"

    nonce, ts_str, session_id, sig = parts
    secret = secret_key or config.FLASK_SECRET_KEY
    payload = f"{nonce}:{ts_str}:{session_id}"
    expected_sig = hmac.new(secret.encode('utf-8'), payload.encode('utf-8'), hashlib.sha256).hexdigest()[:32]

    # Constant-time comparison to prevent timing attacks
    if not hmac.compare_digest(sig, expected_sig):
        return False, "", "State HMAC signature mismatch (forged or tampered state)"

    try:
        ts = int(ts_str)
        age = time.time() - ts
        if age > max_age:
            return False, "", f"State token expired ({int(age)}s old, maximum allowed is {max_age}s)"
        if age < -60:
            return False, "", "State timestamp is in the future"
    except ValueError:
        return False, "", "State contains invalid timestamp"

    # Anti-replay protection
    global _CONSUMED_NONCES
    if nonce in _CONSUMED_NONCES:
        return False, "", "State token has already been consumed (replay attack rejected)"
    _CONSUMED_NONCES.add(nonce)
    if len(_CONSUMED_NONCES) > 10000:
        _CONSUMED_NONCES.clear()

    # Session token comparison if session cookie survived the redirect
    if saved_state and ":" in saved_state:
        if not hmac.compare_digest(returned_state, saved_state):
            return False, "", "Returned state does not match session state token"

    return True, session_id, "State verified successfully"


def get_authorization_url(state: str) -> str:
    """
    Build Google OAuth 2.0 consent URL requesting read-only Gmail scope.
    Includes state parameter to protect against CSRF attacks.
    """
    params = {
        "client_id": config.GOOGLE_CLIENT_ID,
        "redirect_uri": config.GOOGLE_REDIRECT_URI,
        "response_type": "code",
        "scope": config.GMAIL_READONLY_SCOPE,
        "access_type": "offline",      # Ensures a refresh token is returned
        "prompt": "consent",           # Forces consent screen to re-issue refresh token
        "state": state
    }
    return f"{GOOGLE_AUTH_ENDPOINT}?{urlencode(params)}"


def exchange_code_for_tokens(code: str) -> tuple[dict | None, str | None]:
    """
    Exchange authorization code for access and refresh tokens.
    Returns (tokens_dict, None) on success or (None, error_message) on failure.
    """
    if not is_configured():
        return None, "Google Cloud OAuth credentials not configured. Please set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET."

    payload = {
        "code": code,
        "client_id": config.GOOGLE_CLIENT_ID,
        "client_secret": config.GOOGLE_CLIENT_SECRET,
        "redirect_uri": config.GOOGLE_REDIRECT_URI,
        "grant_type": "authorization_code"
    }

    try:
        response = requests.post(GOOGLE_TOKEN_ENDPOINT, data=payload, timeout=10)
        data = response.json()
        if response.status_code != 200:
            error_desc = data.get("error_description", data.get("error", "Failed to exchange authorization code."))
            return None, f"Token exchange failed: {error_desc}"

        return data, None
    except requests.RequestException as e:
        logger.error(f"Network error during code exchange: {e}")
        return None, "Network error communicating with Google authentication servers."


def refresh_access_token(refresh_token: str) -> tuple[dict | None, str | None]:
    """
    Use refresh token to obtain a fresh access token.
    Returns (data_dict, None) on success or (None, error_message) on failure.
    """
    if not refresh_token:
        return None, "No refresh token available."

    payload = {
        "client_id": config.GOOGLE_CLIENT_ID,
        "client_secret": config.GOOGLE_CLIENT_SECRET,
        "refresh_token": refresh_token,
        "grant_type": "refresh_token"
    }

    try:
        response = requests.post(GOOGLE_TOKEN_ENDPOINT, data=payload, timeout=10)
        data = response.json()
        if response.status_code != 200:
            error_desc = data.get("error_description", data.get("error", "Token refresh rejected."))
            return None, f"Refresh failed: {error_desc}"

        return data, None
    except requests.RequestException as e:
        logger.error(f"Network error refreshing access token: {e}")
        return None, "Network error communicating with Google authentication servers."


def get_user_profile(access_token: str) -> tuple[dict | None, str | None]:
    """
    Fetch connected user's Gmail profile metadata (emailAddress, totalMessages).
    Returns (profile_dict, None) on success or (None, error_message) on failure.
    """
    if not access_token:
        return None, "Access token required."

    headers = {"Authorization": f"Bearer {access_token}"}
    try:
        response = requests.get(GMAIL_PROFILE_ENDPOINT, headers=headers, timeout=10)
        if response.status_code != 200:
            return None, f"Failed to retrieve profile: HTTP {response.status_code}"
        return response.json(), None
    except requests.RequestException as e:
        logger.error(f"Network error retrieving Gmail profile: {e}")
        return None, "Network error retrieving Gmail profile."


# ----------------------------------------------------------------------
# Session-Associated Connection Lifecycle Management
# ----------------------------------------------------------------------
def save_connection(session_id: str, email: str, access_token: str, refresh_token: str, expires_in: int):
    """
    Encrypt tokens and persist connection credentials tied to user session ID.
    Never logs or exposes plaintext tokens.
    """
    access_token_enc = encrypt_token(access_token)
    refresh_token_enc = encrypt_token(refresh_token) if refresh_token else ""
    expires_at = time.time() + max(expires_in, 60)
    db.save_gmail_tokens(session_id, email, access_token_enc, refresh_token_enc, expires_at)


def get_connected_account(session_id: str) -> dict | None:
    """
    Return connection status metadata for the current session (email, expires_at).
    Does NOT return token contents.
    """
    if not session_id:
        return None
    record = db.get_gmail_tokens(session_id)
    if not record:
        return None
    return {
        "email": record["email"],
        "expires_at": record["expires_at"],
        "connected_at": record["created_at"],
        "updated_at": record["updated_at"]
    }


def get_valid_access_token(session_id: str) -> tuple[str | None, str | None]:
    """
    Retrieve and decrypt access token for session.
    Automatically refreshes access token if expired or expiring within 60 seconds.
    Returns (access_token, None) or (None, error_reason).
    """
    if not session_id:
        return None, "User session not found."

    record = db.get_gmail_tokens(session_id)
    if not record:
        return None, "No Gmail account connected."

    access_token = decrypt_token(record["access_token_enc"])
    refresh_token = decrypt_token(record["refresh_token_enc"]) if record["refresh_token_enc"] else ""
    expires_at = record["expires_at"]

    # If access token is still valid for > 60 seconds, return it
    if access_token and time.time() < (expires_at - 60):
        return access_token, None

    # Token expired or about to expire: attempt automatic refresh
    if refresh_token:
        logger.info(f"Access token expiring for session {session_id[:8]}... Refreshing token.")
        data, err = refresh_access_token(refresh_token)
        if data and "access_token" in data:
            new_access_token = data["access_token"]
            new_expires_in = data.get("expires_in", 3600)
            new_refresh_token = data.get("refresh_token", refresh_token)
            save_connection(session_id, record["email"], new_access_token, new_refresh_token, new_expires_in)
            return new_access_token, None
        else:
            # Refresh token was revoked or expired; clean up
            logger.warning(f"Refresh failed for session {session_id[:8]}: {err}. Clearing connection.")
            db.delete_gmail_tokens(session_id)
            return None, "Gmail authorization has expired or was revoked. Please reconnect your account."
    else:
        # Expired and no refresh token available
        db.delete_gmail_tokens(session_id)
        return None, "Gmail access token expired and no refresh token was found. Please reconnect."


def disconnect_account(session_id: str):
    """
    Remove stored OAuth tokens and disconnect Gmail for the current session.
    """
    if session_id:
        db.delete_gmail_tokens(session_id)
