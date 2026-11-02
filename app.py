import os
import secrets
from datetime import timedelta
from urllib.parse import parse_qs, urlencode, unquote
from flask import Flask, render_template, request, jsonify, redirect, url_for, session

import config
from detection.analyzer import get_analyzer
from database import db
from gmail import auth as gmail_auth
from gmail import service as gmail_service

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, 'templates'),
    static_folder=os.path.join(BASE_DIR, 'static'),
    static_url_path='/static'
)

class VercelPathMiddleware:
    """
    WSGI Middleware for Vercel Serverless Functions:
    Restores the client's original URL path from Vercel's rewrite query parameter
    (?path=$1) or headers into WSGI environ['PATH_INFO'].
    Preserves HTTP method, headers, request body stream (wsgi.input), and original query parameters.
    """
    def __init__(self, wsgi_app):
        self.wsgi_app = wsgi_app

    def __call__(self, environ, start_response):
        query_string = environ.get('QUERY_STRING', '')
        if 'path=' in query_string:
            params = parse_qs(query_string, keep_blank_values=True)
            if 'path' in params:
                raw_path = params['path'][0] if params['path'] else ''
                # Unquote URL-encoded path characters (e.g. %2F -> /)
                raw_path = unquote(raw_path)
                if not raw_path.startswith('/'):
                    raw_path = '/' + raw_path
                environ['PATH_INFO'] = raw_path
                # Clean 'path' parameter from QUERY_STRING so it doesn't pollute application request.args
                remaining = {k: v for k, v in params.items() if k != 'path'}
                environ['QUERY_STRING'] = urlencode(remaining, doseq=True)
        elif environ.get('PATH_INFO') in ('/api/index', '/api/index.py', '/api', '/api/'):
            matched_path = environ.get('HTTP_X_MATCHED_PATH')
            if matched_path and matched_path not in ('/api/index.py', '/api/index', '/api', '/api/'):
                environ['PATH_INFO'] = matched_path
            else:
                environ['PATH_INFO'] = '/'

        return self.wsgi_app(environ, start_response)

app.wsgi_app = VercelPathMiddleware(app.wsgi_app)
app.config['SECRET_KEY'] = config.FLASK_SECRET_KEY
app.config['SESSION_COOKIE_NAME'] = 'mailvision_session'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
# Secure cookies over HTTPS in production/Vercel; Allow HTTP on local development
app.config['SESSION_COOKIE_SECURE'] = bool(config.IS_VERCEL or os.environ.get('SESSION_COOKIE_SECURE', '').lower() == 'true')
app.config['SESSION_COOKIE_PATH'] = '/'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)

# Ensure database is initialized on startup and log diagnostics safely
with app.app_context():
    db.init_db()
    config.log_diagnostic_status(app.logger)

@app.before_request
def normalize_host_and_session():
    """
    1. Ensure consistent 127.0.0.1 host across all requests.
       Redirects localhost:5000 -> 127.0.0.1:5000 so session cookies are never lost.
    2. Ensure every visiting client has a persistent secure session identifier.
    """
    # Safe diagnostic logging (request path and method metadata only; never logs secrets, tokens, or email contents)
    app.logger.info("Request received: method=%s, path=%s, environ_path=%s",
                    request.method, request.path, request.environ.get('PATH_INFO'))
    # Normalize localhost -> 127.0.0.1 so cookies and Google OAuth redirect URI match
    if request.host == 'localhost:5000' or (request.host.startswith('localhost') and 'SERVER_SOFTWARE' in request.environ):
        new_url = request.url.replace('://localhost', '://127.0.0.1', 1)
        return redirect(new_url, code=307)

    if 'gmail_session_id' not in session:
        session['gmail_session_id'] = secrets.token_hex(16)
    session.permanent = True

@app.route('/')
def home():
    """Render home / main analyzer interface."""
    return render_template('index.html')

@app.route('/api/index', methods=['GET', 'POST'])
@app.route('/api/index.py', methods=['GET', 'POST'])
def vercel_entrypoint_fallback():
    """Fallback in case internal Vercel serverless function path reaches Flask router directly."""
    matched_path = request.headers.get('x-matched-path', '').strip()
    if matched_path and matched_path not in ('/api/index', '/api/index.py', '/'):
        return redirect(matched_path)
    return render_template('index.html')

@app.route('/api/predict', methods=['POST'])
def predict_api():
    """API Endpoint to analyze input message."""
    try:
        data = request.get_json(silent=True)
        if not data or 'message' not in data:
            # Fallback to form data
            message_text = request.form.get('message', '')
        else:
            message_text = data.get('message', '')

        if not message_text or not isinstance(message_text, str) or not message_text.strip():
            return jsonify({
                "status": "error",
                "message": "Input message cannot be empty or whitespace only."
            }), 400

        if len(message_text) > config.MAX_INPUT_LENGTH:
            return jsonify({
                "status": "error",
                "message": f"Input message exceeds maximum allowed limit of {config.MAX_INPUT_LENGTH} characters."
            }), 400

        # Perform analysis
        analyzer = get_analyzer()
        result = analyzer.analyze_message(message_text)

        if result.get("status") == "error":
            return jsonify(result), 400

        # Log prediction to database (without saving message text for privacy)
        db.log_prediction(
            prediction=result["prediction"],
            confidence=result["confidence"],
            spam_prob=result["spam_probability"],
            ham_prob=result["ham_probability"],
            word_count=result["statistics"]["word_count"],
            url_count=result["statistics"]["url_count"]
        )

        return jsonify(result), 200

    except Exception as e:
        # Log internally, return friendly JSON error to client
        app.logger.error(f"Error processing prediction request: {e}")
        return jsonify({
            "status": "error",
            "message": "An internal server error occurred while processing your request."
        }), 500

@app.route('/history')
def history_page():
    """Render prediction history table page."""
    return render_template('history.html')

@app.route('/api/history', methods=['GET'])
def history_api():
    """API Endpoint to fetch history records."""
    try:
        history = db.get_history(limit=100)
        return jsonify({
            "status": "success",
            "history": history
        }), 200
    except Exception as e:
        return jsonify({"status": "error", "message": "Failed to fetch history."}), 500

@app.route('/api/history/clear', methods=['POST'])
def clear_history_api():
    """API Endpoint to clear prediction history."""
    try:
        db.clear_history()
        return jsonify({
            "status": "success",
            "message": "Prediction history cleared successfully."
        }), 200
    except Exception as e:
        return jsonify({"status": "error", "message": "Failed to clear history."}), 500

@app.route('/about')
def about_page():
    """Render about page."""
    return render_template('about.html')

@app.route('/privacy')
def privacy_page():
    """Render Privacy Policy legal page."""
    return render_template('privacy.html')

@app.route('/terms')
def terms_page():
    """Render Terms of Service legal page."""
    return render_template('terms.html')

# ----------------------------------------------------------------------
# Gmail Integration Routes (OAuth 2.0 & On-Demand Inbox Scanning)
# ----------------------------------------------------------------------
@app.route('/gmail')
def gmail_page():
    """Render the Gmail Inbox Scanner dashboard."""
    session_id = session.get('gmail_session_id')
    account = gmail_auth.get_connected_account(session_id)
    configured = gmail_auth.is_configured()

    error_param = request.args.get('error')
    status_param = request.args.get('status')

    error_msg = None
    success_msg = None

    if error_param:
        if error_param == 'not_configured':
            error_msg = "Google Cloud OAuth credentials are not configured. Please add GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET to your .env file."
        else:
            error_msg = error_param
    elif status_param == 'connected':
        success_msg = "Your Gmail account has been securely connected! You can now scan your inbox for spam on demand."

    return render_template(
        'gmail.html',
        connected=bool(account),
        connected_email=account['email'] if account else None,
        configured=configured,
        error_message=error_msg,
        success_message=success_msg
    )

@app.route('/gmail/connect')
def gmail_connect():
    """Initiate Google OAuth 2.0 authorization flow with cryptographically signed CSRF state."""
    if not gmail_auth.is_configured():
        return redirect(url_for('gmail_page', error='not_configured'))

    session_id = session.get('gmail_session_id')
    # Generate cryptographically signed state token with HMAC-SHA256
    state = gmail_auth.generate_signed_state(session_id)
    session['oauth_state'] = state
    session.permanent = True

    app.logger.info("OAuth authorization initiated: CSRF state generated (session_present=%s, state_len=%d)",
                    bool(session_id), len(state))

    auth_url = gmail_auth.get_authorization_url(state)
    response = redirect(auth_url)
    # Also attach state backup cookie in case cross-site session is partitioned
    response.set_cookie(
        'mailvision_oauth_state',
        state,
        max_age=600,
        httponly=True,
        samesite='Lax',
        secure=bool(config.IS_VERCEL or os.environ.get('SESSION_COOKIE_SECURE', '').lower() == 'true'),
        path='/'
    )
    return response

@app.route('/gmail/callback')
def gmail_callback():
    """Handle OAuth 2.0 redirect callback from Google with resilient CSRF validation."""
    # Check for OAuth errors (e.g. user cancelled consent)
    error = request.args.get('error')
    if error:
        app.logger.warning("OAuth error parameter received in callback: %s", error)
        return redirect(url_for('gmail_page', error=f"Google authentication was cancelled: {error}"))

    returned_state = request.args.get('state')
    saved_state = session.get('oauth_state') or request.cookies.get('mailvision_oauth_state')

    # Validate state using signed HMAC token verification
    is_valid, state_session_id, reason = gmail_auth.validate_signed_state(
        returned_state=returned_state,
        saved_state=saved_state
    )

    app.logger.info("OAuth state validation: valid=%s, session_recovered=%s, reason=%s",
                    is_valid, bool(state_session_id), reason)

    if not is_valid:
        app.logger.warning("OAuth CSRF validation rejected: %s", reason)
        return redirect(url_for('gmail_page', error=f"Invalid OAuth state parameter: {reason}. Request rejected to prevent CSRF."))

    # Clear state from session
    session.pop('oauth_state', None)

    # Ensure session_id is preserved or restored from signed state
    session_id = session.get('gmail_session_id') or state_session_id
    if not session_id:
        session_id = secrets.token_hex(16)
    session['gmail_session_id'] = session_id
    session.permanent = True

    # Validate authorization code
    code = request.args.get('code')
    if not code:
        return redirect(url_for('gmail_page', error="Authorization code missing from Google response."))

    # Exchange code for tokens
    tokens, err = gmail_auth.exchange_code_for_tokens(code)
    if err or not tokens:
        return redirect(url_for('gmail_page', error=err or "Failed to exchange authorization code for tokens."))

    access_token = tokens.get('access_token')
    refresh_token = tokens.get('refresh_token', '')
    expires_in = tokens.get('expires_in', 3600)

    # Fetch user email profile
    profile, prof_err = gmail_auth.get_user_profile(access_token)
    email_address = profile.get('emailAddress', 'Connected User') if profile else 'Connected User'

    # Encrypt tokens and associate with user session
    gmail_auth.save_connection(session_id, email_address, access_token, refresh_token, expires_in)

    response = redirect(url_for('gmail_page', status='connected'))
    # Clean up backup cookie
    response.delete_cookie('mailvision_oauth_state', path='/')
    return response

@app.route('/gmail/disconnect', methods=['POST'])
def gmail_disconnect():
    """Disconnect Gmail account and securely clear stored tokens for current session."""
    session_id = session.get('gmail_session_id')
    gmail_auth.disconnect_account(session_id)
    return jsonify({
        "status": "success",
        "message": "Gmail account disconnected successfully."
    }), 200

@app.route('/api/gmail/status', methods=['GET'])
def gmail_status_api():
    """Check connection status of the current user session."""
    session_id = session.get('gmail_session_id')
    account = gmail_auth.get_connected_account(session_id)
    configured = gmail_auth.is_configured()

    return jsonify({
        "status": "success",
        "connected": bool(account),
        "email": account['email'] if account else None,
        "configured": configured
    }), 200

@app.route('/api/gmail/scan', methods=['POST'])
def gmail_scan_api():
    """Perform on-demand scan of the latest inbox messages."""
    session_id = session.get('gmail_session_id')
    data = request.get_json(silent=True) or {}
    page_token = data.get('page_token')
    max_results = data.get('max_results')

    result = gmail_service.scan_inbox(session_id, max_results=max_results, page_token=page_token)

    if result.get("status") == "error":
        status_code = 401 if result.get("error_type") == "auth_error" else 500
        return jsonify(result), status_code

    return jsonify(result), 200

@app.route('/api/gmail/feedback', methods=['POST'])
def gmail_feedback_api():
    """API endpoint to record user feedback on email prediction (Correct / Incorrect)."""
    session_id = session.get('gmail_session_id')
    data = request.get_json(silent=True) or {}
    message_id = (data.get('message_id') or '').strip()
    feedback = (data.get('feedback') or '').strip().lower()
    prediction = (data.get('prediction') or '').strip().upper()
    risk_level = (data.get('risk_level') or '').strip()
    confidence = data.get('confidence')

    if not message_id:
        return jsonify({"status": "error", "message": "Message ID is required."}), 400

    if feedback not in ('correct', 'incorrect'):
        return jsonify({"status": "error", "message": "Feedback must be 'correct' or 'incorrect'."}), 400

    conf_val = None
    if confidence is not None:
        try:
            conf_val = float(confidence)
        except (ValueError, TypeError):
            conf_val = None

    success, msg = db.save_scan_feedback(
        message_id=message_id,
        feedback=feedback,
        prediction=prediction or 'UNKNOWN',
        confidence=conf_val,
        risk_level=risk_level,
        session_id=session_id
    )

    return jsonify({
        "status": "success" if success else "error",
        "message": msg,
        "message_id": message_id,
        "feedback": feedback
    }), 200

# Error Handlers
@app.errorhandler(404)
def not_found_error(error):
    app.logger.warning("404 Not Found: path=%s, environ_path=%s, x_matched_path=%s",
                       request.path, request.environ.get('PATH_INFO'), request.headers.get('x-matched-path'))
    # Return JSON for actual API endpoints, but HTML for all page routes
    if request.path.startswith('/api/') and not request.path.startswith('/api/index'):
        return jsonify({"status": "error", "message": "API endpoint not found"}), 404
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    if request.path.startswith('/api/'):
        return jsonify({"status": "error", "message": "Internal server error"}), 500
    return render_template('500.html'), 500

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=True)
