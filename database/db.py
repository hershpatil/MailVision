import sqlite3
import os
from datetime import datetime

import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config

def get_db_connection():
    """Establish connection to SQLite database."""
    os.makedirs(config.DATABASE_DIR, exist_ok=True)
    conn = sqlite3.connect(config.DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initialize database tables if they do not exist."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS predictions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            prediction TEXT NOT NULL,
            confidence REAL NOT NULL,
            spam_probability REAL NOT NULL,
            ham_probability REAL NOT NULL,
            word_count INTEGER NOT NULL,
            url_count INTEGER NOT NULL
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS gmail_tokens (
            session_id TEXT PRIMARY KEY,
            email TEXT,
            access_token_enc TEXT NOT NULL,
            refresh_token_enc TEXT,
            expires_at REAL NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scan_feedback (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            message_id TEXT NOT NULL,
            session_id TEXT,
            prediction TEXT NOT NULL,
            feedback TEXT NOT NULL,
            risk_level TEXT,
            confidence REAL,
            timestamp TEXT NOT NULL,
            UNIQUE(message_id, session_id)
        )
    ''')
    conn.commit()
    conn.close()

def log_prediction(prediction: str, confidence: float, spam_prob: float, ham_prob: float, word_count: int, url_count: int) -> int:
    """
    Log anonymous prediction metadata to SQLite database.
    Does NOT store raw email text to preserve privacy.
    """
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    cursor.execute('''
        INSERT INTO predictions (timestamp, prediction, confidence, spam_probability, ham_probability, word_count, url_count)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (now_str, prediction, confidence, spam_prob, ham_prob, word_count, url_count))

    conn.commit()
    inserted_id = cursor.lastrowid
    conn.close()
    return inserted_id

def get_history(limit: int = 50) -> list:
    """Retrieve past predictions from database."""
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('''
        SELECT id, timestamp, prediction, confidence, spam_probability, ham_probability, word_count, url_count
        FROM predictions
        ORDER BY id DESC
        LIMIT ?
    ''', (limit,))

    rows = cursor.fetchall()
    conn.close()

    history = []
    for row in rows:
        history.append({
            "id": row["id"],
            "timestamp": row["timestamp"],
            "prediction": row["prediction"],
            "confidence": row["confidence"],
            "spam_probability": row["spam_probability"],
            "ham_probability": row["ham_probability"],
            "word_count": row["word_count"],
            "url_count": row["url_count"]
        })
    return history

def clear_history():
    """Clear all records from predictions table."""
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM predictions')
    conn.commit()
    conn.close()

def save_gmail_tokens(session_id: str, email: str, access_token_enc: str, refresh_token_enc: str, expires_at: float):
    """
    Store encrypted OAuth tokens for a user session.
    Never stores plaintext tokens.
    """
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    cursor.execute('''
        INSERT INTO gmail_tokens (session_id, email, access_token_enc, refresh_token_enc, expires_at, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(session_id) DO UPDATE SET
            email = excluded.email,
            access_token_enc = excluded.access_token_enc,
            refresh_token_enc = CASE WHEN excluded.refresh_token_enc IS NOT NULL AND excluded.refresh_token_enc != '' 
                                     THEN excluded.refresh_token_enc 
                                     ELSE gmail_tokens.refresh_token_enc END,
            expires_at = excluded.expires_at,
            updated_at = excluded.updated_at
    ''', (session_id, email, access_token_enc, refresh_token_enc, expires_at, now_str, now_str))

    conn.commit()
    conn.close()

def get_gmail_tokens(session_id: str) -> dict | None:
    """Retrieve encrypted OAuth tokens for a user session."""
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT session_id, email, access_token_enc, refresh_token_enc, expires_at, created_at, updated_at
        FROM gmail_tokens
        WHERE session_id = ?
    ''', (session_id,))
    row = cursor.fetchone()
    conn.close()

    if row:
        return {
            "session_id": row["session_id"],
            "email": row["email"],
            "access_token_enc": row["access_token_enc"],
            "refresh_token_enc": row["refresh_token_enc"],
            "expires_at": row["expires_at"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"]
        }
    return None

def delete_gmail_tokens(session_id: str):
    """Delete stored OAuth tokens for a user session upon disconnection."""
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM gmail_tokens WHERE session_id = ?', (session_id,))
    conn.commit()
    conn.close()

def save_scan_feedback(message_id: str, feedback: str, prediction: str = "UNKNOWN", confidence: float = None, risk_level: str = None, session_id: str = None) -> tuple[bool, str]:
    """
    Store user feedback ('correct' / 'incorrect') for an email prediction.
    Enforces uniqueness per (message_id, session_id) to prevent duplicate submissions.
    Does NOT store raw email bodies or OAuth tokens.
    """
    if not message_id or not feedback:
        return False, "Message ID and feedback choice are required."

    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Check if feedback already exists for this message & session
    cursor.execute('''
        SELECT id, feedback FROM scan_feedback
        WHERE message_id = ? AND (session_id = ? OR (session_id IS NULL AND ? IS NULL))
    ''', (message_id, session_id, session_id))
    existing = cursor.fetchone()

    if existing:
        if existing['feedback'] == feedback:
            conn.close()
            return True, "Feedback already recorded."
        cursor.execute('''
            UPDATE scan_feedback
            SET feedback = ?, prediction = ?, confidence = ?, risk_level = ?, timestamp = ?
            WHERE id = ?
        ''', (feedback, prediction, confidence, risk_level, now_str, existing['id']))
        conn.commit()
        conn.close()
        return True, "Feedback updated successfully."

    cursor.execute('''
        INSERT INTO scan_feedback (message_id, session_id, prediction, feedback, risk_level, confidence, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (message_id, session_id, prediction, feedback, risk_level, confidence, now_str))
    conn.commit()
    conn.close()
    return True, "Feedback submitted successfully."

def get_feedback_for_messages(message_ids: list[str], session_id: str = None) -> dict[str, str]:
    """Retrieve recorded feedback choices for a list of message IDs."""
    if not message_ids:
        return {}
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()
    placeholders = ','.join(['?'] * len(message_ids))
    params = list(message_ids)
    if session_id:
        cursor.execute(f'''
            SELECT message_id, feedback FROM scan_feedback
            WHERE message_id IN ({placeholders}) AND (session_id = ? OR session_id IS NULL)
        ''', params + [session_id])
    else:
        cursor.execute(f'''
            SELECT message_id, feedback FROM scan_feedback
            WHERE message_id IN ({placeholders})
        ''', params)
    rows = cursor.fetchall()
    conn.close()
    return {row['message_id']: row['feedback'] for row in rows}

def clear_scan_feedback():
    """Clear all records from scan_feedback table (used for test teardown)."""
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM scan_feedback')
    conn.commit()
    conn.close()

if __name__ == '__main__':
    init_db()
    print("Database initialized successfully at:", config.DATABASE_PATH)
