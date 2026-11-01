import sqlite3
import os
import logging
from datetime import datetime
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config

logger = logging.getLogger(__name__)

def is_postgres() -> bool:
    """Check if PostgreSQL DATABASE_URL is configured."""
    url = getattr(config, 'DATABASE_URL', '') or ''
    return url.startswith('postgres://') or url.startswith('postgresql://')

def get_db_connection():
    """
    Establish connection to database.
    Connects to PostgreSQL if DATABASE_URL is set, otherwise connects to local SQLite.
    """
    if is_postgres():
        try:
            import psycopg2
            from psycopg2.extras import RealDictCursor
            url = config.DATABASE_URL
            # Normalize postgres:// -> postgresql:// for modern psycopg2
            if url.startswith("postgres://"):
                url = url.replace("postgres://", "postgresql://", 1)
            conn = psycopg2.connect(url, cursor_factory=RealDictCursor)
            return conn
        except ImportError:
            logger.warning("psycopg2 not installed; falling back to SQLite for local development.")
        except Exception as e:
            logger.error(f"PostgreSQL connection failed: {e}; falling back to SQLite.")

    # Fallback / Local SQLite
    os.makedirs(config.DATABASE_DIR, exist_ok=True)
    conn = sqlite3.connect(config.DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def _execute_query(conn, sql: str, params: tuple = None, fetch_one: bool = False, fetch_all: bool = False, returning_id: bool = False):
    """
    Helper to execute queries seamlessly across PostgreSQL (%s) and SQLite (?).
    """
    pg_mode = is_postgres() and hasattr(conn, 'cursor_factory')
    cursor = conn.cursor()
    query_params = params or ()

    if pg_mode:
        # Convert SQLite ? placeholders to PostgreSQL %s
        transformed_sql = sql.replace('?', '%s')
        if returning_id and 'RETURNING' not in transformed_sql.upper():
            transformed_sql = transformed_sql.rstrip().rstrip(';') + ' RETURNING id;'
        cursor.execute(transformed_sql, query_params)
        if returning_id:
            row = cursor.fetchone()
            return row['id'] if row else None
    else:
        cursor.execute(sql, query_params)
        if returning_id:
            return cursor.lastrowid

    if fetch_one:
        return cursor.fetchone()
    if fetch_all:
        return cursor.fetchall()
    return None

def init_db():
    """Initialize database tables if they do not exist."""
    conn = get_db_connection()
    cursor = conn.cursor()
    pg_mode = is_postgres() and hasattr(conn, 'cursor_factory')

    if pg_mode:
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS predictions (
                id SERIAL PRIMARY KEY,
                timestamp TEXT NOT NULL,
                prediction TEXT NOT NULL,
                confidence DOUBLE PRECISION NOT NULL,
                spam_probability DOUBLE PRECISION NOT NULL,
                ham_probability DOUBLE PRECISION NOT NULL,
                word_count INTEGER NOT NULL,
                url_count INTEGER NOT NULL
            );
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS gmail_tokens (
                session_id TEXT PRIMARY KEY,
                email TEXT,
                access_token_enc TEXT NOT NULL,
                refresh_token_enc TEXT,
                expires_at DOUBLE PRECISION NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_feedback (
                id SERIAL PRIMARY KEY,
                message_id TEXT NOT NULL,
                session_id TEXT,
                prediction TEXT NOT NULL,
                feedback TEXT NOT NULL,
                risk_level TEXT,
                confidence DOUBLE PRECISION,
                timestamp TEXT NOT NULL,
                UNIQUE(message_id, session_id)
            );
        ''')
    else:
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
            );
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
            );
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
            );
        ''')

    conn.commit()
    conn.close()

def log_prediction(prediction: str, confidence: float, spam_prob: float, ham_prob: float, word_count: int, url_count: int) -> int:
    """
    Log anonymous prediction metadata to database.
    Does NOT store raw email text to preserve privacy.
    """
    init_db()
    conn = get_db_connection()
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    sql = '''
        INSERT INTO predictions (timestamp, prediction, confidence, spam_probability, ham_probability, word_count, url_count)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    '''
    inserted_id = _execute_query(conn, sql, (now_str, prediction, confidence, spam_prob, ham_prob, word_count, url_count), returning_id=True)
    conn.commit()
    conn.close()
    return inserted_id or 0

def get_history(limit: int = 50) -> list:
    """Retrieve past predictions from database."""
    init_db()
    conn = get_db_connection()
    sql = '''
        SELECT id, timestamp, prediction, confidence, spam_probability, ham_probability, word_count, url_count
        FROM predictions
        ORDER BY id DESC
        LIMIT ?
    '''
    rows = _execute_query(conn, sql, (limit,), fetch_all=True)
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
    cursor.execute('DELETE FROM predictions;')
    conn.commit()
    conn.close()

def save_gmail_tokens(session_id: str, email: str, access_token_enc: str, refresh_token_enc: str, expires_at: float):
    """
    Store encrypted OAuth tokens for a user session.
    Never stores plaintext tokens.
    """
    init_db()
    conn = get_db_connection()
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    sql = '''
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
    '''
    _execute_query(conn, sql, (session_id, email, access_token_enc, refresh_token_enc, expires_at, now_str, now_str))
    conn.commit()
    conn.close()

def get_gmail_tokens(session_id: str) -> dict | None:
    """Retrieve encrypted OAuth tokens for a user session."""
    init_db()
    conn = get_db_connection()
    sql = '''
        SELECT session_id, email, access_token_enc, refresh_token_enc, expires_at, created_at, updated_at
        FROM gmail_tokens
        WHERE session_id = ?
    '''
    row = _execute_query(conn, sql, (session_id,), fetch_one=True)
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
    sql = 'DELETE FROM gmail_tokens WHERE session_id = ?'
    _execute_query(conn, sql, (session_id,))
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
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    check_sql = '''
        SELECT id, feedback FROM scan_feedback
        WHERE message_id = ? AND (session_id = ? OR (session_id IS NULL AND ? IS NULL))
    '''
    existing = _execute_query(conn, check_sql, (message_id, session_id, session_id), fetch_one=True)

    if existing:
        if existing['feedback'] == feedback:
            conn.close()
            return True, "Feedback already recorded."
        update_sql = '''
            UPDATE scan_feedback
            SET feedback = ?, prediction = ?, confidence = ?, risk_level = ?, timestamp = ?
            WHERE id = ?
        '''
        _execute_query(conn, update_sql, (feedback, prediction, confidence, risk_level, now_str, existing['id']))
        conn.commit()
        conn.close()
        return True, "Feedback updated successfully."

    insert_sql = '''
        INSERT INTO scan_feedback (message_id, session_id, prediction, feedback, risk_level, confidence, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    '''
    _execute_query(conn, insert_sql, (message_id, session_id, prediction, feedback, risk_level, confidence, now_str))
    conn.commit()
    conn.close()
    return True, "Feedback submitted successfully."

def get_feedback_for_messages(message_ids: list[str], session_id: str = None) -> dict[str, str]:
    """Retrieve recorded feedback choices for a list of message IDs."""
    if not message_ids:
        return {}
    init_db()
    conn = get_db_connection()
    placeholders = ','.join(['?'] * len(message_ids))
    params = list(message_ids)
    if session_id:
        sql = f'''
            SELECT message_id, feedback FROM scan_feedback
            WHERE message_id IN ({placeholders}) AND (session_id = ? OR session_id IS NULL)
        '''
        rows = _execute_query(conn, sql, tuple(params + [session_id]), fetch_all=True)
    else:
        sql = f'''
            SELECT message_id, feedback FROM scan_feedback
            WHERE message_id IN ({placeholders})
        '''
        rows = _execute_query(conn, sql, tuple(params), fetch_all=True)
    conn.close()
    return {row['message_id']: row['feedback'] for row in rows}

def clear_scan_feedback():
    """Clear all records from scan_feedback table (used for test teardown)."""
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM scan_feedback;')
    conn.commit()
    conn.close()

if __name__ == '__main__':
    init_db()
    print("Database initialized successfully at:", config.DATABASE_PATH)
