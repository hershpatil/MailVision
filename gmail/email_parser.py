"""
MIME Email Parsing and Content Extraction for Gmail Messages.

Provides:
- Base64URL decoding of message body parts.
- Safe HTML-to-text conversion with script/style stripping and entity unescaping.
- Recursive multipart MIME payload traversal prioritizing plain text.
- Header extraction (From, Subject, Date) and snippet preservation.
- Graceful handling of malformed messages, empty bodies, and attachments.
"""
import base64
import html
from html.parser import HTMLParser
import re


def decode_base64url(data: str) -> str:
    """
    Safely decode Base64URL-encoded data from Gmail API.
    Handles missing padding and replaces invalid unicode characters.
    """
    if not data or not isinstance(data, str):
        return ""
    try:
        # Add padding if missing
        padded = data + '=' * (-len(data) % 4)
        raw_bytes = base64.urlsafe_b64decode(padded.encode('ascii'))
        return raw_bytes.decode('utf-8', errors='replace')
    except Exception:
        try:
            # Fallback standard b64 decode with replacements
            data_clean = data.replace('-', '+').replace('_', '/')
            padded = data_clean + '=' * (-len(data_clean) % 4)
            return base64.b64decode(padded.encode('ascii')).decode('utf-8', errors='replace')
        except Exception:
            return ""


class HTMLTextExtractor(HTMLParser):
    """
    Strips scripts, styles, metadata, and extracts clean, readable text from HTML.
    Preserves structural line breaks for headings, paragraphs, and list items.
    """
    def __init__(self):
        super().__init__()
        self.reset()
        self.fed = []
        self._ignore = False
        self._ignore_tags = {'script', 'style', 'head', 'title', 'meta', 'svg', 'noscript', 'iframe'}
        self._block_tags = {'p', 'div', 'br', 'hr', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'tr', 'li', 'blockquote'}

    def handle_starttag(self, tag, attrs):
        tag_lower = tag.lower()
        if tag_lower in self._ignore_tags:
            self._ignore = True
        elif tag_lower in self._block_tags:
            self.fed.append('\n')

    def handle_endtag(self, tag):
        tag_lower = tag.lower()
        if tag_lower in self._ignore_tags:
            self._ignore = False
        elif tag_lower in self._block_tags:
            self.fed.append('\n')

    def handle_data(self, d):
        if not self._ignore and d:
            self.fed.append(d)

    def get_text(self) -> str:
        raw_text = ''.join(self.fed)
        # Unescape all HTML entities (e.g. &nbsp;, &amp;, &lt;)
        unescaped = html.unescape(raw_text)
        # Clean lines and normalize extra newlines
        lines = [line.strip() for line in unescaped.splitlines()]
        cleaned = '\n'.join(line for line in lines if line)
        return cleaned


def clean_html_to_text(html_content: str) -> str:
    """
    Convert an HTML email body into clean plain text for spam analysis.
    """
    if not html_content or not isinstance(html_content, str):
        return ""
    try:
        extractor = HTMLTextExtractor()
        extractor.feed(html_content)
        text = extractor.get_text()
        return text.strip()
    except Exception:
        # Fallback regex-based HTML strip
        no_script = re.sub(r'<(script|style|head|title)[^>]*>.*?</\1>', '', html_content, flags=re.DOTALL | re.IGNORECASE)
        no_tags = re.sub(r'<[^>]+>', ' ', no_script)
        return html.unescape(re.sub(r'\s+', ' ', no_tags)).strip()


def extract_payload_text(payload: dict) -> tuple[str, bool]:
    """
    Recursively extract email body text from Gmail message payload.
    Prioritizes 'text/plain' content; falls back to cleaned 'text/html'.
    Returns (extracted_body_text, has_attachments).
    """
    if not payload or not isinstance(payload, dict):
        return "", False

    plain_parts = []
    html_parts = []
    has_attachments = False

    def _walk(part: dict):
        nonlocal has_attachments
        if not part or not isinstance(part, dict):
            return

        filename = part.get('filename')
        mime_type = (part.get('mimeType') or '').lower()
        body = part.get('body', {}) or {}
        data = body.get('data')

        if filename:
            has_attachments = True

        if mime_type == 'text/plain' and data:
            decoded = decode_base64url(data)
            if decoded.strip():
                plain_parts.append(decoded.strip())
        elif mime_type == 'text/html' and data:
            decoded = decode_base64url(data)
            cleaned = clean_html_to_text(decoded)
            if cleaned.strip():
                html_parts.append(cleaned.strip())

        # Recurse through multipart children
        for sub_part in part.get('parts', []):
            _walk(sub_part)

    _walk(payload)

    # Prefer plain text if available, otherwise use cleaned HTML
    if plain_parts:
        final_text = "\n\n".join(plain_parts)
    elif html_parts:
        final_text = "\n\n".join(html_parts)
    else:
        # If payload itself had a direct body without parts array
        direct_body = payload.get('body', {}) or {}
        direct_data = direct_body.get('data')
        if direct_data:
            decoded = decode_base64url(direct_data)
            mime = (payload.get('mimeType') or '').lower()
            if mime == 'text/html':
                final_text = clean_html_to_text(decoded)
            else:
                final_text = decoded.strip()
        else:
            final_text = ""

    return final_text, has_attachments


def parse_gmail_message(message_data: dict) -> dict:
    """
    Parse a raw Gmail API message dictionary into a clean, structured object.
    Extracts headers (From, Subject, Date), body text, and snippet.
    """
    if not message_data or not isinstance(message_data, dict):
        return {
            "id": "",
            "thread_id": "",
            "sender": "Unknown Sender",
            "subject": "(No Subject)",
            "date": "Unknown Date",
            "snippet": "",
            "body_text": "",
            "has_attachments": False
        }

    msg_id = message_data.get('id', '')
    thread_id = message_data.get('threadId', '')
    snippet = html.unescape(message_data.get('snippet', '')).strip()

    payload = message_data.get('payload', {}) or {}
    headers_list = payload.get('headers', []) or []

    # Map headers by lowercase name
    headers = {}
    for h in headers_list:
        if isinstance(h, dict) and 'name' in h:
            headers[h['name'].lower()] = h.get('value', '')

    sender = headers.get('from', 'Unknown Sender').strip()
    subject = headers.get('subject', '').strip() or "(No Subject)"
    date_str = headers.get('date', 'Unknown Date').strip()

    # Extract internal timestamp for sorting newest first
    timestamp = 0.0
    internal_date_raw = message_data.get('internalDate')
    if internal_date_raw:
        try:
            timestamp = float(internal_date_raw) / 1000.0
        except (ValueError, TypeError):
            timestamp = 0.0

    if timestamp == 0.0 and date_str and date_str != 'Unknown Date':
        import email.utils
        try:
            dt = email.utils.parsedate_to_datetime(date_str)
            timestamp = dt.timestamp()
        except Exception:
            timestamp = 0.0

    # Extract body text and attachment presence
    body_text, has_attachments = extract_payload_text(payload)

    # Fallback to snippet if body text is completely empty
    if not body_text and snippet:
        body_text = snippet

    return {
        "id": msg_id,
        "thread_id": thread_id,
        "sender": sender,
        "subject": subject,
        "date": date_str,
        "snippet": snippet,
        "body_text": body_text,
        "has_attachments": has_attachments,
        "timestamp": timestamp
    }
