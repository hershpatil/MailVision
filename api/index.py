import os
import sys
from urllib.parse import parse_qs, urlencode

# Ensure project root is in Python's search path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from app import app


class VercelPathMiddleware:
    """
    WSGI Middleware for Vercel Serverless Functions:
    Restores the client's original URL path from Vercel's rewrite query parameter
    (?path=$1) or headers into WSGI environ['PATH_INFO'].
    """
    def __init__(self, wsgi_app):
        self.wsgi_app = wsgi_app

    def __call__(self, environ, start_response):
        query_string = environ.get('QUERY_STRING', '')
        if 'path=' in query_string:
            params = parse_qs(query_string, keep_blank_values=True)
            if 'path' in params:
                raw_path = params['path'][0] if params['path'] else ''
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


# Apply middleware to Flask application instance for Vercel
app.wsgi_app = VercelPathMiddleware(app.wsgi_app)
