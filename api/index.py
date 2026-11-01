import os
import sys

# Ensure project root is in Python's search path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from app import app


class VercelPathMiddleware:
    """
    WSGI Middleware for Vercel Serverless Functions:
    When Vercel's rewrite rule maps traffic to /api/index, WSGI environ['PATH_INFO']
    may retain the internal function path ('/api/index' or '/api/index.py') instead
    of the client's actual requested URL path.

    This middleware inspects Vercel's x-matched-path header (and x-forwarded-uri)
    to restore the true client request path before passing it to Flask's router.
    """
    def __init__(self, wsgi_app):
        self.wsgi_app = wsgi_app

    def __call__(self, environ, start_response):
        path_info = environ.get('PATH_INFO', '')
        # Check if the path points to the serverless function destination
        if path_info in ('/api/index.py', '/api/index', '/api', '/api/'):
            # 1. Recover the actual matched route from Vercel's header
            matched_path = environ.get('HTTP_X_MATCHED_PATH')
            if matched_path and matched_path not in ('/api/index.py', '/api/index', '/api', '/api/'):
                environ['PATH_INFO'] = matched_path
            # 2. Check forwarded URI
            elif environ.get('HTTP_X_FORWARDED_URI'):
                uri = environ.get('HTTP_X_FORWARDED_URI').split('?')[0]
                if uri not in ('/api/index.py', '/api/index', '/api', '/api/'):
                    environ['PATH_INFO'] = uri
            # 3. Default to root homepage if no specific subpath was matched
            else:
                environ['PATH_INFO'] = '/'

        return self.wsgi_app(environ, start_response)


# Apply middleware to Flask application instance for Vercel
app.wsgi_app = VercelPathMiddleware(app.wsgi_app)
