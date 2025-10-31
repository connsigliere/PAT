"""
Security Middleware and Decorators
Implements authentication, rate limiting, and security headers
"""

from functools import wraps
from flask import request, jsonify, session, redirect, url_for
from datetime import datetime, timedelta
import hashlib
import secrets
from collections import defaultdict
from loguru import logger


# Rate limiting storage (in-memory, use Redis in production)
rate_limit_storage = defaultdict(list)

# CSRF token storage
csrf_tokens = {}


def login_required(f):
    """Decorator to require authentication for routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check session
        if 'user_id' not in session:
            # For API calls, return JSON
            if request.path.startswith('/api/'):
                return jsonify({'success': False, 'error': 'Authentication required'}), 401
            # For web pages, redirect to login
            return redirect(url_for('login_page'))

        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    """Decorator to require admin privileges"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            if request.path.startswith('/api/'):
                return jsonify({'success': False, 'error': 'Authentication required'}), 401
            return redirect(url_for('login_page'))

        if not session.get('is_admin', False):
            if request.path.startswith('/api/'):
                return jsonify({'success': False, 'error': 'Admin privileges required'}), 403
            return jsonify({'error': 'Forbidden'}), 403

        return f(*args, **kwargs)
    return decorated_function


def api_key_required(f):
    """Decorator to require API key for programmatic access"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')

        if not api_key:
            return jsonify({'success': False, 'error': 'API key required'}), 401

        # Validate API key (this will be done against database)
        from core.auth import AuthManager
        auth = AuthManager()
        user = auth.validate_api_key(api_key)

        if not user:
            return jsonify({'success': False, 'error': 'Invalid API key'}), 401

        # Add user to request context
        request.current_user = user

        return f(*args, **kwargs)
    return decorated_function


def rate_limit(max_requests: int = 100, window_seconds: int = 60):
    """
    Decorator to rate limit requests

    Args:
        max_requests: Maximum requests allowed
        window_seconds: Time window in seconds
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Get client identifier (IP address)
            client_id = request.remote_addr

            # Get current time
            now = datetime.now()
            cutoff = now - timedelta(seconds=window_seconds)

            # Clean old requests
            rate_limit_storage[client_id] = [
                req_time for req_time in rate_limit_storage[client_id]
                if req_time > cutoff
            ]

            # Check rate limit
            if len(rate_limit_storage[client_id]) >= max_requests:
                logger.warning(f"Rate limit exceeded for {client_id}")
                return jsonify({
                    'success': False,
                    'error': 'Rate limit exceeded. Please try again later.'
                }), 429

            # Add current request
            rate_limit_storage[client_id].append(now)

            return f(*args, **kwargs)
        return decorated_function
    return decorator


def generate_csrf_token():
    """Generate CSRF token for session"""
    token = secrets.token_urlsafe(32)
    session['csrf_token'] = token
    csrf_tokens[token] = datetime.now()
    return token


def validate_csrf_token(token: str) -> bool:
    """Validate CSRF token"""
    session_token = session.get('csrf_token')

    if not session_token or session_token != token:
        return False

    # Check token age (expire after 1 hour)
    if token in csrf_tokens:
        token_age = datetime.now() - csrf_tokens[token]
        if token_age.total_seconds() > 3600:
            del csrf_tokens[token]
            return False

    return True


def csrf_protect(f):
    """Decorator to protect against CSRF attacks"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method in ['POST', 'PUT', 'DELETE', 'PATCH']:
            token = request.headers.get('X-CSRF-Token') or request.form.get('csrf_token')

            if not token or not validate_csrf_token(token):
                logger.warning(f"CSRF validation failed from {request.remote_addr}")
                return jsonify({'success': False, 'error': 'CSRF validation failed'}), 403

        return f(*args, **kwargs)
    return decorated_function


def add_security_headers(response):
    """Add security headers to response"""
    # Prevent clickjacking
    response.headers['X-Frame-Options'] = 'DENY'

    # Prevent MIME sniffing
    response.headers['X-Content-Type-Options'] = 'nosniff'

    # XSS Protection
    response.headers['X-XSS-Protection'] = '1; mode=block'

    # Strict Transport Security (HTTPS only)
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'

    # Content Security Policy
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "img-src 'self' data: https:; "
        "font-src 'self' https://cdn.jsdelivr.net;"
    )

    # Referrer Policy
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'

    # Permissions Policy
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'

    return response


def sanitize_input(data):
    """Sanitize user input to prevent XSS"""
    if isinstance(data, str):
        # Remove dangerous characters
        dangerous_chars = ['<', '>', '"', "'", '&']
        for char in dangerous_chars:
            data = data.replace(char, '')
        return data.strip()

    elif isinstance(data, dict):
        return {k: sanitize_input(v) for k, v in data.items()}

    elif isinstance(data, list):
        return [sanitize_input(item) for item in data]

    return data


def get_client_ip():
    """Get real client IP address (handling proxies)"""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    elif request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP')
    return request.remote_addr


def log_security_event(event_type: str, details: str, severity: str = 'info'):
    """Log security events"""
    log_data = {
        'event': event_type,
        'details': details,
        'ip': get_client_ip(),
        'user_agent': request.headers.get('User-Agent'),
        'timestamp': datetime.now().isoformat()
    }

    if severity == 'warning':
        logger.warning(f"Security Event: {log_data}")
    elif severity == 'error':
        logger.error(f"Security Event: {log_data}")
    else:
        logger.info(f"Security Event: {log_data}")
