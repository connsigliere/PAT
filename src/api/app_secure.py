"""
Flask Web Application with Authentication - REST API for Phishing Automation Tool
"""

from flask import Flask, render_template, jsonify, request, session, redirect, url_for
from flask_cors import CORS
import sys
import secrets
from pathlib import Path
from datetime import timedelta

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.domain_checker import DomainChecker
from core.email_generator import EmailGenerator
from core.page_cloner import PageCloner
from core.ssl_manager import SSLManager
from core.email_sender import EmailSender, EmailConfig, EmailMessage
from core.campaign_manager import CampaignManager, Target
from core.auth import AuthManager
from api.security import (
    login_required, admin_required, api_key_required,
    rate_limit, csrf_protect, add_security_headers,
    generate_csrf_token, get_client_ip, log_security_event
)
from loguru import logger


def create_app(config=None):
    """Create and configure Flask application with security"""

    app = Flask(__name__,
                template_folder='../web/templates',
                static_folder='../web/static')

    # Enable CORS with credentials
    CORS(app, supports_credentials=True)

    # Configuration
    app.config['SECRET_KEY'] = secrets.token_hex(32)  # Generate secure secret key
    app.config['JSON_SORT_KEYS'] = False
    app.config['SESSION_COOKIE_SECURE'] = True  # HTTPS only
    app.config['SESSION_COOKIE_HTTPONLY'] = True  # No JavaScript access
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # CSRF protection
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)

    if config:
        app.config.update(config)

    # Initialize managers
    domain_checker = DomainChecker()
    email_generator = EmailGenerator()
    page_cloner = PageCloner()
    campaign_manager = CampaignManager()
    auth_manager = AuthManager()

    # Add security headers to all responses
    @app.after_request
    def after_request(response):
        return add_security_headers(response)

    # Clean expired sessions periodically
    @app.before_request
    def before_request():
        auth_manager.delete_expired_sessions()


    # ============= AUTHENTICATION ROUTES =============

    @app.route('/login')
    def login_page():
        """Login page"""
        if 'user_id' in session:
            return redirect(url_for('index'))
        return render_template('login.html')

    @app.route('/api/auth/login', methods=['POST'])
    @rate_limit(max_requests=5, window_seconds=300)  # 5 attempts per 5 minutes
    def login():
        """Authenticate user"""
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')

        if not username or not password:
            return jsonify({'success': False, 'error': 'Username and password required'}), 400

        # Authenticate
        user = auth_manager.authenticate(username, password, get_client_ip())

        if user:
            # Create session
            session.permanent = True
            session['user_id'] = user.id
            session['username'] = user.username
            session['is_admin'] = user.is_admin
            session['csrf_token'] = generate_csrf_token()

            # Create session in database
            session_id = auth_manager.create_session(
                user.id,
                get_client_ip(),
                request.headers.get('User-Agent', 'Unknown')
            )

            log_security_event('login_success', f"User {username} logged in")

            return jsonify({
                'success': True,
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'is_admin': user.is_admin
                },
                'csrf_token': session['csrf_token']
            })

        log_security_event('login_failed', f"Failed login attempt for {username}", 'warning')
        return jsonify({'success': False, 'error': 'Invalid credentials'}), 401

    @app.route('/api/auth/logout', methods=['POST'])
    @login_required
    def logout():
        """Logout user"""
        username = session.get('username')
        session.clear()

        log_security_event('logout', f"User {username} logged out")

        return jsonify({'success': True, 'message': 'Logged out successfully'})

    @app.route('/api/auth/me')
    @login_required
    def get_current_user():
        """Get current user information"""
        user = auth_manager.get_user_by_id(session['user_id'])

        if user:
            return jsonify({
                'success': True,
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'is_admin': user.is_admin,
                    'api_key': user.api_key
                }
            })

        return jsonify({'success': False, 'error': 'User not found'}), 404

    @app.route('/api/auth/change-password', methods=['POST'])
    @login_required
    @csrf_protect
    def change_password():
        """Change user password"""
        data = request.get_json()
        current_password = data.get('current_password')
        new_password = data.get('new_password')

        if not current_password or not new_password:
            return jsonify({'success': False, 'error': 'Passwords required'}), 400

        # Verify current password
        user = auth_manager.authenticate(
            session['username'],
            current_password,
            get_client_ip()
        )

        if not user:
            return jsonify({'success': False, 'error': 'Current password incorrect'}), 401

        # Update password
        if auth_manager.update_password(user.id, new_password):
            log_security_event('password_changed', f"User {user.username} changed password")
            return jsonify({'success': True, 'message': 'Password updated'})

        return jsonify({'success': False, 'error': 'Password update failed'}), 500

    @app.route('/api/auth/regenerate-api-key', methods=['POST'])
    @login_required
    @csrf_protect
    def regenerate_api_key():
        """Regenerate user's API key"""
        api_key = auth_manager.regenerate_api_key(session['user_id'])

        if api_key:
            log_security_event('api_key_regenerated', f"User {session['username']} regenerated API key")
            return jsonify({'success': True, 'api_key': api_key})

        return jsonify({'success': False, 'error': 'Failed to regenerate API key'}), 500


    # ============= ADMIN ROUTES =============

    @app.route('/admin')
    @login_required
    @admin_required
    def admin_page():
        """Admin dashboard"""
        return render_template('admin.html')

    @app.route('/api/admin/users')
    @login_required
    @admin_required
    def list_users():
        """List all users (admin only)"""
        users = auth_manager.list_users()

        return jsonify({
            'success': True,
            'users': [{
                'id': u.id,
                'username': u.username,
                'email': u.email,
                'is_active': u.is_active,
                'is_admin': u.is_admin,
                'created_at': u.created_at,
                'last_login': u.last_login
            } for u in users]
        })

    @app.route('/api/admin/users', methods=['POST'])
    @login_required
    @admin_required
    @csrf_protect
    def create_user():
        """Create new user (admin only)"""
        data = request.get_json()

        user = auth_manager.create_user(
            username=data['username'],
            email=data['email'],
            password=data['password'],
            is_admin=data.get('is_admin', False)
        )

        if user:
            log_security_event('user_created', f"Admin created user {user.username}")
            return jsonify({
                'success': True,
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'api_key': user.api_key
                }
            })

        return jsonify({'success': False, 'error': 'User creation failed'}), 400

    @app.route('/api/admin/audit-log')
    @login_required
    @admin_required
    def get_audit_log():
        """Get audit log (admin only)"""
        limit = request.args.get('limit', 100, type=int)
        log_entries = auth_manager.get_audit_log(limit)

        return jsonify({'success': True, 'logs': log_entries})


    # ============= PROTECTED WEB ROUTES =============

    @app.route('/')
    @login_required
    def index():
        """Main dashboard"""
        return render_template('index.html')

    @app.route('/campaigns')
    @login_required
    def campaigns_page():
        """Campaign management page"""
        return render_template('campaigns.html')

    @app.route('/domain-checker')
    @login_required
    def domain_checker_page():
        """Domain checker page"""
        return render_template('domain_checker.html')

    @app.route('/email-generator')
    @login_required
    def email_generator_page():
        """Email generator page"""
        return render_template('email_generator.html')

    @app.route('/page-cloner')
    @login_required
    def page_cloner_page():
        """Page cloner page"""
        return render_template('page_cloner.html')

    @app.route('/ssl-manager')
    @login_required
    def ssl_manager_page():
        """SSL manager page"""
        return render_template('ssl_manager.html')


    # ============= PROTECTED API ROUTES =============

    # Dashboard API
    @app.route('/api/dashboard/stats')
    @login_required
    def dashboard_stats():
        """Get dashboard statistics"""
        try:
            campaigns = campaign_manager.list_campaigns()

            total_campaigns = len(campaigns)
            active_campaigns = len([c for c in campaigns if c.status == 'active'])
            total_sent = sum(c.emails_sent for c in campaigns)
            total_clicked = sum(c.links_clicked for c in campaigns)

            return jsonify({
                'success': True,
                'stats': {
                    'total_campaigns': total_campaigns,
                    'active_campaigns': active_campaigns,
                    'total_emails_sent': total_sent,
                    'total_clicks': total_clicked,
                    'click_rate': round((total_clicked / total_sent * 100) if total_sent > 0 else 0, 2)
                }
            })
        except Exception as e:
            logger.error(f"Dashboard stats error: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500


    # Domain Checker API
    @app.route('/api/domain/check', methods=['POST'])
    @login_required
    @rate_limit(max_requests=10, window_seconds=60)
    def check_domain():
        """Check domain reputation"""
        try:
            data = request.get_json()
            domain = data.get('domain')

            if not domain:
                return jsonify({'success': False, 'error': 'Domain is required'}), 400

            result = domain_checker.check_all(domain)
            return jsonify({'success': True, 'result': result})

        except Exception as e:
            logger.error(f"Domain check error: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500


    # Campaign API (all routes require authentication)
    @app.route('/api/campaigns', methods=['GET'])
    @login_required
    def list_campaigns():
        """List all campaigns"""
        try:
            status_filter = request.args.get('status')
            campaigns = campaign_manager.list_campaigns(status_filter)

            campaigns_data = []
            for c in campaigns:
                campaigns_data.append({
                    'id': c.id,
                    'name': c.name,
                    'description': c.description,
                    'status': c.status,
                    'template_type': c.template_type,
                    'created_at': c.created_at,
                    'targets_count': c.targets_count,
                    'emails_sent': c.emails_sent,
                    'emails_opened': c.emails_opened,
                    'links_clicked': c.links_clicked,
                    'credentials_captured': c.credentials_captured
                })

            return jsonify({'success': True, 'campaigns': campaigns_data})

        except Exception as e:
            logger.error(f"List campaigns error: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500


    @app.route('/api/campaigns', methods=['POST'])
    @login_required
    @csrf_protect
    @rate_limit(max_requests=20, window_seconds=3600)
    def create_campaign():
        """Create a new campaign"""
        try:
            data = request.get_json()

            campaign = campaign_manager.create_campaign(
                name=data['name'],
                description=data['description'],
                template_type=data['template_type'],
                target_domain=data['target_domain'],
                phishing_url=data['phishing_url']
            )

            log_security_event('campaign_created', f"Campaign created: {campaign.name}")

            return jsonify({
                'success': True,
                'campaign': {
                    'id': campaign.id,
                    'name': campaign.name,
                    'status': campaign.status
                }
            })

        except Exception as e:
            logger.error(f"Create campaign error: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500


    # Additional campaign routes with authentication...
    # (Include all other routes from original app.py with @login_required decorator)


    # Health check (no authentication required)
    @app.route('/api/health')
    def health_check():
        """API health check"""
        return jsonify({
            'status': 'healthy',
            'version': '2.0.0',
            'authentication': 'enabled'
        })


    return app


if __name__ == '__main__':
    app = create_app()
    app.run(host='0.0.0.0', port=5000, debug=True)
