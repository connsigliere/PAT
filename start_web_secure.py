#!/usr/bin/env python3
"""
Phishing Automation Tool - Secure Web Interface Startup Script
For authorized penetration testing only - WITH AUTHENTICATION ENABLED
"""

import sys
import os
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / 'src'))

from api.app_secure import create_app
from loguru import logger

# Configure logging
logger.add("logs/web_secure.log", rotation="100 MB", retention="30 days", level="INFO")

def check_setup():
    """Check if security setup has been completed"""
    auth_db = Path("auth.db")

    if not auth_db.exists():
        print("""
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   SECURITY SETUP REQUIRED                                     ║
║                                                               ║
║   No user database found. Please run security setup first:    ║
║                                                               ║
║   python setup_security.py                                    ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
        """)
        return False

    return True


def main():
    """Start the secure web application"""

    # Check setup
    if not check_setup():
        sys.exit(1)

    # Create app
    app = create_app()

    # Display startup banner
    print("""
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   Phishing Automation Tool - Secure Web Interface             ║
║   For Authorized Penetration Testing Only                     ║
║                                                               ║
║   [!] AUTHENTICATION ENABLED                                  ║
║   [!] Unauthorized access is illegal and unethical            ║
║   [!] Always obtain written authorization                     ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝

🔐 SECURITY FEATURES ENABLED:
   ✓ User authentication with sessions
   ✓ Password hashing with bcrypt
   ✓ CSRF protection on all forms
   ✓ Rate limiting on API endpoints
   ✓ Security headers (XSS, Clickjacking, etc.)
   ✓ API key authentication for programmatic access
   ✓ Audit logging of all security events
   ✓ Session timeout and management

🌐 ACCESS INFORMATION:
   Login Page: http://localhost:5000/login
   Dashboard:  http://localhost:5000/ (after login)

📚 DOCUMENTATION:
   Security Guide:    SECURITY_GUIDE.md
   Web Interface:     WEB_INTERFACE_GUIDE.md
   General Usage:     USAGE_GUIDE.md

🔑 DEFAULT ADMIN CREDENTIALS (if not changed):
   Username: admin
   Password: Change_This_Password_123!
   ⚠  CHANGE IMMEDIATELY AFTER FIRST LOGIN!

⚡ API AUTHENTICATION:
   Use X-API-Key header with your API key for programmatic access
   Get your API key from the Profile menu after logging in

📊 MONITORING:
   Audit logs: Check Admin Dashboard
   Application logs: logs/web_secure.log

Press CTRL+C to stop the server
    """)

    try:
        # Start server
        app.run(
            host='0.0.0.0',
            port=5000,
            debug=False,  # Disable debug in production
            use_reloader=False
        )
    except KeyboardInterrupt:
        print("\n\nShutting down gracefully...")
        logger.info("Secure web server stopped by user")
    except Exception as e:
        logger.error(f"Server error: {e}")
        print(f"\nError starting server: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
