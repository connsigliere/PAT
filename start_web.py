#!/usr/bin/env python3
"""
Phishing Automation Tool - Web Interface Startup Script
For authorized penetration testing only
"""

import sys
import os
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / 'src'))

from api.app import create_app
from loguru import logger

# Configure logging
logger.add("logs/web.log", rotation="100 MB", retention="30 days", level="INFO")

def main():
    """Start the web application"""

    # Create app
    app = create_app()

    # Display startup banner
    print("""
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   Phishing Infrastructure Automation Tool - Web Interface     ║
║   For Authorized Penetration Testing Only                     ║
║                                                               ║
║   [!] Unauthorized use is illegal and unethical               ║
║   [!] Always obtain written authorization                     ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝

Starting web server...

Access the dashboard at: http://localhost:5000

API Documentation:
  - Dashboard Stats: GET  /api/dashboard/stats
  - Campaigns:       GET  /api/campaigns
  - Create Campaign: POST /api/campaigns
  - Check Domain:    POST /api/domain/check
  - Generate Email:  POST /api/email/generate
  - Clone Page:      POST /api/clone/page

Press CTRL+C to stop the server
    """)

    try:
        # Start server
        app.run(
            host='0.0.0.0',
            port=5000,
            debug=True,
            use_reloader=False  # Disable reloader to prevent double startup
        )
    except KeyboardInterrupt:
        print("\n\nShutting down gracefully...")
        logger.info("Web server stopped by user")
    except Exception as e:
        logger.error(f"Server error: {e}")
        print(f"\nError starting server: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
