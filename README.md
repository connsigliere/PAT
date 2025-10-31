# Phishing Infrastructure Automation Tool

## ⚠️ LEGAL DISCLAIMER

This tool is designed EXCLUSIVELY for authorized penetration testing and security awareness training.

**YOU MUST:**
- Obtain written authorization before ANY engagement
- Only test systems you own or have explicit permission to test
- Comply with all applicable laws and regulations
- Document all client agreements and scope boundaries

**UNAUTHORIZED USE IS ILLEGAL** and may result in criminal prosecution under laws including but not limited to:
- Computer Fraud and Abuse Act (CFAA) - US
- Computer Misuse Act - UK
- Similar laws in your jurisdiction

The authors assume NO LIABILITY for misuse of this tool.

---

## 🎯 Purpose

A comprehensive automation toolkit for authorized phishing assessments during penetration testing engagements. Streamlines infrastructure setup, campaign management, and reporting.

## ✨ Features

### 1. Domain Reputation Checker
- Check domain reputation across multiple threat intelligence feeds
- Verify domain age and registration history
- Test email deliverability scores
- DNS configuration validation

### 2. Email Template Generator
- Pre-built phishing templates (corporate, IT support, HR, etc.)
- Anti-spam evasion techniques
- Variable injection for personalization
- A/B testing support

### 3. Landing Page Cloner
- Clone legitimate websites with high fidelity
- Built-in credential harvester with encryption
- Real-time notification system
- MFA prompt capture capability

### 4. SSL Certificate Automation
- Automatic Let's Encrypt certificate generation
- Certificate renewal management
- Multi-domain support
- HTTPS enforcement

### 5. Email Infrastructure
- SPF/DKIM/DMARC configuration automation
- Email warmup sequences
- Sender reputation monitoring
- Rate limiting and throttling

### 6. Campaign Management
- Track multiple campaigns simultaneously
- Real-time analytics and reporting
- Credential logging and encryption
- Audit trail for compliance

## 🖥️ Web Interface

**NEW!** Access all features through a modern web-based dashboard:

```bash
# Start the web server
python start_web.py

# Access at: http://localhost:5000
```

**Features:**
- 📊 Real-time campaign dashboard
- 🎯 Visual campaign management
- 🌐 Interactive domain checker
- ✉️ Email template generator with preview
- 📄 Landing page cloner interface
- 🔒 SSL certificate manager

See [WEB_INTERFACE_GUIDE.md](WEB_INTERFACE_GUIDE.md) for detailed documentation.

## 🔐 Security Features

**NEW!** Comprehensive authentication and security:

```bash
# Setup security (first time)
python setup_security.py

# Start secure web server
python start_web_secure.py

# Access at: http://localhost:5000/login
```

**Security Features:**
- 🔒 User authentication with bcrypt password hashing
- 🔑 API key authentication for programmatic access
- 🛡️ CSRF protection on all forms
- ⏱️ Rate limiting on API endpoints
- 📝 Comprehensive audit logging
- 🔐 Secure session management
- 🚫 Security headers (XSS, Clickjacking protection)
- 👥 Role-based access control (User/Admin)
- 📊 Admin dashboard with user management

See [SECURITY_GUIDE.md](SECURITY_GUIDE.md) for complete security documentation.

## 🚀 Quick Start

### Option 1: Web Interface (Recommended)

```bash
# Install dependencies
pip install -r requirements.txt

# Start web server
python start_web.py

# Open browser to http://localhost:5000
```

### Option 2: Command Line Interface

```bash
# Clone the repository
git clone https://github.com/connsigliere/PAT.git
cd PAT

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp config/config.example.yml config/config.yml
# Edit config.yml with your settings

# Run CLI commands
python src/main.py --help
```

## 📚 Documentation

See the `docs/` folder for detailed documentation:
- Setup Guide
- API Documentation
- Campaign Workflow
- Best Practices
- Legal Considerations

## 🛠️ Technology Stack

- Python 3.9+
- Flask/FastAPI
- SQLAlchemy
- BeautifulSoup4/Playwright
- Certbot
- Docker

## 📝 License

MIT License - See LICENSE file for details

## 🤝 Contributing

Contributions are welcome! Please read CONTRIBUTING.md first.

## 📧 Contact

For questions or security concerns: [your-email]

---

**Remember: With great power comes great responsibility. Use ethically and legally.**
