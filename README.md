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

## 🚀 Quick Start

```bash
# Clone the repository
git clone https://github.com/yourusername/phishing-automation-tool.git
cd phishing-automation-tool

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp config/config.example.yml config/config.yml
# Edit config.yml with your settings

# Run the application
python src/main.py
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
