# Web Interface Guide

## Overview

The Phishing Automation Tool now includes a modern web-based interface for easy access to all features through your browser.

## Quick Start

### 1. Install Dependencies

```bash
cd phishing-automation-tool

# Activate virtual environment
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows

# Install/update dependencies (includes Flask and Flask-CORS)
pip install -r requirements.txt
```

### 2. Start the Web Server

```bash
# Simple start
python start_web.py

# Or manually
python src/api/app.py
```

The server will start on `http://localhost:5000`

### 3. Access the Dashboard

Open your browser and navigate to:
```
http://localhost:5000
```

---

## Features

### 📊 Dashboard (`/`)

**Overview of all campaign statistics:**
- Total campaigns
- Active campaigns
- Emails sent
- Click rates
- Recent campaigns list

**Quick Actions:**
- Create new campaign
- Check domain reputation
- Generate phishing email
- Clone landing page

### 🎯 Campaign Management (`/campaigns`)

**Create and manage phishing campaigns:**
- Create new campaigns
- View campaign statistics
- Start/pause/complete campaigns
- Add targets (manual or CSV import)
- View campaign results in real-time
- Filter by status (draft, active, completed)

**Campaign Workflow:**
1. Click "New Campaign"
2. Enter campaign details
3. Select email template
4. Add targets
5. Start campaign
6. Monitor results

### 🌐 Domain Checker (`/domain-checker`)

**Analyze domain reputation and configuration:**
- DNS record validation
- WHOIS information
- Blacklist status
- Email configuration (SPF/DKIM/DMARC)
- SSL certificate details
- Overall reputation score (0-100)

**Usage:**
1. Enter domain name
2. Click "Check Domain"
3. Review comprehensive results
4. Address any issues found

### ✉️ Email Generator (`/email-generator`)

**Generate phishing emails from templates:**
- 4 pre-built templates:
  - IT Support - Password Reset
  - HR - Benefits Enrollment
  - Executive Impersonation
  - Document Share
- Personalization with target data
- Anti-spam evasion levels
- Live preview of generated email
- Copy HTML source

**Usage:**
1. Select template type
2. Fill in target information
3. Set evasion level
4. Click "Generate Email"
5. Preview and copy HTML

### 📄 Page Cloner (`/page-cloner`)

**Clone landing pages with credential harvesting:**
- Clone any webpage
- Inject credential harvesting code
- Include assets (CSS, JS, images)
- Optional webhook notifications
- Automatic PHP backend generation

**Usage:**
1. Enter target URL
2. Select harvest method
3. Add webhook URL (optional)
4. Click "Clone Page"
5. Deploy cloned files to your infrastructure

### 🔒 SSL Manager (`/ssl-manager`)

**Manage SSL certificates:**
- Obtain Let's Encrypt certificates
- List installed certificates
- View expiration dates
- Multiple challenge methods:
  - Standalone (port 80)
  - Webroot
  - DNS challenge

**Usage:**
1. Enter domain and email
2. Select challenge method
3. Click "Obtain Certificate"
4. Certificate installed automatically

---

## API Endpoints

All features are accessible via REST API:

### Dashboard
```
GET  /api/dashboard/stats       - Get overall statistics
```

### Campaigns
```
GET  /api/campaigns              - List all campaigns
POST /api/campaigns              - Create new campaign
GET  /api/campaigns/{id}         - Get campaign details
POST /api/campaigns/{id}/start   - Start campaign
POST /api/campaigns/{id}/pause   - Pause campaign
POST /api/campaigns/{id}/complete - Complete campaign
GET  /api/campaigns/{id}/targets  - Get campaign targets
POST /api/campaigns/{id}/targets  - Add targets
GET  /api/campaigns/{id}/results  - Get campaign results
```

### Domain Checker
```
POST /api/domain/check           - Check domain reputation
```

### Email Generator
```
GET  /api/email/templates        - List templates
POST /api/email/generate         - Generate email
```

### Page Cloner
```
POST /api/clone/page             - Clone webpage
```

### SSL Manager
```
GET  /api/ssl/certificates       - List certificates
POST /api/ssl/obtain             - Obtain certificate
```

### API Usage Example

```javascript
// Check domain
const response = await fetch('/api/domain/check', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ domain: 'example.com' })
});

const result = await response.json();
console.log(result);
```

---

## Configuration

### Port Configuration

Edit `start_web.py` to change the port:

```python
app.run(
    host='0.0.0.0',
    port=5000,  # Change this
    debug=True
)
```

### Remote Access

To access from other machines:

```bash
# Make sure firewall allows port 5000
# Start server (already binds to 0.0.0.0)
python start_web.py

# Access from other machine
http://YOUR_SERVER_IP:5000
```

### Production Deployment

For production, use a proper WSGI server:

```bash
# Install gunicorn
pip install gunicorn

# Run with gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 "src.api.app:create_app()"
```

---

## Security Considerations

### Authentication

The current version does NOT include authentication. For production:

1. **Add Basic Auth:**
   ```python
   from flask_httpauth import HTTPBasicAuth
   ```

2. **Use Reverse Proxy:**
   - Nginx with client certificates
   - Apache with authentication

3. **Implement API Keys:**
   - Add API key validation
   - Rate limiting

### HTTPS

Always use HTTPS in production:

```nginx
server {
    listen 443 ssl;
    server_name your-domain.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://localhost:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

### Firewall

Restrict access by IP:

```bash
# Using iptables
sudo iptables -A INPUT -p tcp --dport 5000 -s YOUR_IP -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 5000 -j DROP
```

---

## Troubleshooting

### Server Won't Start

**Issue:** Port already in use
```bash
# Find process using port 5000
netstat -ano | findstr :5000  # Windows
lsof -i :5000                  # Linux/Mac

# Kill process or use different port
```

**Issue:** Module not found
```bash
# Reinstall dependencies
pip install -r requirements.txt
```

### API Errors

**Issue:** 404 errors
- Check API endpoint URL
- Ensure server is running
- Verify route in browser console

**Issue:** CORS errors
- Flask-CORS is installed and configured
- Check browser console for details

### UI Not Loading

**Issue:** Blank page
- Check browser console for errors
- Verify static files are served correctly
- Clear browser cache

---

## Development

### Adding New Features

1. **Add API Route** (`src/api/app.py`):
```python
@app.route('/api/new-feature', methods=['POST'])
def new_feature():
    data = request.get_json()
    # Your logic here
    return jsonify({'success': True, 'result': result})
```

2. **Create UI Page** (`src/web/templates/feature.html`):
```html
{% extends "base.html" %}
{% block content %}
  <!-- Your HTML here -->
{% endblock %}
```

3. **Add Navigation Link** (`src/web/templates/base.html`)

### File Structure

```
src/
├── api/
│   ├── __init__.py
│   └── app.py          # Flask application & API routes
└── web/
    ├── templates/      # HTML templates
    │   ├── base.html
    │   ├── index.html
    │   ├── campaigns.html
    │   └── ...
    └── static/         # CSS, JS, images
        ├── css/
        │   └── style.css
        └── js/
            └── app.js
```

---

## Support

For issues or questions:
- GitHub Issues: https://github.com/connsigliere/PAT/issues
- Documentation: Check README.md and other guides

---

**Remember: This tool is for AUTHORIZED penetration testing ONLY. Always obtain written permission before testing.**
