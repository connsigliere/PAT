# Security Guide

## Overview

The Phishing Automation Tool now includes comprehensive security features to protect against unauthorized access and ensure safe operation during authorized penetration testing engagements.

---

## 🔐 Security Features

### 1. **User Authentication**
- Secure login system with username/password
- Password hashing using bcrypt (cost factor 12)
- Session management with automatic expiration
- "Remember me" option with extended sessions
- Account lockout after failed login attempts

### 2. **Session Security**
- Secure session cookies (HTTP-only, Secure, SameSite)
- Session timeout after 24 hours of inactivity
- Automatic cleanup of expired sessions
- Session invalidation on logout
- Protection against session fixation

### 3. **API Key Authentication**
- Unique API keys for programmatic access
- Token-based authentication for REST API
- Key regeneration capability
- Separate authentication from web sessions

### 4. **Rate Limiting**
- Login attempts: 5 per 15 minutes per IP/username
- API endpoints: 100 requests per hour per IP
- Domain checks: 10 per minute
- Campaign creation: 20 per hour

### 5. **CSRF Protection**
- CSRF tokens on all state-changing requests
- Token validation on POST/PUT/DELETE/PATCH
- Automatic token rotation
- Token expiration after 1 hour

### 6. **Security Headers**
- `X-Frame-Options: DENY` - Prevents clickjacking
- `X-Content-Type-Options: nosniff` - Prevents MIME sniffing
- `X-XSS-Protection: 1; mode=block` - XSS protection
- `Strict-Transport-Security` - Forces HTTPS
- `Content-Security-Policy` - Restricts resource loading
- `Referrer-Policy` - Controls referrer information

### 7. **Audit Logging**
- All authentication events logged
- User actions tracked
- Admin operations recorded
- IP addresses and timestamps captured
- Audit log accessible to admins only

### 8. **Password Security**
- Minimum 8 characters required
- bcrypt hashing with salt
- Password change functionality
- Current password verification required

### 9. **Role-Based Access Control**
- User and Admin roles
- Admin-only features (user management, audit logs)
- Permission checks on all sensitive operations

---

## 🚀 Initial Setup

### Step 1: Run Security Setup

```bash
# Install dependencies
pip install -r requirements.txt

# Run security setup
python setup_security.py
```

This will:
1. Create the authentication database
2. Create an initial admin user
3. Generate a Flask secret key
4. Provide security recommendations

### Step 2: Start Secure Web Server

```bash
python start_web_secure.py
```

### Step 3: First Login

1. Open http://localhost:5000/login
2. Login with admin credentials
3. **IMMEDIATELY** change your password
4. Review audit log in Admin Dashboard

---

## 👤 User Management

### Creating Users

**Via Web Interface (Admin):**
1. Login as admin
2. Go to Admin Dashboard
3. Click "Create User"
4. Enter user details
5. Choose whether to grant admin privileges
6. Save API key (shown only once)

**Via Command Line:**
```bash
python setup_security.py
```

### User Roles

**Regular User:**
- Access to all phishing tools
- Create and manage campaigns
- View own audit trail

**Administrator:**
- All user permissions
- Create/manage other users
- Access audit logs
- View system statistics
- Manage security settings

### Password Requirements

- Minimum length: 8 characters (12+ recommended)
- Must contain a mix of:
  - Uppercase letters
  - Lowercase letters
  - Numbers
  - Special characters (recommended)

### API Keys

Each user has a unique API key for programmatic access:

```bash
# Get your API key from Profile menu
# Use in API requests:
curl -H "X-API-Key: pat_your_key_here" http://localhost:5000/api/campaigns
```

**Regenerate API Key:**
1. Login to web interface
2. Click username → Profile
3. Click "Regenerate" next to API Key
4. Save new key immediately

---

## 🔒 Production Security

### 1. HTTPS Configuration

**NEVER run in production without HTTPS!**

Use a reverse proxy (Nginx recommended):

```nginx
server {
    listen 443 ssl http2;
    server_name pat.example.com;

    # SSL Certificates
    ssl_certificate /etc/letsencrypt/live/pat.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/pat.example.com/privkey.pem;

    # SSL Configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    # Security Headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    # Proxy to Flask
    location / {
        proxy_pass http://localhost:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Session cookie security
        proxy_cookie_path / "/; HTTPOnly; Secure; SameSite=Strict";
    }
}

# Redirect HTTP to HTTPS
server {
    listen 80;
    server_name pat.example.com;
    return 301 https://$server_name$request_uri;
}
```

### 2. Firewall Configuration

**UFW (Ubuntu):**
```bash
# Allow SSH (careful!)
sudo ufw allow 22/tcp

# Allow HTTPS only (HTTP redirects to HTTPS)
sudo ufw allow 443/tcp

# Block direct access to Flask port
sudo ufw deny 5000/tcp

# Enable firewall
sudo ufw enable
```

**iptables:**
```bash
# Allow established connections
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow SSH
iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# Allow HTTPS
iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# Allow loopback
iptables -A INPUT -i lo -j ACCEPT

# Drop everything else
iptables -P INPUT DROP
```

### 3. IP Whitelist

Restrict access to specific IPs:

**In Nginx:**
```nginx
# Allow specific IPs
allow 192.168.1.100;
allow 10.0.0.0/24;
deny all;
```

**In Flask (app_secure.py):**
```python
ALLOWED_IPS = ['192.168.1.100', '10.0.0.50']

@app.before_request
def check_ip():
    if request.remote_addr not in ALLOWED_IPS:
        abort(403)
```

### 4. Environment Variables

Never hardcode secrets! Use environment variables:

```bash
# .env file (add to .gitignore!)
FLASK_SECRET_KEY=your_secret_key_here
DATABASE_PASSWORD=your_db_password
SMTP_PASSWORD=your_smtp_password
```

Load in Python:
```python
from dotenv import load_dotenv
import os

load_dotenv()
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY')
```

### 5. Database Security

- Use strong database passwords
- Restrict database access to localhost
- Regular backups (encrypted)
- Separate database user with minimal privileges

### 6. Logging and Monitoring

**Monitor audit logs:**
```bash
# Web interface: Admin → Audit Log
# Or database directly:
sqlite3 auth.db "SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT 50"
```

**Application logs:**
```bash
tail -f logs/web_secure.log
```

**Set up alerts for:**
- Multiple failed login attempts
- New user creation
- Password changes
- API key regeneration
- Unusual access patterns

### 7. Regular Updates

```bash
# Update dependencies
pip install --upgrade -r requirements.txt

# Check for security advisories
pip-audit

# Monitor CVEs
# https://nvd.nist.gov/
```

---

## 🛡️ Security Best Practices

### For Administrators

1. **Strong Passwords**
   - Minimum 16 characters
   - Use password manager
   - Unique for this application
   - Change every 90 days

2. **API Key Management**
   - Rotate keys regularly
   - Never commit to git
   - Use environment variables
   - Separate keys per environment

3. **Access Control**
   - Principle of least privilege
   - Review user access quarterly
   - Disable inactive accounts
   - Log all admin actions

4. **Monitoring**
   - Review audit logs weekly
   - Set up automated alerts
   - Monitor for suspicious activity
   - Regular security audits

5. **Backups**
   - Daily automated backups
   - Encrypted at rest
   - Test restoration process
   - Off-site storage

### For Users

1. **Password Security**
   - Use unique, strong passwords
   - Never share credentials
   - Change if compromised
   - Use password manager

2. **Session Security**
   - Always logout when done
   - Don't use on public computers
   - Clear browser cache
   - Close all windows

3. **API Keys**
   - Keep API keys secret
   - Don't hardcode in scripts
   - Rotate if exposed
   - Use environment variables

4. **Reporting**
   - Report suspicious activity
   - Report security concerns
   - Document anomalies
   - Follow incident response procedures

---

## 🚨 Incident Response

### Suspected Unauthorized Access

1. **Immediate Actions:**
   ```bash
   # Stop the server
   pkill -f start_web_secure.py

   # Check audit log
   sqlite3 auth.db "SELECT * FROM audit_log WHERE action = 'login_failed' ORDER BY timestamp DESC LIMIT 100"

   # Review system logs
   tail -1000 logs/web_secure.log | grep -i "error\|warning\|security"
   ```

2. **Investigation:**
   - Review all login attempts
   - Check for new users
   - Verify admin actions
   - Analyze IP addresses
   - Check for data exfiltration

3. **Remediation:**
   - Change all passwords
   - Regenerate all API keys
   - Review and revoke sessions
   - Update firewall rules
   - Patch vulnerabilities

4. **Documentation:**
   - Timeline of events
   - Actions taken
   - Root cause analysis
   - Lessons learned
   - Preventive measures

### Password Compromise

1. Force password reset for affected users
2. Invalidate all sessions
3. Regenerate API keys
4. Review audit log for unauthorized actions
5. Notify affected parties

### API Key Exposure

1. Immediately regenerate the key
2. Review API usage logs
3. Check for unauthorized operations
4. Revoke compromised sessions
5. Investigate how exposure occurred

---

## 📝 Compliance & Legal

### Authorization Documentation

**ALWAYS maintain:**
- Written authorization from client
- Scope of engagement
- Approved target list
- Timeline and duration
- Rules of engagement
- Emergency contacts

### Audit Trail

The tool maintains comprehensive audit logs:
- User authentication events
- Campaign creation/modification
- Target additions
- System configuration changes
- Admin actions

**Retention:** 90 days minimum (configurable)

### Data Protection

- Credentials encrypted at rest
- Secure transmission (HTTPS only)
- Access controls enforced
- Audit logging enabled
- Data minimization practiced

---

## 🔍 Security Checklist

### Initial Setup
- [ ] Run security setup script
- [ ] Create strong admin password
- [ ] Save API key securely
- [ ] Configure HTTPS
- [ ] Set up firewall
- [ ] Enable audit logging
- [ ] Configure backups

### Production Deployment
- [ ] HTTPS enabled and enforced
- [ ] Firewall configured
- [ ] IP whitelist active
- [ ] Strong passwords enforced
- [ ] API keys rotated
- [ ] Monitoring configured
- [ ] Backups tested
- [ ] Incident response plan ready

### Regular Maintenance
- [ ] Review audit logs (weekly)
- [ ] Update dependencies (monthly)
- [ ] Rotate passwords (quarterly)
- [ ] Test backups (monthly)
- [ ] Security audit (annually)
- [ ] Penetration test (annually)

---

## 📚 Additional Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Flask Security Best Practices](https://flask.palletsprojects.com/en/latest/security/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [CIS Controls](https://www.cisecurity.org/controls)

---

## 🆘 Support

For security concerns:
- Review documentation thoroughly
- Check audit logs
- Open GitHub issue (for non-sensitive issues)
- Contact project maintainers privately for vulnerabilities

**Remember: This tool is for AUTHORIZED penetration testing ONLY!**

---

**Last Updated:** 2024
**Version:** 2.0.0
