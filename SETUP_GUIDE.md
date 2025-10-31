# Phishing Infrastructure Automation Tool - Setup Guide

## ⚠️ Legal Requirements

**BEFORE PROCEEDING:**
1. Obtain written authorization from the target organization
2. Define clear scope and boundaries
3. Ensure compliance with applicable laws
4. Document all agreements

**Unauthorized use is illegal.**

---

## Prerequisites

### System Requirements
- Linux server (Ubuntu 20.04+ recommended)
- Python 3.9 or higher
- Root/sudo access (for SSL certificates)
- Public IP address
- Domain name (for phishing infrastructure)

### Required Software
```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Python and dependencies
sudo apt install python3 python3-pip python3-venv -y

# Install certbot for SSL
sudo apt install certbot -y

# Install nginx (for hosting landing pages)
sudo apt install nginx -y

# Install PHP (for credential harvesting backend)
sudo apt install php-fpm -y
```

---

## Installation Steps

### 1. Clone the Repository
```bash
git clone https://github.com/yourusername/phishing-automation-tool.git
cd phishing-automation-tool
```

### 2. Create Virtual Environment
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Configure the Application
```bash
# Copy example configuration
cp config/config.example.yml config/config.yml

# Edit configuration
nano config/config.yml
```

**Required Configuration:**
- Database settings
- SMTP server credentials
- Domain configuration
- SSL email for Let's Encrypt
- API keys (VirusTotal, etc.) - optional

### 5. Initialize Database
```bash
python src/main.py campaign list  # This will create the database
```

---

## DNS Configuration

### Required DNS Records

For domain `phishing.example.com`:

```dns
# A Record - Point to your server IP
phishing.example.com.     A     YOUR_SERVER_IP

# MX Record - Mail server
phishing.example.com.     MX    10 mail.phishing.example.com.
mail.phishing.example.com. A    YOUR_SERVER_IP

# SPF Record - Email authentication
phishing.example.com.     TXT   "v=spf1 ip4:YOUR_SERVER_IP a mx ~all"

# DMARC Record - Email policy
_dmarc.phishing.example.com. TXT "v=DMARC1; p=quarantine; rua=mailto:dmarc@phishing.example.com"

# DKIM Record - Generate key first
default._domainkey.phishing.example.com. TXT "v=DKIM1; k=rsa; p=YOUR_PUBLIC_KEY"
```

### Generate DKIM Keys
```bash
# Install opendkim
sudo apt install opendkim-tools -y

# Generate keys
opendkim-genkey -s default -d phishing.example.com

# View public key
cat default.txt
# Add this to your DNS as shown above
```

---

## SSL Certificate Setup

### Obtain Certificate
```bash
# Using the tool
python src/main.py ssl obtain phishing.example.com --email admin@example.com

# Or manually with certbot
sudo certbot certonly --standalone -d phishing.example.com
```

### Configure Nginx
```bash
# Generate nginx config
python src/main.py ssl generate-config phishing.example.com

# Copy to nginx
sudo cp generated_nginx.conf /etc/nginx/sites-available/phishing.example.com
sudo ln -s /etc/nginx/sites-available/phishing.example.com /etc/nginx/sites-enabled/

# Test and reload
sudo nginx -t
sudo systemctl reload nginx
```

---

## Email Server Setup

### Option 1: Use Existing SMTP Service (Recommended for Testing)

Popular services:
- **SendGrid** - 100 emails/day free
- **Mailgun** - 5,000 emails/month free
- **Amazon SES** - Very cheap, requires verification

Update `config/config.yml` with your SMTP credentials.

### Option 2: Setup Own Mail Server

**Pros:** Full control, no rate limits
**Cons:** Complex, may get blacklisted

```bash
# Install Postfix
sudo apt install postfix -y

# Configure SPF, DKIM, DMARC as shown above

# Warm up IP gradually
# Days 1-3: 10 emails/day
# Days 4-7: 25 emails/day
# Week 2: 50 emails/day
# Week 3+: 100+ emails/day
```

---

## Firewall Configuration

```bash
# Allow HTTP/HTTPS
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# Allow SMTP (if running own mail server)
sudo ufw allow 25/tcp
sudo ufw allow 587/tcp

# Allow SSH (be careful!)
sudo ufw allow 22/tcp

# Enable firewall
sudo ufw enable
```

---

## Testing the Installation

### 1. Test Domain Checker
```bash
python src/main.py domain check google.com
```

### 2. Test Email Generation
```bash
python src/main.py email generate \
  --template it_support \
  --name "John Doe" \
  --email-addr "john@example.com" \
  --company "Acme Corp" \
  --url "https://phishing.example.com" \
  --output test_email.html
```

### 3. Test Page Cloning
```bash
python src/main.py clone page https://www.office.com
```

### 4. Create Test Campaign
```bash
python src/main.py campaign create \
  --name "Test Campaign" \
  --description "Testing setup" \
  --template it_support \
  --domain example.com \
  --url https://phishing.example.com
```

---

## Production Deployment

### 1. Use Process Manager (PM2 or systemd)

**Using systemd:**
```bash
# Create service file
sudo nano /etc/systemd/system/phishing-tool.service
```

```ini
[Unit]
Description=Phishing Automation Tool
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=/path/to/phishing-automation-tool
Environment="PATH=/path/to/phishing-automation-tool/venv/bin"
ExecStart=/path/to/phishing-automation-tool/venv/bin/python src/main.py
Restart=always

[Install]
WantedBy=multi-user.target
```

```bash
# Enable and start
sudo systemctl enable phishing-tool
sudo systemctl start phishing-tool
sudo systemctl status phishing-tool
```

### 2. Setup Logging

```bash
# Logs are in logs/ directory
tail -f logs/app.log
```

### 3. Setup Backups

```bash
# Backup database daily
crontab -e

# Add:
0 2 * * * cp /path/to/campaigns.db /path/to/backups/campaigns_$(date +\%Y\%m\%d).db
```

---

## Security Hardening

1. **Restrict Access**
   ```bash
   # Only allow specific IPs to access backend
   # Add to nginx config:
   allow YOUR_IP;
   deny all;
   ```

2. **Enable Encryption**
   - All credentials are encrypted by default
   - Keep encryption key secure
   - Never commit config.yml to git

3. **Monitoring**
   - Set up log monitoring
   - Configure alerts for suspicious activity
   - Review captured credentials regularly

4. **Cleanup**
   - Delete campaigns after engagement
   - Clear logs as per retention policy
   - Revoke SSL certificates when done

---

## Troubleshooting

### Issue: SSL Certificate Fails
```bash
# Check if port 80 is accessible
curl http://phishing.example.com

# Check certbot logs
sudo tail -f /var/log/letsencrypt/letsencrypt.log

# Try manual method
sudo certbot certonly --manual -d phishing.example.com
```

### Issue: Emails Not Sending
```bash
# Test SMTP connection
telnet smtp.example.com 587

# Check SPF/DKIM/DMARC
python src/main.py domain check phishing.example.com

# Check mail logs
tail -f /var/log/mail.log
```

### Issue: Landing Page Not Loading
```bash
# Check nginx status
sudo systemctl status nginx

# Check nginx error logs
sudo tail -f /var/log/nginx/error.log

# Test configuration
sudo nginx -t
```

---

## Next Steps

1. Read [USAGE_GUIDE.md](USAGE_GUIDE.md) for campaign workflows
2. Review [BEST_PRACTICES.md](BEST_PRACTICES.md)
3. Check [API_DOCUMENTATION.md](API_DOCUMENTATION.md) for automation

---

## Support

- Report issues: https://github.com/yourusername/phishing-automation-tool/issues
- Security concerns: security@example.com

**Remember: Use responsibly and legally!**
