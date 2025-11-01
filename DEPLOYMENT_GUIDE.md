# Deployment Guide - Python 3.12 Ready

## Overview

This guide will help you deploy the Phishing Automation Tool in various environments with Python 3.12 compatibility guaranteed.

---

## 🐍 Python 3.12 Compatibility

**Status:** ✅ Fully Compatible

The project has been optimized for Python 3.12 with all dependencies tested and verified.

### Supported Python Versions
- ✅ **Python 3.12** (Recommended)
- ✅ Python 3.11 (Compatible)
- ✅ Python 3.10 (Compatible)
- ✅ Python 3.9 (Minimum)

### Python 3.13 Note
⚠️ Python 3.13 is very new and some dependencies may not have wheels available yet. Use Python 3.12 for best results.

---

## 🚀 Quick Start (Local)

### Step 1: Check Your Environment

```bash
# Check Python version
python --version
# Should show Python 3.12.x (3.9+ supported)

# Run environment check
python check_environment.py
```

### Step 2: Install Dependencies

```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate

# Install dependencies
pip install --upgrade pip
pip install -r requirements.txt
```

### Step 3: Configure Security

```bash
# Run security setup (first time only)
python setup_security.py

# This will:
# - Create authentication database
# - Create admin user
# - Generate secret keys
```

### Step 4: Start the Application

```bash
# With authentication (recommended)
python start_web_secure.py

# Without authentication (development only)
python start_web.py
```

### Step 5: Access the Application

Open your browser:
- **Secure:** http://localhost:5000/login
- **Open:** http://localhost:5000

---

## 🐳 Docker Deployment (Easiest)

### Prerequisites
- Docker 20.10+
- Docker Compose 1.29+

### Quick Deploy

```bash
# Build and start
docker-compose up -d

# View logs
docker-compose logs -f

# Stop
docker-compose down
```

### First-Time Setup

```bash
# Start container
docker-compose up -d

# Run security setup inside container
docker exec -it phishing-automation-tool python setup_security.py

# Restart container
docker-compose restart
```

### Access Application

http://localhost:5000/login

### Docker Management

```bash
# View status
docker-compose ps

# View logs
docker-compose logs -f phishing-tool

# Restart
docker-compose restart

# Stop
docker-compose stop

# Remove (keeps volumes)
docker-compose down

# Remove everything (including volumes)
docker-compose down -v

# Rebuild after code changes
docker-compose up -d --build
```

---

## 🌐 Production Deployment

### Option 1: Ubuntu/Debian Server

#### Step 1: Prepare Server

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Python 3.12
sudo apt install software-properties-common -y
sudo add-apt-repository ppa:deadsnakes/ppa -y
sudo apt update
sudo apt install python3.12 python3.12-venv python3.12-dev -y

# Install system dependencies
sudo apt install build-essential libssl-dev libffi-dev \
    python3-pip nginx certbot python3-certbot-nginx -y
```

#### Step 2: Create Deployment User

```bash
# Create user
sudo useradd -m -s /bin/bash phishing
sudo usermod -aG sudo phishing

# Switch to user
sudo su - phishing
```

#### Step 3: Deploy Application

```bash
# Clone repository
cd ~
git clone https://github.com/connsigliere/PAT.git
cd PAT

# Create virtual environment with Python 3.12
python3.12 -m venv venv
source venv/bin/activate

# Install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# Run environment check
python check_environment.py

# Setup security
python setup_security.py

# Test application
python start_web_secure.py
# Press Ctrl+C to stop
```

#### Step 4: Create Systemd Service

```bash
# Create service file
sudo nano /etc/systemd/system/phishing-tool.service
```

Add this content:

```ini
[Unit]
Description=Phishing Automation Tool
After=network.target

[Service]
Type=simple
User=phishing
WorkingDirectory=/home/phishing/PAT
Environment="PATH=/home/phishing/PAT/venv/bin"
Environment="PYTHONUNBUFFERED=1"
ExecStart=/home/phishing/PAT/venv/bin/python start_web_secure.py
Restart=always
RestartSec=10

# Security
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/home/phishing/PAT/logs /home/phishing/PAT

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
# Reload systemd
sudo systemctl daemon-reload

# Enable service
sudo systemctl enable phishing-tool

# Start service
sudo systemctl start phishing-tool

# Check status
sudo systemctl status phishing-tool

# View logs
sudo journalctl -u phishing-tool -f
```

#### Step 5: Configure Nginx Reverse Proxy

```bash
# Create Nginx configuration
sudo nano /etc/nginx/sites-available/phishing-tool
```

Add this content:

```nginx
# HTTP to HTTPS redirect
server {
    listen 80;
    server_name your-domain.com;
    return 301 https://$server_name$request_uri;
}

# HTTPS server
server {
    listen 443 ssl http2;
    server_name your-domain.com;

    # SSL Configuration
    ssl_certificate /etc/letsencrypt/live/your-domain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/your-domain.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    # Security Headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;

    # Proxy to Flask
    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }

    # Access logs
    access_log /var/log/nginx/phishing-tool-access.log;
    error_log /var/log/nginx/phishing-tool-error.log;
}
```

Enable and test:

```bash
# Enable site
sudo ln -s /etc/nginx/sites-available/phishing-tool /etc/nginx/sites-enabled/

# Test configuration
sudo nginx -t

# Reload Nginx
sudo systemctl reload nginx
```

#### Step 6: Obtain SSL Certificate

```bash
# Get Let's Encrypt certificate
sudo certbot --nginx -d your-domain.com

# Test auto-renewal
sudo certbot renew --dry-run
```

#### Step 7: Configure Firewall

```bash
# Allow SSH (careful!)
sudo ufw allow 22/tcp

# Allow HTTP and HTTPS
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# Deny direct access to Flask port
sudo ufw deny 5000/tcp

# Enable firewall
sudo ufw enable

# Check status
sudo ufw status
```

---

## 🔧 Windows Server Deployment

### Prerequisites
- Windows Server 2019/2022
- Python 3.12 installed
- IIS or Apache (optional)

### Step 1: Install Python 3.12

1. Download Python 3.12 from https://www.python.org/downloads/
2. Run installer with "Add Python to PATH" checked
3. Verify: `python --version`

### Step 2: Deploy Application

```powershell
# Clone repository
cd C:\
git clone https://github.com/connsigliere/PAT.git
cd PAT

# Create virtual environment
python -m venv venv
venv\Scripts\activate

# Install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# Setup security
python setup_security.py
```

### Step 3: Create Windows Service

Use NSSM (Non-Sucking Service Manager):

```powershell
# Download NSSM
# https://nssm.cc/download

# Install service
nssm install PhishingTool "C:\PAT\venv\Scripts\python.exe" "C:\PAT\start_web_secure.py"

# Set working directory
nssm set PhishingTool AppDirectory "C:\PAT"

# Start service
nssm start PhishingTool

# Check status
nssm status PhishingTool
```

### Step 4: Configure IIS Reverse Proxy (Optional)

1. Install URL Rewrite and ARR modules
2. Configure reverse proxy to localhost:5000
3. Set up SSL certificate

---

## ☁️ Cloud Deployment

### AWS EC2

```bash
# Launch EC2 instance (Ubuntu 22.04 LTS)
# t3.medium recommended (2 vCPU, 4GB RAM)

# SSH into instance
ssh -i your-key.pem ubuntu@your-ec2-ip

# Follow Ubuntu deployment steps above

# Configure Security Group:
# - Allow inbound: 22 (SSH), 80 (HTTP), 443 (HTTPS)
# - Deny: 5000 (Flask port)
```

### Google Cloud Platform

```bash
# Create VM instance
gcloud compute instances create phishing-tool \
    --machine-type=e2-medium \
    --image-family=ubuntu-2204-lts \
    --image-project=ubuntu-os-cloud

# SSH into instance
gcloud compute ssh phishing-tool

# Follow Ubuntu deployment steps above

# Configure firewall
gcloud compute firewall-rules create allow-http-https \
    --allow tcp:80,tcp:443
```

### Azure VM

```bash
# Create VM (Ubuntu 22.04)
az vm create \
    --resource-group YourResourceGroup \
    --name phishing-tool \
    --image UbuntuLTS \
    --size Standard_B2s

# SSH into VM
ssh azureuser@your-vm-ip

# Follow Ubuntu deployment steps above

# Configure NSG
az network nsg rule create \
    --resource-group YourResourceGroup \
    --nsg-name YourNSG \
    --name AllowHTTPHTTPS \
    --priority 100 \
    --destination-port-ranges 80 443
```

### DigitalOcean Droplet

```bash
# Create droplet (Ubuntu 22.04)
# $12/month plan recommended

# SSH into droplet
ssh root@your-droplet-ip

# Follow Ubuntu deployment steps above
```

---

## 📦 Alternative Deployment Methods

### Using Gunicorn (Production WSGI Server)

```bash
# Install gunicorn
pip install gunicorn

# Create gunicorn config
nano gunicorn_config.py
```

```python
# gunicorn_config.py
bind = "0.0.0.0:5000"
workers = 4
worker_class = "sync"
timeout = 120
keepalive = 5
errorlog = "logs/gunicorn-error.log"
accesslog = "logs/gunicorn-access.log"
loglevel = "info"
```

Run with gunicorn:

```bash
gunicorn -c gunicorn_config.py "src.api.app_secure:create_app()"
```

### Using uWSGI

```bash
# Install uwsgi
pip install uwsgi

# Create uwsgi config
nano uwsgi.ini
```

```ini
[uwsgi]
module = src.api.app_secure:create_app()
callable = app
master = true
processes = 4
socket = /tmp/phishing-tool.sock
chmod-socket = 660
vacuum = true
die-on-term = true
```

Run with uwsgi:

```bash
uwsgi --ini uwsgi.ini
```

---

## 🔍 Health Checks & Monitoring

### Health Check Endpoint

```bash
# Check application health
curl http://localhost:5000/api/health

# Response:
# {
#   "status": "healthy",
#   "version": "2.0.0",
#   "authentication": "enabled"
# }
```

### Monitoring with Systemd

```bash
# View logs
sudo journalctl -u phishing-tool -f

# Check status
sudo systemctl status phishing-tool

# Restart if needed
sudo systemctl restart phishing-tool
```

### Application Logs

```bash
# View application logs
tail -f logs/web_secure.log

# View all logs
ls -lh logs/
```

---

## 🔒 Security Hardening

### 1. Firewall Configuration

```bash
# UFW (Ubuntu)
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp  # SSH
sudo ufw allow 80/tcp  # HTTP
sudo ufw allow 443/tcp # HTTPS
sudo ufw enable

# Check status
sudo ufw status verbose
```

### 2. Fail2Ban (Brute Force Protection)

```bash
# Install
sudo apt install fail2ban -y

# Create jail for phishing tool
sudo nano /etc/fail2ban/jail.local
```

```ini
[phishing-tool]
enabled = true
port = 80,443
filter = phishing-tool
logpath = /home/phishing/PAT/logs/web_secure.log
maxretry = 5
bantime = 3600
```

### 3. Automatic Updates

```bash
# Install unattended-upgrades
sudo apt install unattended-upgrades -y

# Configure
sudo dpkg-reconfigure -plow unattended-upgrades
```

### 4. Database Backups

```bash
# Create backup script
nano ~/backup_databases.sh
```

```bash
#!/bin/bash
BACKUP_DIR="/home/phishing/backups"
DATE=$(date +%Y%m%d_%H%M%S)

mkdir -p $BACKUP_DIR

# Backup databases
cp ~/PAT/auth.db $BACKUP_DIR/auth_$DATE.db
cp ~/PAT/campaigns.db $BACKUP_DIR/campaigns_$DATE.db

# Keep only last 30 days
find $BACKUP_DIR -name "*.db" -mtime +30 -delete

echo "Backup completed: $DATE"
```

```bash
# Make executable
chmod +x ~/backup_databases.sh

# Add to crontab (daily at 2 AM)
crontab -e
# Add: 0 2 * * * /home/phishing/backup_databases.sh
```

---

## 📊 Performance Tuning

### Optimize Flask

```python
# In app_secure.py or app.py
app.config['JSON_SORT_KEYS'] = False
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 31536000
```

### Nginx Optimization

```nginx
# Add to nginx configuration
client_max_body_size 10M;
gzip on;
gzip_types text/plain text/css application/json application/javascript;

# Caching
location /static/ {
    expires 1y;
    add_header Cache-Control "public, immutable";
}
```

### Database Optimization

```bash
# Regular database optimization
sqlite3 campaigns.db "VACUUM;"
sqlite3 auth.db "VACUUM;"
```

---

## 🐛 Troubleshooting

### Application Won't Start

```bash
# Check Python version
python --version

# Check environment
python check_environment.py

# Check logs
tail -f logs/web_secure.log

# Check service status
sudo systemctl status phishing-tool
```

### Dependencies Issue

```bash
# Reinstall all dependencies
pip install --force-reinstall -r requirements.txt

# Or recreate virtual environment
deactivate
rm -rf venv
python3.12 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Port Already in Use

```bash
# Find process using port 5000
# Linux:
sudo lsof -i :5000
# Windows:
netstat -ano | findstr :5000

# Kill process
sudo kill -9 <PID>
```

### Permission Errors

```bash
# Fix permissions
sudo chown -R phishing:phishing /home/phishing/PAT
chmod 755 /home/phishing/PAT
chmod 644 /home/phishing/PAT/*.py
```

---

## 📚 Post-Deployment Checklist

- [ ] Python 3.12 installed and verified
- [ ] All dependencies installed
- [ ] Security setup completed
- [ ] Admin user created
- [ ] HTTPS/SSL certificate configured
- [ ] Firewall rules set up
- [ ] Service/daemon configured
- [ ] Reverse proxy (Nginx) configured
- [ ] Backups automated
- [ ] Logs rotating
- [ ] Health checks working
- [ ] Monitoring set up
- [ ] Documentation reviewed
- [ ] Initial password changed
- [ ] API keys secured

---

## 🆘 Support & Resources

- **Environment Check**: `python check_environment.py`
- **Documentation**: README.md, SECURITY_GUIDE.md, WEB_INTERFACE_GUIDE.md
- **GitHub Issues**: https://github.com/connsigliere/PAT/issues
- **Python 3.12 Docs**: https://docs.python.org/3.12/

---

## 📝 Version Info

- **Application Version**: 2.0.0
- **Python Version**: 3.12.4 (Recommended)
- **Last Updated**: 2024

**Remember: This tool is for AUTHORIZED penetration testing ONLY!**
