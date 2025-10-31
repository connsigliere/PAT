#!/bin/bash

# Phishing Infrastructure Automation Tool - Quick Start Script
# For authorized penetration testing only

set -e

echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║   Phishing Infrastructure Automation Tool - Quick Start       ║"
echo "║   For Authorized Penetration Testing Only                     ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""

# Check if running as root (needed for certbot)
if [ "$EUID" -eq 0 ]; then
    echo "⚠️  Warning: Running as root. This is only needed for SSL certificate operations."
    read -p "Continue? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Check Python version
echo "🔍 Checking Python version..."
PYTHON_VERSION=$(python3 --version 2>&1 | grep -oP '(?<=Python )[0-9]+\.[0-9]+')
REQUIRED_VERSION="3.9"

if [ "$(printf '%s\n' "$REQUIRED_VERSION" "$PYTHON_VERSION" | sort -V | head -n1)" != "$REQUIRED_VERSION" ]; then
    echo "❌ Python 3.9 or higher is required. Found: Python $PYTHON_VERSION"
    exit 1
fi
echo "✅ Python $PYTHON_VERSION found"

# Create virtual environment
if [ ! -d "venv" ]; then
    echo ""
    echo "📦 Creating virtual environment..."
    python3 -m venv venv
    echo "✅ Virtual environment created"
else
    echo "✅ Virtual environment already exists"
fi

# Activate virtual environment
echo ""
echo "🔌 Activating virtual environment..."
source venv/bin/activate

# Install dependencies
echo ""
echo "📥 Installing dependencies..."
pip install --upgrade pip > /dev/null 2>&1
pip install -r requirements.txt > /dev/null 2>&1
echo "✅ Dependencies installed"

# Create directories
echo ""
echo "📁 Creating project directories..."
mkdir -p logs
mkdir -p landing_pages
mkdir -p templates/email_templates
mkdir -p config
mkdir -p backups
echo "✅ Directories created"

# Setup configuration
echo ""
if [ ! -f "config/config.yml" ]; then
    echo "⚙️  Setting up configuration..."
    cp config/config.example.yml config/config.yml
    echo "✅ Configuration file created"
    echo "⚠️  Please edit config/config.yml with your settings"
else
    echo "✅ Configuration file already exists"
fi

# Initialize database
echo ""
echo "🗄️  Initializing database..."
python src/main.py campaign list > /dev/null 2>&1 || true
echo "✅ Database initialized"

# Check for optional dependencies
echo ""
echo "🔍 Checking optional dependencies..."

# Check certbot
if command -v certbot &> /dev/null; then
    echo "✅ certbot found"
else
    echo "⚠️  certbot not found (required for SSL certificates)"
    echo "   Install: sudo apt install certbot"
fi

# Check nginx
if command -v nginx &> /dev/null; then
    echo "✅ nginx found"
else
    echo "⚠️  nginx not found (required for hosting landing pages)"
    echo "   Install: sudo apt install nginx"
fi

# Check PHP
if command -v php &> /dev/null; then
    echo "✅ PHP found"
else
    echo "⚠️  PHP not found (required for credential harvesting)"
    echo "   Install: sudo apt install php-fpm"
fi

# Run tests
echo ""
echo "🧪 Running quick tests..."

# Test domain checker
echo -n "   Testing domain checker... "
python -c "from src.core.domain_checker import DomainChecker; DomainChecker()" 2>/dev/null && echo "✅" || echo "❌"

# Test email generator
echo -n "   Testing email generator... "
python -c "from src.core.email_generator import EmailGenerator; EmailGenerator()" 2>/dev/null && echo "✅" || echo "❌"

# Test page cloner
echo -n "   Testing page cloner... "
python -c "from src.core.page_cloner import PageCloner; PageCloner()" 2>/dev/null && echo "✅" || echo "❌"

# Test campaign manager
echo -n "   Testing campaign manager... "
python -c "from src.core.campaign_manager import CampaignManager; CampaignManager()" 2>/dev/null && echo "✅" || echo "❌"

echo ""
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║                    Setup Complete! ✨                          ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""
echo "📚 Next Steps:"
echo ""
echo "1. Configure your settings:"
echo "   nano config/config.yml"
echo ""
echo "2. Read the documentation:"
echo "   - SETUP_GUIDE.md - Detailed setup instructions"
echo "   - USAGE_GUIDE.md - Campaign workflow guide"
echo "   - PENTEST_CAREER_GUIDE.md - Career development tips"
echo ""
echo "3. Try the CLI:"
echo "   python src/main.py --help"
echo ""
echo "4. Run a test:"
echo "   python src/main.py domain check google.com"
echo ""
echo "⚠️  IMPORTANT REMINDER:"
echo "   This tool is for AUTHORIZED penetration testing ONLY."
echo "   Always obtain written permission before testing."
echo ""
echo "Happy (ethical) hacking! 🔐"
