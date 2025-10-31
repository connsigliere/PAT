"""
SSL Certificate Manager
Automates Let's Encrypt certificate generation and renewal
"""

import subprocess
import os
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime, timedelta
from loguru import logger
import json


class SSLManager:
    """Manage SSL certificates using Let's Encrypt (Certbot)"""

    def __init__(
        self,
        email: str,
        cert_dir: str = "/etc/letsencrypt",
        webroot: Optional[str] = None
    ):
        """
        Initialize SSL Manager

        Args:
            email: Email address for Let's Encrypt notifications
            cert_dir: Directory for certificate storage
            webroot: Webroot path for HTTP-01 challenge
        """
        self.email = email
        self.cert_dir = Path(cert_dir)
        self.webroot = webroot

        # Check if certbot is installed
        if not self._check_certbot():
            logger.error("Certbot not found. Please install certbot first.")

    def _check_certbot(self) -> bool:
        """Check if certbot is installed"""
        try:
            result = subprocess.run(
                ["certbot", "--version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.returncode == 0
        except FileNotFoundError:
            return False

    def obtain_certificate(
        self,
        domain: str,
        additional_domains: Optional[List[str]] = None,
        method: str = "standalone",
        port: int = 80
    ) -> Dict:
        """
        Obtain SSL certificate for domain(s)

        Args:
            domain: Primary domain name
            additional_domains: Additional domain names for certificate
            method: Challenge method (standalone, webroot, dns)
            port: Port for standalone method

        Returns:
            Dictionary with certificate information
        """
        logger.info(f"Obtaining SSL certificate for {domain}")

        domains = [domain]
        if additional_domains:
            domains.extend(additional_domains)

        # Build certbot command
        cmd = [
            "certbot", "certonly",
            "--non-interactive",
            "--agree-tos",
            "--email", self.email,
        ]

        # Add method-specific options
        if method == "standalone":
            cmd.extend([
                "--standalone",
                "--preferred-challenges", "http",
                f"--http-01-port={port}"
            ])
        elif method == "webroot":
            if not self.webroot:
                return {
                    "success": False,
                    "error": "Webroot path required for webroot method"
                }
            cmd.extend([
                "--webroot",
                "-w", self.webroot
            ])
        elif method == "dns":
            cmd.extend(["--manual", "--preferred-challenges", "dns"])

        # Add domains
        for d in domains:
            cmd.extend(["-d", d])

        try:
            # Execute certbot
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300
            )

            if result.returncode == 0:
                cert_info = self.get_certificate_info(domain)
                logger.info(f"Certificate obtained successfully for {domain}")
                return {
                    "success": True,
                    "domain": domain,
                    "certificate_info": cert_info,
                    "output": result.stdout
                }
            else:
                logger.error(f"Certificate request failed: {result.stderr}")
                return {
                    "success": False,
                    "error": result.stderr,
                    "output": result.stdout
                }

        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "error": "Certificate request timed out"
            }
        except Exception as e:
            logger.error(f"Failed to obtain certificate: {e}")
            return {
                "success": False,
                "error": str(e)
            }

    def renew_certificate(self, domain: Optional[str] = None) -> Dict:
        """
        Renew SSL certificate(s)

        Args:
            domain: Specific domain to renew, or None to renew all

        Returns:
            Dictionary with renewal results
        """
        logger.info(f"Renewing certificate{f' for {domain}' if domain else 's'}")

        cmd = ["certbot", "renew", "--non-interactive"]

        if domain:
            cmd.extend(["--cert-name", domain])

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300
            )

            if result.returncode == 0:
                logger.info("Certificate renewal successful")
                return {
                    "success": True,
                    "output": result.stdout
                }
            else:
                logger.warning(f"Certificate renewal had issues: {result.stderr}")
                return {
                    "success": False,
                    "error": result.stderr,
                    "output": result.stdout
                }

        except Exception as e:
            logger.error(f"Failed to renew certificate: {e}")
            return {
                "success": False,
                "error": str(e)
            }

    def get_certificate_info(self, domain: str) -> Dict:
        """Get information about a certificate"""

        cert_path = self.cert_dir / "live" / domain / "cert.pem"

        if not cert_path.exists():
            return {"error": "Certificate not found"}

        try:
            # Use openssl to get certificate details
            result = subprocess.run(
                ["openssl", "x509", "-in", str(cert_path), "-text", "-noout"],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode == 0:
                cert_text = result.stdout

                # Parse relevant information
                info = {
                    "domain": domain,
                    "certificate_path": str(cert_path),
                    "key_path": str(self.cert_dir / "live" / domain / "privkey.pem"),
                    "chain_path": str(self.cert_dir / "live" / domain / "chain.pem"),
                    "fullchain_path": str(self.cert_dir / "live" / domain / "fullchain.pem")
                }

                # Extract expiration date
                for line in cert_text.split('\n'):
                    if "Not After" in line:
                        info["expires"] = line.split(":", 1)[1].strip()

                return info
            else:
                return {"error": "Failed to read certificate"}

        except Exception as e:
            logger.error(f"Failed to get certificate info: {e}")
            return {"error": str(e)}

    def list_certificates(self) -> List[Dict]:
        """List all managed certificates"""

        try:
            result = subprocess.run(
                ["certbot", "certificates"],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode == 0:
                # Parse certbot output
                certificates = []
                cert_block = {}

                for line in result.stdout.split('\n'):
                    line = line.strip()

                    if line.startswith("Certificate Name:"):
                        if cert_block:
                            certificates.append(cert_block)
                        cert_block = {
                            "name": line.split(":", 1)[1].strip()
                        }
                    elif line.startswith("Domains:"):
                        cert_block["domains"] = line.split(":", 1)[1].strip()
                    elif line.startswith("Expiry Date:"):
                        cert_block["expiry"] = line.split(":", 1)[1].strip()
                    elif line.startswith("Certificate Path:"):
                        cert_block["path"] = line.split(":", 1)[1].strip()

                if cert_block:
                    certificates.append(cert_block)

                return certificates
            else:
                logger.error("Failed to list certificates")
                return []

        except Exception as e:
            logger.error(f"Failed to list certificates: {e}")
            return []

    def check_renewal_needed(self, domain: str, days_before: int = 30) -> bool:
        """
        Check if certificate needs renewal

        Args:
            domain: Domain name to check
            days_before: Days before expiry to consider renewal needed

        Returns:
            True if renewal needed, False otherwise
        """
        cert_info = self.get_certificate_info(domain)

        if "error" in cert_info:
            return False

        try:
            # Parse expiration date
            expires_str = cert_info.get("expires", "")
            # This would need proper date parsing based on format
            # For now, returning False as placeholder
            return False

        except Exception as e:
            logger.error(f"Failed to check renewal: {e}")
            return False

    def revoke_certificate(self, domain: str) -> Dict:
        """Revoke a certificate"""

        logger.info(f"Revoking certificate for {domain}")

        cmd = [
            "certbot", "revoke",
            "--non-interactive",
            "--cert-name", domain
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )

            if result.returncode == 0:
                logger.info(f"Certificate revoked for {domain}")
                return {
                    "success": True,
                    "output": result.stdout
                }
            else:
                return {
                    "success": False,
                    "error": result.stderr
                }

        except Exception as e:
            logger.error(f"Failed to revoke certificate: {e}")
            return {
                "success": False,
                "error": str(e)
            }

    def setup_auto_renewal(self) -> Dict:
        """Setup automatic certificate renewal via cron"""

        logger.info("Setting up automatic certificate renewal")

        # Create renewal script
        script_content = f"""#!/bin/bash
# Auto-renewal script for SSL certificates
# Run this via cron: 0 0 * * * /path/to/this/script.sh

certbot renew --quiet --post-hook "systemctl reload nginx"

# Log the renewal attempt
echo "$(date): Certificate renewal check completed" >> /var/log/certbot-renewal.log
"""

        script_path = Path("/usr/local/bin/certbot-renew.sh")

        try:
            with open(script_path, "w") as f:
                f.write(script_content)

            # Make executable
            os.chmod(script_path, 0o755)

            logger.info(f"Renewal script created: {script_path}")
            logger.info("Add to crontab: 0 0 * * * /usr/local/bin/certbot-renew.sh")

            return {
                "success": True,
                "script_path": str(script_path),
                "crontab_entry": "0 0 * * * /usr/local/bin/certbot-renew.sh"
            }

        except Exception as e:
            logger.error(f"Failed to setup auto-renewal: {e}")
            return {
                "success": False,
                "error": str(e)
            }

    def generate_nginx_config(self, domain: str, webroot: str = "/var/www/html") -> str:
        """Generate Nginx configuration for SSL"""

        cert_path = self.cert_dir / "live" / domain

        config = f"""
# Nginx SSL Configuration for {domain}
# Generated by Phishing Automation Tool

server {{
    listen 80;
    server_name {domain};

    # Redirect HTTP to HTTPS
    return 301 https://$server_name$request_uri;
}}

server {{
    listen 443 ssl http2;
    server_name {domain};

    # SSL Configuration
    ssl_certificate {cert_path}/fullchain.pem;
    ssl_certificate_key {cert_path}/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    # Security Headers
    add_header Strict-Transport-Security "max-age=31536000" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;

    # Root directory
    root {webroot};
    index index.html index.php;

    # PHP support (if needed)
    location ~ \\.php$ {{
        fastcgi_pass unix:/var/run/php/php-fpm.sock;
        fastcgi_index index.php;
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
    }}

    # Access logs
    access_log /var/log/nginx/{domain}_access.log;
    error_log /var/log/nginx/{domain}_error.log;
}}
"""

        return config


if __name__ == "__main__":
    # Example usage
    manager = SSLManager(email="admin@example.com")

    # List existing certificates
    print("Existing certificates:")
    certs = manager.list_certificates()
    for cert in certs:
        print(f"  - {cert.get('name')}: {cert.get('domains')}")

    # Generate Nginx config
    print("\nNginx configuration:")
    print(manager.generate_nginx_config("phishing.example.com"))
