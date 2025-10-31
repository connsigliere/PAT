"""
Domain Reputation Checker Module
Checks domain reputation, age, blacklist status, and email deliverability
"""

import dns.resolver
import whois
import requests
import socket
from datetime import datetime
from typing import Dict, List, Optional
from loguru import logger
import tldextract


class DomainChecker:
    """Comprehensive domain reputation and configuration checker"""

    def __init__(self, api_keys: Optional[Dict[str, str]] = None):
        """
        Initialize the domain checker

        Args:
            api_keys: Dictionary of API keys for third-party services
                     (virustotal, abuseipdb, etc.)
        """
        self.api_keys = api_keys or {}
        self.resolver = dns.resolver.Resolver()

    def check_all(self, domain: str) -> Dict:
        """
        Run all checks on a domain

        Args:
            domain: Domain name to check

        Returns:
            Dictionary with all check results
        """
        logger.info(f"Starting comprehensive check for domain: {domain}")

        results = {
            "domain": domain,
            "timestamp": datetime.now().isoformat(),
            "dns": self.check_dns(domain),
            "whois": self.check_whois(domain),
            "blacklist": self.check_blacklists(domain),
            "email_config": self.check_email_configuration(domain),
            "ssl": self.check_ssl(domain),
            "reputation_score": 0,
            "issues": []
        }

        # Calculate overall reputation score (0-100)
        results["reputation_score"] = self._calculate_reputation_score(results)

        logger.info(f"Domain check complete. Score: {results['reputation_score']}/100")
        return results

    def check_dns(self, domain: str) -> Dict:
        """Check DNS records for the domain"""
        logger.debug(f"Checking DNS records for {domain}")

        dns_results = {
            "A": [],
            "AAAA": [],
            "MX": [],
            "TXT": [],
            "NS": [],
            "CNAME": [],
            "has_records": False
        }

        record_types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME']

        for record_type in record_types:
            try:
                answers = self.resolver.resolve(domain, record_type)
                dns_results[record_type] = [str(rdata) for rdata in answers]
                dns_results["has_records"] = True
            except dns.resolver.NoAnswer:
                pass
            except dns.resolver.NXDOMAIN:
                dns_results["error"] = "Domain does not exist"
                break
            except Exception as e:
                logger.warning(f"DNS lookup failed for {record_type}: {e}")

        return dns_results

    def check_whois(self, domain: str) -> Dict:
        """Check WHOIS information for the domain"""
        logger.debug(f"Checking WHOIS for {domain}")

        whois_data = {
            "registered": False,
            "creation_date": None,
            "expiration_date": None,
            "registrar": None,
            "age_days": None,
            "status": []
        }

        try:
            w = whois.whois(domain)

            if w.domain_name:
                whois_data["registered"] = True
                whois_data["registrar"] = w.registrar
                whois_data["status"] = w.status if isinstance(w.status, list) else [w.status]

                # Handle creation date
                creation = w.creation_date
                if isinstance(creation, list):
                    creation = creation[0]
                if creation:
                    whois_data["creation_date"] = creation.isoformat() if hasattr(creation, 'isoformat') else str(creation)
                    age = datetime.now() - creation
                    whois_data["age_days"] = age.days

                # Handle expiration date
                expiration = w.expiration_date
                if isinstance(expiration, list):
                    expiration = expiration[0]
                if expiration:
                    whois_data["expiration_date"] = expiration.isoformat() if hasattr(expiration, 'isoformat') else str(expiration)

        except Exception as e:
            logger.warning(f"WHOIS lookup failed: {e}")
            whois_data["error"] = str(e)

        return whois_data

    def check_blacklists(self, domain: str) -> Dict:
        """Check if domain is on common blacklists"""
        logger.debug(f"Checking blacklists for {domain}")

        blacklist_results = {
            "listed": False,
            "blacklists": [],
            "clean": []
        }

        # Common DNS-based blacklists
        dnsbl_lists = [
            "zen.spamhaus.org",
            "dnsbl.sorbs.net",
            "bl.spamcop.net",
            "b.barracudacentral.org"
        ]

        # Get IP address of domain
        try:
            ip_address = socket.gethostbyname(domain)
            reversed_ip = '.'.join(reversed(ip_address.split('.')))

            for dnsbl in dnsbl_lists:
                query = f"{reversed_ip}.{dnsbl}"
                try:
                    socket.gethostbyname(query)
                    blacklist_results["listed"] = True
                    blacklist_results["blacklists"].append(dnsbl)
                    logger.warning(f"Domain listed on {dnsbl}")
                except socket.gaierror:
                    # Not listed (which is good)
                    blacklist_results["clean"].append(dnsbl)

        except Exception as e:
            logger.error(f"Blacklist check failed: {e}")
            blacklist_results["error"] = str(e)

        return blacklist_results

    def check_email_configuration(self, domain: str) -> Dict:
        """Check email-related DNS configuration (SPF, DKIM, DMARC)"""
        logger.debug(f"Checking email configuration for {domain}")

        email_config = {
            "has_mx": False,
            "mx_records": [],
            "spf": None,
            "dmarc": None,
            "configured_properly": False
        }

        # Check MX records
        try:
            mx_records = self.resolver.resolve(domain, 'MX')
            email_config["has_mx"] = True
            email_config["mx_records"] = [str(mx.exchange) for mx in mx_records]
        except Exception as e:
            logger.warning(f"MX lookup failed: {e}")

        # Check SPF record
        try:
            txt_records = self.resolver.resolve(domain, 'TXT')
            for txt in txt_records:
                txt_string = str(txt)
                if 'v=spf1' in txt_string:
                    email_config["spf"] = txt_string
                    break
        except Exception as e:
            logger.warning(f"SPF lookup failed: {e}")

        # Check DMARC record
        try:
            dmarc_domain = f"_dmarc.{domain}"
            txt_records = self.resolver.resolve(dmarc_domain, 'TXT')
            for txt in txt_records:
                txt_string = str(txt)
                if 'v=DMARC1' in txt_string:
                    email_config["dmarc"] = txt_string
                    break
        except Exception as e:
            logger.warning(f"DMARC lookup failed: {e}")

        # Determine if properly configured
        email_config["configured_properly"] = (
            email_config["has_mx"] and
            email_config["spf"] is not None and
            email_config["dmarc"] is not None
        )

        return email_config

    def check_ssl(self, domain: str) -> Dict:
        """Check SSL certificate status"""
        logger.debug(f"Checking SSL for {domain}")

        ssl_info = {
            "has_ssl": False,
            "issuer": None,
            "valid_from": None,
            "valid_to": None,
            "days_remaining": None
        }

        try:
            import ssl
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    ssl_info["has_ssl"] = True
                    ssl_info["issuer"] = dict(x[0] for x in cert['issuer'])
                    ssl_info["valid_from"] = cert['notBefore']
                    ssl_info["valid_to"] = cert['notAfter']

                    # Calculate days remaining
                    valid_to = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_remaining = (valid_to - datetime.now()).days
                    ssl_info["days_remaining"] = days_remaining

        except Exception as e:
            logger.warning(f"SSL check failed: {e}")
            ssl_info["error"] = str(e)

        return ssl_info

    def check_virustotal(self, domain: str) -> Dict:
        """Check domain reputation on VirusTotal (requires API key)"""
        if not self.api_keys.get('virustotal'):
            return {"error": "VirusTotal API key not configured"}

        logger.debug(f"Checking VirusTotal for {domain}")

        try:
            url = f"https://www.virustotal.com/api/v3/domains/{domain}"
            headers = {"x-apikey": self.api_keys['virustotal']}
            response = requests.get(url, headers=headers, timeout=10)

            if response.status_code == 200:
                data = response.json()
                stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                return {
                    "malicious": stats.get('malicious', 0),
                    "suspicious": stats.get('suspicious', 0),
                    "harmless": stats.get('harmless', 0),
                    "undetected": stats.get('undetected', 0)
                }
            else:
                return {"error": f"API returned status {response.status_code}"}

        except Exception as e:
            logger.error(f"VirusTotal check failed: {e}")
            return {"error": str(e)}

    def _calculate_reputation_score(self, results: Dict) -> int:
        """Calculate overall reputation score (0-100)"""
        score = 100
        issues = []

        # DNS checks
        if not results["dns"].get("has_records"):
            score -= 30
            issues.append("No DNS records found")

        # Domain age
        whois_data = results["whois"]
        if whois_data.get("age_days"):
            if whois_data["age_days"] < 30:
                score -= 20
                issues.append("Domain is very new (< 30 days)")
            elif whois_data["age_days"] < 90:
                score -= 10
                issues.append("Domain is relatively new (< 90 days)")

        # Blacklist status
        if results["blacklist"].get("listed"):
            score -= 40
            issues.append("Domain is blacklisted")

        # Email configuration
        if not results["email_config"].get("has_mx"):
            score -= 5
            issues.append("No MX records configured")
        if not results["email_config"].get("spf"):
            score -= 5
            issues.append("No SPF record configured")
        if not results["email_config"].get("dmarc"):
            score -= 5
            issues.append("No DMARC record configured")

        # SSL certificate
        if not results["ssl"].get("has_ssl"):
            score -= 10
            issues.append("No SSL certificate")
        elif results["ssl"].get("days_remaining", 0) < 30:
            score -= 5
            issues.append("SSL certificate expires soon")

        results["issues"] = issues
        return max(0, min(100, score))


if __name__ == "__main__":
    # Example usage
    checker = DomainChecker()
    result = checker.check_all("google.com")

    print(f"\nDomain Reputation Report for {result['domain']}")
    print(f"{'='*60}")
    print(f"Reputation Score: {result['reputation_score']}/100")
    print(f"\nDNS Records: {'✓' if result['dns']['has_records'] else '✗'}")
    print(f"Domain Age: {result['whois'].get('age_days', 'Unknown')} days")
    print(f"Blacklisted: {'Yes' if result['blacklist']['listed'] else 'No'}")
    print(f"Email Configured: {'✓' if result['email_config']['configured_properly'] else '✗'}")
    print(f"SSL Certificate: {'✓' if result['ssl']['has_ssl'] else '✗'}")

    if result['issues']:
        print(f"\nIssues Found:")
        for issue in result['issues']:
            print(f"  - {issue}")
