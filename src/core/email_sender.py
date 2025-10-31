"""
Email Sender with SPF/DKIM Configuration
Handles email delivery with proper authentication
"""

import smtplib
import asyncio
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.image import MIMEImage
from email.utils import formataddr, make_msgid
from typing import Dict, List, Optional
from datetime import datetime, timedelta
import time
from pathlib import Path
from loguru import logger
import dkim
import dns.resolver
from dataclasses import dataclass
import aiosmtplib


@dataclass
class EmailConfig:
    """Email server configuration"""
    smtp_host: str
    smtp_port: int
    smtp_user: str
    smtp_password: str
    use_tls: bool = True
    from_email: str = None
    from_name: str = None


@dataclass
class EmailMessage:
    """Email message structure"""
    to_email: str
    to_name: str
    subject: str
    html_body: str
    text_body: str
    preheader: Optional[str] = None


class EmailSender:
    """Send phishing emails with proper authentication"""

    def __init__(
        self,
        config: EmailConfig,
        dkim_private_key_path: Optional[str] = None,
        rate_limit: int = 50,
        warmup_enabled: bool = False
    ):
        """
        Initialize the email sender

        Args:
            config: Email server configuration
            dkim_private_key_path: Path to DKIM private key
            rate_limit: Maximum emails per hour
            warmup_enabled: Enable gradual sending warmup
        """
        self.config = config
        self.rate_limit = rate_limit
        self.warmup_enabled = warmup_enabled

        # Load DKIM key if provided
        self.dkim_key = None
        if dkim_private_key_path:
            try:
                with open(dkim_private_key_path, 'rb') as f:
                    self.dkim_key = f.read()
                logger.info("DKIM key loaded")
            except Exception as e:
                logger.warning(f"Failed to load DKIM key: {e}")

        # Tracking
        self.sent_count = 0
        self.last_send_time = None

        # Warmup schedule
        self.warmup_schedule = [10, 20, 30, 40, 50]  # Emails per day
        self.current_warmup_day = 0

    def send_email(
        self,
        message: EmailMessage,
        track_clicks: bool = True,
        track_opens: bool = True
    ) -> Dict:
        """
        Send a single email

        Args:
            message: Email message to send
            track_clicks: Enable click tracking
            track_opens: Enable open tracking

        Returns:
            Dictionary with sending results
        """
        logger.info(f"Sending email to {message.to_email}")

        try:
            # Apply rate limiting
            self._apply_rate_limit()

            # Create MIME message
            mime_message = self._create_mime_message(message)

            # Add tracking if enabled
            if track_clicks:
                mime_message = self._add_click_tracking(mime_message, message)
            if track_opens:
                mime_message = self._add_open_tracking(mime_message)

            # Sign with DKIM if configured
            if self.dkim_key:
                mime_message = self._sign_dkim(mime_message)

            # Send via SMTP
            with smtplib.SMTP(self.config.smtp_host, self.config.smtp_port) as server:
                if self.config.use_tls:
                    server.starttls()

                server.login(self.config.smtp_user, self.config.smtp_password)

                server.send_message(mime_message)

            self.sent_count += 1
            self.last_send_time = datetime.now()

            logger.info(f"Email sent successfully to {message.to_email}")
            return {
                "success": True,
                "to": message.to_email,
                "timestamp": datetime.now().isoformat()
            }

        except Exception as e:
            logger.error(f"Failed to send email: {e}")
            return {
                "success": False,
                "to": message.to_email,
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }

    async def send_bulk_emails(
        self,
        messages: List[EmailMessage],
        delay_seconds: int = 5
    ) -> List[Dict]:
        """
        Send multiple emails with delays

        Args:
            messages: List of email messages
            delay_seconds: Delay between sends

        Returns:
            List of sending results
        """
        logger.info(f"Starting bulk send of {len(messages)} emails")

        results = []

        for i, message in enumerate(messages):
            result = self.send_email(message)
            results.append(result)

            # Add delay between sends
            if i < len(messages) - 1:
                logger.debug(f"Waiting {delay_seconds}s before next send...")
                await asyncio.sleep(delay_seconds)

        logger.info(f"Bulk send complete. Success: {sum(1 for r in results if r['success'])}/{len(results)}")
        return results

    def _create_mime_message(self, message: EmailMessage) -> MIMEMultipart:
        """Create MIME message from EmailMessage"""

        # Create multipart message
        mime_msg = MIMEMultipart('alternative')

        # Set headers
        mime_msg['Subject'] = message.subject
        mime_msg['From'] = formataddr((
            self.config.from_name or self.config.smtp_user,
            self.config.from_email or self.config.smtp_user
        ))
        mime_msg['To'] = formataddr((message.to_name, message.to_email))
        mime_msg['Date'] = datetime.now().strftime('%a, %d %b %Y %H:%M:%S %z')
        mime_msg['Message-ID'] = make_msgid()

        # Add preheader if provided
        if message.preheader:
            preheader_html = f'<div style="display:none;max-height:0px;overflow:hidden;">{message.preheader}</div>'
            message.html_body = preheader_html + message.html_body

        # Attach text and HTML versions
        part_text = MIMEText(message.text_body, 'plain', 'utf-8')
        part_html = MIMEText(message.html_body, 'html', 'utf-8')

        mime_msg.attach(part_text)
        mime_msg.attach(part_html)

        return mime_msg

    def _add_click_tracking(
        self,
        mime_message: MIMEMultipart,
        original_message: EmailMessage
    ) -> MIMEMultipart:
        """Add click tracking to links in email"""

        # Get HTML body
        for part in mime_message.walk():
            if part.get_content_type() == 'text/html':
                html_body = part.get_payload(decode=True).decode('utf-8')

                # Replace links with tracking URLs
                # In a real implementation, you'd replace URLs with tracking redirects
                # For now, this is a placeholder

                part.set_payload(html_body, 'utf-8')

        return mime_message

    def _add_open_tracking(self, mime_message: MIMEMultipart) -> MIMEMultipart:
        """Add open tracking pixel to email"""

        # Generate unique tracking ID
        tracking_id = make_msgid().strip('<>')

        # Add tracking pixel
        tracking_pixel = f'<img src="https://tracking.example.com/pixel/{tracking_id}" width="1" height="1" />'

        # Insert into HTML body
        for part in mime_message.walk():
            if part.get_content_type() == 'text/html':
                html_body = part.get_payload(decode=True).decode('utf-8')
                html_body = html_body.replace('</body>', f'{tracking_pixel}</body>')
                part.set_payload(html_body, 'utf-8')

        return mime_message

    def _sign_dkim(self, mime_message: MIMEMultipart) -> MIMEMultipart:
        """Sign email with DKIM"""

        if not self.dkim_key:
            return mime_message

        try:
            # Get message as bytes
            message_bytes = mime_message.as_bytes()

            # Sign with DKIM
            signature = dkim.sign(
                message_bytes,
                b'default',  # Selector
                self.config.from_email.split('@')[1].encode(),  # Domain
                self.dkim_key,
                include_headers=[b'From', b'To', b'Subject']
            )

            # Add DKIM signature to headers
            mime_message['DKIM-Signature'] = signature.decode().split(':', 1)[1].strip()

            logger.debug("DKIM signature added")

        except Exception as e:
            logger.error(f"DKIM signing failed: {e}")

        return mime_message

    def _apply_rate_limit(self):
        """Apply rate limiting between sends"""

        if self.warmup_enabled:
            # Apply warmup schedule
            daily_limit = self.warmup_schedule[min(self.current_warmup_day, len(self.warmup_schedule) - 1)]
            logger.debug(f"Warmup mode: Daily limit {daily_limit}")

        if self.last_send_time:
            # Calculate minimum delay
            min_delay = 3600 / self.rate_limit  # seconds between emails

            elapsed = (datetime.now() - self.last_send_time).total_seconds()
            if elapsed < min_delay:
                sleep_time = min_delay - elapsed
                logger.debug(f"Rate limiting: sleeping {sleep_time:.1f}s")
                time.sleep(sleep_time)

    def verify_dns_configuration(self, domain: str) -> Dict:
        """Verify SPF, DKIM, and DMARC DNS records"""

        logger.info(f"Verifying email DNS configuration for {domain}")

        results = {
            "domain": domain,
            "spf": {"configured": False, "record": None, "valid": False},
            "dkim": {"configured": False, "record": None},
            "dmarc": {"configured": False, "record": None, "valid": False},
            "mx": {"configured": False, "records": []}
        }

        resolver = dns.resolver.Resolver()

        # Check SPF
        try:
            txt_records = resolver.resolve(domain, 'TXT')
            for record in txt_records:
                txt = str(record)
                if 'v=spf1' in txt:
                    results["spf"]["configured"] = True
                    results["spf"]["record"] = txt

                    # Basic validation
                    if any(x in txt for x in ['include:', 'a:', 'mx:', 'ip4:', 'ip6:']):
                        results["spf"]["valid"] = True

                    break
        except Exception as e:
            logger.warning(f"SPF check failed: {e}")

        # Check DMARC
        try:
            dmarc_domain = f"_dmarc.{domain}"
            txt_records = resolver.resolve(dmarc_domain, 'TXT')
            for record in txt_records:
                txt = str(record)
                if 'v=DMARC1' in txt:
                    results["dmarc"]["configured"] = True
                    results["dmarc"]["record"] = txt

                    # Basic validation
                    if 'p=' in txt:
                        results["dmarc"]["valid"] = True

                    break
        except Exception as e:
            logger.warning(f"DMARC check failed: {e}")

        # Check DKIM (requires selector)
        try:
            dkim_domain = f"default._domainkey.{domain}"
            txt_records = resolver.resolve(dkim_domain, 'TXT')
            for record in txt_records:
                txt = str(record)
                if 'v=DKIM1' in txt or 'p=' in txt:
                    results["dkim"]["configured"] = True
                    results["dkim"]["record"] = txt
                    break
        except Exception as e:
            logger.debug(f"DKIM check failed (selector 'default'): {e}")

        # Check MX
        try:
            mx_records = resolver.resolve(domain, 'MX')
            results["mx"]["configured"] = True
            results["mx"]["records"] = [str(mx.exchange) for mx in mx_records]
        except Exception as e:
            logger.warning(f"MX check failed: {e}")

        # Overall status
        results["all_configured"] = all([
            results["spf"]["configured"],
            results["dmarc"]["configured"],
            results["mx"]["configured"]
        ])

        return results

    def generate_dns_records(self, domain: str, server_ip: str) -> Dict:
        """Generate recommended DNS records for email authentication"""

        records = {
            "spf": f'v=spf1 ip4:{server_ip} a mx ~all',
            "dmarc": f'v=DMARC1; p=quarantine; rua=mailto:dmarc@{domain}; pct=100',
            "mx": f'{domain}. IN MX 10 mail.{domain}.',
            "dkim_note": "DKIM record requires key generation. Run: opendkim-genkey -s default -d {domain}"
        }

        return records


if __name__ == "__main__":
    # Example usage
    config = EmailConfig(
        smtp_host="smtp.gmail.com",
        smtp_port=587,
        smtp_user="your-email@gmail.com",
        smtp_password="your-password",
        from_name="IT Support",
        from_email="support@example.com"
    )

    sender = EmailSender(config)

    # Verify DNS configuration
    dns_check = sender.verify_dns_configuration("example.com")
    print(f"DNS Configuration Check:")
    print(f"  SPF: {'✓' if dns_check['spf']['configured'] else '✗'}")
    print(f"  DKIM: {'✓' if dns_check['dkim']['configured'] else '✗'}")
    print(f"  DMARC: {'✓' if dns_check['dmarc']['configured'] else '✗'}")
    print(f"  MX: {'✓' if dns_check['mx']['configured'] else '✗'}")

    # Generate DNS records
    print("\nRecommended DNS Records:")
    records = sender.generate_dns_records("example.com", "192.168.1.1")
    for record_type, record_value in records.items():
        print(f"  {record_type.upper()}: {record_value}")
