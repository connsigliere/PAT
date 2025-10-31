"""
Email Template Generator with Anti-Detection Evasion
Generates phishing email templates with various evasion techniques
"""

import random
import string
from typing import Dict, List, Optional
from jinja2 import Environment, FileSystemLoader, Template
from faker import Faker
from datetime import datetime, timedelta
from loguru import logger
import html
import base64


class EmailGenerator:
    """Generate phishing email templates with evasion techniques"""

    def __init__(self, template_dir: str = "./templates/email_templates"):
        """
        Initialize the email generator

        Args:
            template_dir: Directory containing email templates
        """
        self.template_dir = template_dir
        self.faker = Faker()
        self.env = Environment(loader=FileSystemLoader(template_dir))

    def generate_email(
        self,
        template_type: str,
        target_data: Dict,
        evasion_level: str = "medium"
    ) -> Dict:
        """
        Generate a phishing email from a template

        Args:
            template_type: Type of template (it_support, hr, finance, etc.)
            target_data: Dictionary with target information (name, email, company, etc.)
            evasion_level: Level of evasion (low, medium, high)

        Returns:
            Dictionary with email subject, html body, and plain text body
        """
        logger.info(f"Generating {template_type} email with {evasion_level} evasion")

        # Load base template
        template_data = self._get_template_data(template_type)

        # Personalize with target data
        personalized = self._personalize_template(template_data, target_data)

        # Apply evasion techniques
        evaded = self._apply_evasion(personalized, evasion_level)

        # Generate both HTML and plain text versions
        result = {
            "subject": evaded["subject"],
            "html_body": evaded["html_body"],
            "text_body": self._html_to_text(evaded["html_body"]),
            "preheader": evaded.get("preheader", ""),
            "metadata": {
                "template_type": template_type,
                "evasion_level": evasion_level,
                "generated_at": datetime.now().isoformat()
            }
        }

        logger.info("Email generated successfully")
        return result

    def _get_template_data(self, template_type: str) -> Dict:
        """Get template data based on type"""

        templates = {
            "it_support": {
                "subject": "Action Required: Password Reset for {company} Account",
                "preheader": "Your account will be locked in 24 hours if no action is taken",
                "html_body": """
                <html>
                <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                    <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                        <h2>Security Alert</h2>
                        <p>Dear {name},</p>
                        <p>We have detected unusual activity on your {company} account. As a security precaution,
                        your password must be reset within the next 24 hours.</p>
                        <p><strong>Account Details:</strong></p>
                        <ul>
                            <li>Email: {email}</li>
                            <li>Last Login: {last_login}</li>
                            <li>IP Address: {ip_address}</li>
                        </ul>
                        <p>Please click the link below to reset your password immediately:</p>
                        <p style="text-align: center; margin: 30px 0;">
                            <a href="{phishing_url}" style="background-color: #0066cc; color: white; padding: 12px 30px;
                            text-decoration: none; border-radius: 5px; display: inline-block;">Reset Password Now</a>
                        </p>
                        <p>If you did not request this change, please contact IT support immediately.</p>
                        <p style="color: #666; font-size: 12px; margin-top: 40px; border-top: 1px solid #ddd; padding-top: 20px;">
                            This is an automated message from {company} IT Security.<br>
                            Please do not reply to this email.<br>
                            © {year} {company}. All rights reserved.
                        </p>
                    </div>
                </body>
                </html>
                """
            },

            "hr_notification": {
                "subject": "{company} HR: Important Benefits Update",
                "preheader": "Review your updated benefits package before the deadline",
                "html_body": """
                <html>
                <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                    <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                        <h2>Benefits Enrollment Update</h2>
                        <p>Dear {name},</p>
                        <p>The annual benefits enrollment period is now open. You must review and confirm
                        your selections by {deadline}.</p>
                        <p><strong>What's New This Year:</strong></p>
                        <ul>
                            <li>Enhanced dental coverage options</li>
                            <li>Flexible spending account increases</li>
                            <li>New wellness program incentives</li>
                        </ul>
                        <p>Please log in to the employee portal to review your options:</p>
                        <p style="text-align: center; margin: 30px 0;">
                            <a href="{phishing_url}" style="background-color: #28a745; color: white; padding: 12px 30px;
                            text-decoration: none; border-radius: 5px; display: inline-block;">Access Employee Portal</a>
                        </p>
                        <p>If you have questions, contact HR at {hr_phone}.</p>
                        <p style="color: #666; font-size: 12px; margin-top: 40px; border-top: 1px solid #ddd; padding-top: 20px;">
                            {company} Human Resources Department<br>
                            © {year} {company}. All rights reserved.
                        </p>
                    </div>
                </body>
                </html>
                """
            },

            "executive_impersonation": {
                "subject": "Urgent: Quick Request from {executive_name}",
                "preheader": "Need your help with a time-sensitive matter",
                "html_body": """
                <html>
                <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                    <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                        <p>{name},</p>
                        <p>I'm in meetings all day but need your help with something urgent.</p>
                        <p>We're finalizing a confidential acquisition and I need you to prepare wire transfer
                        information for our legal team. I'll send the details separately.</p>
                        <p>First, please verify your access to the finance portal by logging in here:</p>
                        <p style="text-align: center; margin: 30px 0;">
                            <a href="{phishing_url}" style="background-color: #dc3545; color: white; padding: 12px 30px;
                            text-decoration: none; border-radius: 5px; display: inline-block;">Verify Access</a>
                        </p>
                        <p>This is time-sensitive - please handle today.</p>
                        <p>Thanks,<br>{executive_name}<br>{executive_title}</p>
                        <p style="color: #999; font-size: 11px; margin-top: 30px;">
                            Sent from my iPhone
                        </p>
                    </div>
                </body>
                </html>
                """
            },

            "document_share": {
                "subject": "Document Shared with You: {document_name}",
                "preheader": "Click to view the shared document",
                "html_body": """
                <html>
                <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                    <div style="max-width: 600px; margin: 0 auto; padding: 20px; background-color: #f8f9fa;">
                        <div style="background-color: white; padding: 30px; border-radius: 8px;">
                            <h2 style="color: #4285f4;">Document Shared</h2>
                            <p>Hello {name},</p>
                            <p>{sender_name} has shared a document with you:</p>
                            <div style="background-color: #f1f3f4; padding: 15px; border-radius: 5px; margin: 20px 0;">
                                <strong>📄 {document_name}</strong><br>
                                <span style="color: #666; font-size: 14px;">Modified {modified_date}</span>
                            </div>
                            <p style="text-align: center; margin: 30px 0;">
                                <a href="{phishing_url}" style="background-color: #4285f4; color: white; padding: 12px 30px;
                                text-decoration: none; border-radius: 5px; display: inline-block;">Open Document</a>
                            </p>
                            <p style="color: #666; font-size: 12px;">
                                This link will expire in 7 days.
                            </p>
                        </div>
                        <p style="color: #666; font-size: 11px; text-align: center; margin-top: 20px;">
                            This email was intended for {email}
                        </p>
                    </div>
                </body>
                </html>
                """
            }
        }

        return templates.get(template_type, templates["it_support"])

    def _personalize_template(self, template_data: Dict, target_data: Dict) -> Dict:
        """Personalize template with target data"""

        # Generate realistic fake data if not provided
        defaults = {
            "name": target_data.get("name", self.faker.name()),
            "email": target_data.get("email", self.faker.email()),
            "company": target_data.get("company", self.faker.company()),
            "phishing_url": target_data.get("phishing_url", "https://example.com/login"),
            "last_login": (datetime.now() - timedelta(days=random.randint(1, 7))).strftime("%Y-%m-%d %H:%M"),
            "ip_address": self.faker.ipv4(),
            "deadline": (datetime.now() + timedelta(days=7)).strftime("%B %d, %Y"),
            "year": datetime.now().year,
            "executive_name": target_data.get("executive_name", "Michael Chen"),
            "executive_title": target_data.get("executive_title", "CEO"),
            "document_name": target_data.get("document_name", f"Q{random.randint(1,4)}_Report_{datetime.now().year}.pdf"),
            "sender_name": target_data.get("sender_name", self.faker.name()),
            "modified_date": (datetime.now() - timedelta(hours=random.randint(1, 48))).strftime("%B %d at %I:%M %p"),
            "hr_phone": target_data.get("hr_phone", self.faker.phone_number())
        }

        # Merge with provided data
        context = {**defaults, **target_data}

        # Render templates
        return {
            "subject": Template(template_data["subject"]).render(context),
            "html_body": Template(template_data["html_body"]).render(context),
            "preheader": Template(template_data.get("preheader", "")).render(context)
        }

    def _apply_evasion(self, template_data: Dict, evasion_level: str) -> Dict:
        """Apply anti-detection evasion techniques"""

        html_body = template_data["html_body"]

        if evasion_level in ["medium", "high"]:
            # Add random whitespace and comments
            html_body = self._add_noise_to_html(html_body)

            # Obfuscate URLs slightly
            html_body = self._obfuscate_urls(html_body, evasion_level)

        if evasion_level == "high":
            # Add invisible characters
            html_body = self._add_invisible_chars(html_body)

            # Encode parts of the content
            html_body = self._encode_content(html_body)

        template_data["html_body"] = html_body
        return template_data

    def _add_noise_to_html(self, html: str) -> str:
        """Add HTML comments and whitespace as noise"""
        comments = [
            "<!-- Layout Section -->",
            "<!-- Content Block -->",
            "<!-- Footer Area -->",
            "<!-- Responsive Design -->",
            "<!-- Email Client Compatibility -->",
        ]

        # Insert random comments
        for _ in range(random.randint(2, 5)):
            position = random.randint(0, len(html))
            comment = random.choice(comments)
            html = html[:position] + comment + html[position:]

        return html

    def _obfuscate_urls(self, html: str, level: str) -> str:
        """Lightly obfuscate URLs to avoid simple pattern matching"""

        if level == "high":
            # Use URL redirectors or shorteners (implement based on needs)
            # For now, just add harmless query parameters
            html = html.replace('href="http', 'href="http')  # Placeholder

        return html

    def _add_invisible_chars(self, html: str) -> str:
        """Add zero-width invisible characters to break pattern matching"""
        invisible_chars = ['\u200B', '\u200C', '\u200D']  # Zero-width space, non-joiner, joiner

        # Add invisible characters randomly in text content
        # This should be done carefully to not break HTML structure
        # For simplicity, adding between words

        return html  # Implement carefully based on needs

    def _encode_content(self, html: str) -> str:
        """Encode parts of the content (base64, hex, etc.)"""
        # This can be used for JavaScript-based rendering
        # Implement based on specific needs
        return html

    def _html_to_text(self, html: str) -> str:
        """Convert HTML to plain text for plain-text email version"""
        # Remove HTML tags
        import re
        text = re.sub('<[^<]+?>', '', html)

        # Decode HTML entities
        text = html.unescape(text)

        # Clean up whitespace
        text = re.sub(r'\n\s*\n', '\n\n', text)
        text = text.strip()

        return text

    def generate_subject_variations(self, base_subject: str, count: int = 5) -> List[str]:
        """Generate variations of a subject line for A/B testing"""
        variations = [base_subject]

        urgency_prefixes = ["URGENT: ", "ACTION REQUIRED: ", "IMPORTANT: ", "Time Sensitive: "]
        urgency_suffixes = [" - Action Needed", " - Response Required", " [Priority]"]

        for _ in range(count - 1):
            variant = base_subject

            # Randomly add urgency
            if random.choice([True, False]):
                if random.choice([True, False]):
                    variant = random.choice(urgency_prefixes) + variant
                else:
                    variant = variant + random.choice(urgency_suffixes)

            # Randomly add emojis (use sparingly)
            if random.random() < 0.3:
                emojis = ["🔔", "⚠️", "📧", "🔒", "⏰"]
                variant = random.choice(emojis) + " " + variant

            variations.append(variant)

        return list(set(variations))  # Remove duplicates


if __name__ == "__main__":
    # Example usage
    generator = EmailGenerator()

    target = {
        "name": "John Smith",
        "email": "john.smith@example.com",
        "company": "Acme Corp",
        "phishing_url": "https://secure-login-portal.com/auth"
    }

    email = generator.generate_email("it_support", target, evasion_level="medium")

    print(f"Subject: {email['subject']}\n")
    print(f"Preheader: {email['preheader']}\n")
    print("HTML Body:")
    print(email['html_body'][:500] + "...")
    print("\n\nSubject Variations:")
    for variation in generator.generate_subject_variations(email['subject']):
        print(f"  - {variation}")
