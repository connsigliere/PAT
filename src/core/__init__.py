"""
Core modules for phishing infrastructure automation
"""

from .domain_checker import DomainChecker
from .email_generator import EmailGenerator
from .page_cloner import PageCloner
from .ssl_manager import SSLManager
from .email_sender import EmailSender, EmailConfig, EmailMessage
from .campaign_manager import CampaignManager, Campaign, Target

__all__ = [
    'DomainChecker',
    'EmailGenerator',
    'PageCloner',
    'SSLManager',
    'EmailSender',
    'EmailConfig',
    'EmailMessage',
    'CampaignManager',
    'Campaign',
    'Target'
]
