"""
Phishing Infrastructure Automation Tool - Main Application
For authorized penetration testing only
"""

import sys
import click
from pathlib import Path
from loguru import logger
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
import yaml

# Import core modules
sys.path.insert(0, str(Path(__file__).parent))
from core.domain_checker import DomainChecker
from core.email_generator import EmailGenerator
from core.page_cloner import PageCloner
from core.ssl_manager import SSLManager
from core.email_sender import EmailSender, EmailConfig, EmailMessage
from core.campaign_manager import CampaignManager, Target

# Setup logging
logger.add("logs/app.log", rotation="100 MB", retention="30 days", level="INFO")
console = Console()


def load_config(config_path: str = "config/config.yml") -> dict:
    """Load configuration file"""
    try:
        with open(config_path, 'r') as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        logger.error(f"Configuration file not found: {config_path}")
        console.print(f"[red]Error: Configuration file not found: {config_path}[/red]")
        console.print("Please copy config.example.yml to config.yml and configure it.")
        sys.exit(1)


def display_banner():
    """Display application banner"""
    banner = """
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   Phishing Infrastructure Automation Tool                     ║
║   For Authorized Penetration Testing Only                     ║
║                                                               ║
║   [!] Unauthorized use is illegal and unethical               ║
║   [!] Always obtain written authorization                     ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
    """
    console.print(banner, style="bold cyan")


@click.group()
def cli():
    """Phishing Infrastructure Automation Tool"""
    display_banner()


@cli.group()
def campaign():
    """Campaign management commands"""
    pass


@campaign.command()
@click.option('--name', required=True, help='Campaign name')
@click.option('--description', required=True, help='Campaign description')
@click.option('--template', required=True, type=click.Choice(['it_support', 'hr_notification', 'executive_impersonation', 'document_share']))
@click.option('--domain', required=True, help='Target domain')
@click.option('--url', required=True, help='Phishing URL')
def create(name, description, template, domain, url):
    """Create a new campaign"""
    manager = CampaignManager()
    campaign = manager.create_campaign(
        name=name,
        description=description,
        template_type=template,
        target_domain=domain,
        phishing_url=url
    )

    console.print(f"\n[green]✓[/green] Campaign created successfully!")
    console.print(f"  ID: [cyan]{campaign.id}[/cyan]")
    console.print(f"  Name: {campaign.name}")
    console.print(f"  Template: {campaign.template_type}")


@campaign.command()
def list():
    """List all campaigns"""
    manager = CampaignManager()
    campaigns = manager.list_campaigns()

    if not campaigns:
        console.print("\n[yellow]No campaigns found.[/yellow]")
        return

    table = Table(title="Campaigns")
    table.add_column("ID", style="cyan")
    table.add_column("Name", style="white")
    table.add_column("Status", style="green")
    table.add_column("Targets", justify="right")
    table.add_column("Sent", justify="right")
    table.add_column("Opened", justify="right")
    table.add_column("Clicked", justify="right")

    for c in campaigns:
        table.add_row(
            c.id,
            c.name,
            c.status,
            str(c.targets_count),
            str(c.emails_sent),
            str(c.emails_opened),
            str(c.links_clicked)
        )

    console.print(table)


@campaign.command()
@click.argument('campaign_id')
def stats(campaign_id):
    """Show campaign statistics"""
    manager = CampaignManager()
    stats = manager.get_campaign_statistics(campaign_id)

    if not stats:
        console.print(f"[red]Campaign not found: {campaign_id}[/red]")
        return

    panel_content = f"""
[cyan]Campaign:[/cyan] {stats['name']}
[cyan]Status:[/cyan] {stats['status']}
[cyan]Duration:[/cyan] {stats['duration'] or 'N/A'}

[bold]Targets & Delivery:[/bold]
  Total Targets: {stats['targets']}
  Emails Sent: {stats['sent']}

[bold]Engagement Metrics:[/bold]
  Emails Opened: {stats['opened']} ({stats['open_rate']}%)
  Links Clicked: {stats['clicked']} ({stats['click_rate']}%)
  Credentials Captured: {stats['captured']} ({stats['capture_rate']}%)
    """

    console.print(Panel(panel_content, title=f"Campaign Statistics - {campaign_id}", border_style="cyan"))


@cli.group()
def domain():
    """Domain analysis commands"""
    pass


@domain.command()
@click.argument('domain_name')
def check(domain_name):
    """Check domain reputation and configuration"""
    checker = DomainChecker()

    console.print(f"\n[cyan]Analyzing domain:[/cyan] {domain_name}\n")

    with console.status("[bold cyan]Running checks..."):
        results = checker.check_all(domain_name)

    # Display results
    console.print(f"[bold]Reputation Score:[/bold] {results['reputation_score']}/100")

    table = Table(title="Domain Analysis Results")
    table.add_column("Check", style="cyan")
    table.add_column("Status", style="white")
    table.add_column("Details")

    # DNS
    dns_status = "✓" if results['dns']['has_records'] else "✗"
    table.add_row("DNS Records", dns_status, f"{len(results['dns']['A'])} A records")

    # WHOIS
    age = results['whois'].get('age_days', 'Unknown')
    table.add_row("Domain Age", "✓" if age != 'Unknown' else "✗", f"{age} days")

    # Blacklist
    bl_status = "✗" if results['blacklist']['listed'] else "✓"
    table.add_row("Blacklist Status", bl_status, f"Clean on {len(results['blacklist']['clean'])} lists")

    # Email
    email_status = "✓" if results['email_config']['configured_properly'] else "✗"
    table.add_row("Email Config", email_status, f"SPF: {bool(results['email_config']['spf'])}, DMARC: {bool(results['email_config']['dmarc'])}")

    # SSL
    ssl_status = "✓" if results['ssl']['has_ssl'] else "✗"
    table.add_row("SSL Certificate", ssl_status, results['ssl'].get('issuer', {}).get('organizationName', 'N/A') if results['ssl']['has_ssl'] else "None")

    console.print(table)

    if results['issues']:
        console.print("\n[yellow]Issues Found:[/yellow]")
        for issue in results['issues']:
            console.print(f"  • {issue}")


@cli.group()
def clone():
    """Landing page cloning commands"""
    pass


@clone.command()
@click.argument('url')
@click.option('--output', default='./landing_pages', help='Output directory')
@click.option('--webhook', help='Webhook URL for notifications')
def page(url, output, webhook):
    """Clone a webpage for phishing"""
    cloner = PageCloner(output_dir=output)

    console.print(f"\n[cyan]Cloning page:[/cyan] {url}\n")

    with console.status("[bold cyan]Cloning webpage..."):
        result = cloner.clone_page(
            target_url=url,
            harvest_method="form",
            include_assets=True,
            webhook_url=webhook
        )

    if result['success']:
        console.print("[green]✓[/green] Page cloned successfully!")
        console.print(f"  Directory: [cyan]{result['clone_directory']}[/cyan]")
        console.print(f"  HTML file: {result['html_file']}")
        console.print(f"  Credentials file: {result['credentials_file']}")
    else:
        console.print(f"[red]✗ Clone failed:[/red] {result['error']}")


@cli.group()
def email():
    """Email generation and sending commands"""
    pass


@email.command()
@click.option('--template', required=True, type=click.Choice(['it_support', 'hr_notification', 'executive_impersonation', 'document_share']))
@click.option('--name', required=True, help='Target name')
@click.option('--email-addr', required=True, help='Target email')
@click.option('--company', required=True, help='Target company')
@click.option('--url', required=True, help='Phishing URL')
@click.option('--output', default='./generated_email.html', help='Output file')
def generate(template, name, email_addr, company, url, output):
    """Generate phishing email from template"""
    generator = EmailGenerator()

    target_data = {
        "name": name,
        "email": email_addr,
        "company": company,
        "phishing_url": url
    }

    email_content = generator.generate_email(template, target_data, evasion_level="medium")

    # Save to file
    with open(output, 'w') as f:
        f.write(email_content['html_body'])

    console.print(f"\n[green]✓[/green] Email generated successfully!")
    console.print(f"  Subject: [cyan]{email_content['subject']}[/cyan]")
    console.print(f"  Output file: {output}")


@cli.group()
def ssl():
    """SSL certificate management commands"""
    pass


@ssl.command()
@click.argument('domain_name')
@click.option('--email', required=True, help='Email for Let\'s Encrypt')
@click.option('--method', default='standalone', type=click.Choice(['standalone', 'webroot', 'dns']))
def obtain(domain_name, email, method):
    """Obtain SSL certificate for domain"""
    manager = SSLManager(email=email)

    console.print(f"\n[cyan]Obtaining certificate for:[/cyan] {domain_name}\n")

    with console.status("[bold cyan]Requesting certificate..."):
        result = manager.obtain_certificate(domain_name, method=method)

    if result['success']:
        console.print("[green]✓[/green] Certificate obtained successfully!")
        console.print(f"  Certificate path: {result['certificate_info']['certificate_path']}")
    else:
        console.print(f"[red]✗ Failed:[/red] {result['error']}")


@ssl.command()
def list_certs():
    """List all SSL certificates"""
    manager = SSLManager(email="admin@example.com")
    certificates = manager.list_certificates()

    if not certificates:
        console.print("\n[yellow]No certificates found.[/yellow]")
        return

    table = Table(title="SSL Certificates")
    table.add_column("Name", style="cyan")
    table.add_column("Domains", style="white")
    table.add_column("Expiry")

    for cert in certificates:
        table.add_row(
            cert.get('name', 'N/A'),
            cert.get('domains', 'N/A'),
            cert.get('expiry', 'N/A')
        )

    console.print(table)


@cli.command()
def version():
    """Show version information"""
    console.print("\n[cyan]Phishing Infrastructure Automation Tool v1.0.0[/cyan]")
    console.print("For authorized penetration testing only\n")


if __name__ == "__main__":
    cli()
