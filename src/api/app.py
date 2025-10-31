"""
Flask Web Application - REST API for Phishing Automation Tool
"""

from flask import Flask, render_template, jsonify, request, send_from_directory
from flask_cors import CORS
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.domain_checker import DomainChecker
from core.email_generator import EmailGenerator
from core.page_cloner import PageCloner
from core.ssl_manager import SSLManager
from core.email_sender import EmailSender, EmailConfig, EmailMessage
from core.campaign_manager import CampaignManager, Target
from loguru import logger


def create_app(config=None):
    """Create and configure Flask application"""

    app = Flask(__name__,
                template_folder='../web/templates',
                static_folder='../web/static')

    # Enable CORS
    CORS(app)

    # Configuration
    app.config['SECRET_KEY'] = 'change-this-in-production'
    app.config['JSON_SORT_KEYS'] = False

    if config:
        app.config.update(config)

    # Initialize managers
    domain_checker = DomainChecker()
    email_generator = EmailGenerator()
    page_cloner = PageCloner()
    campaign_manager = CampaignManager()


    # ============= WEB ROUTES =============

    @app.route('/')
    def index():
        """Main dashboard"""
        return render_template('index.html')

    @app.route('/campaigns')
    def campaigns_page():
        """Campaign management page"""
        return render_template('campaigns.html')

    @app.route('/domain-checker')
    def domain_checker_page():
        """Domain checker page"""
        return render_template('domain_checker.html')

    @app.route('/email-generator')
    def email_generator_page():
        """Email generator page"""
        return render_template('email_generator.html')

    @app.route('/page-cloner')
    def page_cloner_page():
        """Page cloner page"""
        return render_template('page_cloner.html')

    @app.route('/ssl-manager')
    def ssl_manager_page():
        """SSL manager page"""
        return render_template('ssl_manager.html')


    # ============= API ROUTES =============

    # Dashboard API
    @app.route('/api/dashboard/stats')
    def dashboard_stats():
        """Get dashboard statistics"""
        try:
            campaigns = campaign_manager.list_campaigns()

            total_campaigns = len(campaigns)
            active_campaigns = len([c for c in campaigns if c.status == 'active'])
            total_sent = sum(c.emails_sent for c in campaigns)
            total_clicked = sum(c.links_clicked for c in campaigns)

            return jsonify({
                'success': True,
                'stats': {
                    'total_campaigns': total_campaigns,
                    'active_campaigns': active_campaigns,
                    'total_emails_sent': total_sent,
                    'total_clicks': total_clicked,
                    'click_rate': round((total_clicked / total_sent * 100) if total_sent > 0 else 0, 2)
                }
            })
        except Exception as e:
            logger.error(f"Dashboard stats error: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500


    # Domain Checker API
    @app.route('/api/domain/check', methods=['POST'])
    def check_domain():
        """Check domain reputation"""
        try:
            data = request.get_json()
            domain = data.get('domain')

            if not domain:
                return jsonify({'success': False, 'error': 'Domain is required'}), 400

            result = domain_checker.check_all(domain)
            return jsonify({'success': True, 'result': result})

        except Exception as e:
            logger.error(f"Domain check error: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500


    # Campaign API
    @app.route('/api/campaigns', methods=['GET'])
    def list_campaigns():
        """List all campaigns"""
        try:
            status_filter = request.args.get('status')
            campaigns = campaign_manager.list_campaigns(status_filter)

            campaigns_data = []
            for c in campaigns:
                campaigns_data.append({
                    'id': c.id,
                    'name': c.name,
                    'description': c.description,
                    'status': c.status,
                    'template_type': c.template_type,
                    'created_at': c.created_at,
                    'targets_count': c.targets_count,
                    'emails_sent': c.emails_sent,
                    'emails_opened': c.emails_opened,
                    'links_clicked': c.links_clicked,
                    'credentials_captured': c.credentials_captured
                })

            return jsonify({'success': True, 'campaigns': campaigns_data})

        except Exception as e:
            logger.error(f"List campaigns error: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500


    @app.route('/api/campaigns', methods=['POST'])
    def create_campaign():
        """Create a new campaign"""
        try:
            data = request.get_json()

            campaign = campaign_manager.create_campaign(
                name=data['name'],
                description=data['description'],
                template_type=data['template_type'],
                target_domain=data['target_domain'],
                phishing_url=data['phishing_url']
            )

            return jsonify({
                'success': True,
                'campaign': {
                    'id': campaign.id,
                    'name': campaign.name,
                    'status': campaign.status
                }
            })

        except Exception as e:
            logger.error(f"Create campaign error: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500


    @app.route('/api/campaigns/<campaign_id>', methods=['GET'])
    def get_campaign(campaign_id):
        """Get campaign details"""
        try:
            campaign = campaign_manager.get_campaign(campaign_id)

            if not campaign:
                return jsonify({'success': False, 'error': 'Campaign not found'}), 404

            stats = campaign_manager.get_campaign_statistics(campaign_id)

            return jsonify({
                'success': True,
                'campaign': {
                    'id': campaign.id,
                    'name': campaign.name,
                    'description': campaign.description,
                    'status': campaign.status,
                    'template_type': campaign.template_type,
                    'target_domain': campaign.target_domain,
                    'phishing_url': campaign.phishing_url,
                    'created_at': campaign.created_at,
                    'started_at': campaign.started_at,
                    'ended_at': campaign.ended_at
                },
                'statistics': stats
            })

        except Exception as e:
            logger.error(f"Get campaign error: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500


    @app.route('/api/campaigns/<campaign_id>/start', methods=['POST'])
    def start_campaign(campaign_id):
        """Start a campaign"""
        try:
            campaign_manager.start_campaign(campaign_id)
            return jsonify({'success': True, 'message': 'Campaign started'})
        except Exception as e:
            logger.error(f"Start campaign error: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500


    @app.route('/api/campaigns/<campaign_id>/pause', methods=['POST'])
    def pause_campaign(campaign_id):
        """Pause a campaign"""
        try:
            campaign_manager.pause_campaign(campaign_id)
            return jsonify({'success': True, 'message': 'Campaign paused'})
        except Exception as e:
            logger.error(f"Pause campaign error: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500


    @app.route('/api/campaigns/<campaign_id>/complete', methods=['POST'])
    def complete_campaign(campaign_id):
        """Complete a campaign"""
        try:
            campaign_manager.complete_campaign(campaign_id)
            return jsonify({'success': True, 'message': 'Campaign completed'})
        except Exception as e:
            logger.error(f"Complete campaign error: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500


    @app.route('/api/campaigns/<campaign_id>/targets', methods=['GET'])
    def get_campaign_targets(campaign_id):
        """Get campaign targets"""
        try:
            targets = campaign_manager.get_campaign_targets(campaign_id)

            targets_data = []
            for t in targets:
                targets_data.append({
                    'email': t.email,
                    'name': t.name,
                    'company': t.company,
                    'position': t.position,
                    'department': t.department
                })

            return jsonify({'success': True, 'targets': targets_data})

        except Exception as e:
            logger.error(f"Get targets error: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500


    @app.route('/api/campaigns/<campaign_id>/targets', methods=['POST'])
    def add_campaign_targets(campaign_id):
        """Add targets to campaign"""
        try:
            data = request.get_json()
            targets_data = data.get('targets', [])

            targets = []
            for t in targets_data:
                targets.append(Target(
                    email=t['email'],
                    name=t['name'],
                    company=t['company'],
                    position=t.get('position'),
                    department=t.get('department')
                ))

            count = campaign_manager.add_targets(campaign_id, targets)

            return jsonify({
                'success': True,
                'message': f'Added {count} targets'
            })

        except Exception as e:
            logger.error(f"Add targets error: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500


    @app.route('/api/campaigns/<campaign_id>/results', methods=['GET'])
    def get_campaign_results(campaign_id):
        """Get campaign results"""
        try:
            results = campaign_manager.get_campaign_results(campaign_id)

            results_data = []
            for r in results:
                results_data.append({
                    'target_email': r.target_email,
                    'event_type': r.event_type,
                    'timestamp': r.timestamp,
                    'ip_address': r.ip_address,
                    'user_agent': r.user_agent
                })

            return jsonify({'success': True, 'results': results_data})

        except Exception as e:
            logger.error(f"Get results error: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500


    # Email Generator API
    @app.route('/api/email/generate', methods=['POST'])
    def generate_email():
        """Generate phishing email"""
        try:
            data = request.get_json()

            email = email_generator.generate_email(
                template_type=data['template_type'],
                target_data=data.get('target_data', {}),
                evasion_level=data.get('evasion_level', 'medium')
            )

            return jsonify({'success': True, 'email': email})

        except Exception as e:
            logger.error(f"Generate email error: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500


    @app.route('/api/email/templates', methods=['GET'])
    def list_email_templates():
        """List available email templates"""
        templates = [
            {
                'id': 'it_support',
                'name': 'IT Support - Password Reset',
                'description': 'Password reset request from IT support'
            },
            {
                'id': 'hr_notification',
                'name': 'HR - Benefits Enrollment',
                'description': 'Benefits enrollment notification'
            },
            {
                'id': 'executive_impersonation',
                'name': 'Executive Impersonation',
                'description': 'Urgent request from executive'
            },
            {
                'id': 'document_share',
                'name': 'Document Share',
                'description': 'Shared document notification'
            }
        ]

        return jsonify({'success': True, 'templates': templates})


    # Page Cloner API
    @app.route('/api/clone/page', methods=['POST'])
    def clone_page():
        """Clone a webpage"""
        try:
            data = request.get_json()

            result = page_cloner.clone_page(
                target_url=data['url'],
                harvest_method=data.get('harvest_method', 'form'),
                include_assets=data.get('include_assets', True),
                webhook_url=data.get('webhook_url')
            )

            return jsonify({'success': result['success'], 'result': result})

        except Exception as e:
            logger.error(f"Clone page error: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500


    # SSL Manager API
    @app.route('/api/ssl/certificates', methods=['GET'])
    def list_ssl_certificates():
        """List SSL certificates"""
        try:
            # This requires certbot, handle gracefully
            ssl_manager = SSLManager(email="admin@example.com")
            certs = ssl_manager.list_certificates()

            return jsonify({'success': True, 'certificates': certs})

        except Exception as e:
            logger.error(f"List certificates error: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500


    @app.route('/api/ssl/obtain', methods=['POST'])
    def obtain_ssl_certificate():
        """Obtain SSL certificate"""
        try:
            data = request.get_json()

            ssl_manager = SSLManager(email=data['email'])
            result = ssl_manager.obtain_certificate(
                domain=data['domain'],
                method=data.get('method', 'standalone')
            )

            return jsonify({'success': result['success'], 'result': result})

        except Exception as e:
            logger.error(f"Obtain certificate error: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500


    # Health check
    @app.route('/api/health')
    def health_check():
        """API health check"""
        return jsonify({
            'status': 'healthy',
            'version': '1.0.0'
        })


    return app


if __name__ == '__main__':
    app = create_app()
    app.run(host='0.0.0.0', port=5000, debug=True)
