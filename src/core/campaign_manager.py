"""
Campaign Management System
Orchestrates phishing campaigns and tracks results
"""

import json
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime
from dataclasses import dataclass, asdict
from loguru import logger
import sqlite3
from contextlib import contextmanager


@dataclass
class Campaign:
    """Phishing campaign data structure"""
    id: str
    name: str
    description: str
    template_type: str
    target_domain: str
    phishing_url: str
    status: str  # draft, active, paused, completed
    created_at: str
    started_at: Optional[str] = None
    ended_at: Optional[str] = None
    targets_count: int = 0
    emails_sent: int = 0
    emails_opened: int = 0
    links_clicked: int = 0
    credentials_captured: int = 0


@dataclass
class Target:
    """Target (recipient) information"""
    email: str
    name: str
    company: str
    position: Optional[str] = None
    department: Optional[str] = None
    custom_fields: Optional[Dict] = None


@dataclass
class CampaignResult:
    """Individual campaign result/interaction"""
    campaign_id: str
    target_email: str
    event_type: str  # sent, opened, clicked, submitted
    timestamp: str
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    data: Optional[Dict] = None


class CampaignManager:
    """Manage phishing campaigns"""

    def __init__(self, db_path: str = "./campaigns.db"):
        """
        Initialize campaign manager

        Args:
            db_path: Path to SQLite database
        """
        self.db_path = Path(db_path)
        self._init_database()

    def _init_database(self):
        """Initialize database schema"""

        with self._get_db() as conn:
            cursor = conn.cursor()

            # Campaigns table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS campaigns (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT,
                    template_type TEXT,
                    target_domain TEXT,
                    phishing_url TEXT,
                    status TEXT,
                    created_at TEXT,
                    started_at TEXT,
                    ended_at TEXT,
                    targets_count INTEGER DEFAULT 0,
                    emails_sent INTEGER DEFAULT 0,
                    emails_opened INTEGER DEFAULT 0,
                    links_clicked INTEGER DEFAULT 0,
                    credentials_captured INTEGER DEFAULT 0
                )
            """)

            # Targets table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS targets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    campaign_id TEXT,
                    email TEXT NOT NULL,
                    name TEXT,
                    company TEXT,
                    position TEXT,
                    department TEXT,
                    custom_fields TEXT,
                    FOREIGN KEY (campaign_id) REFERENCES campaigns (id)
                )
            """)

            # Results table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    campaign_id TEXT,
                    target_email TEXT,
                    event_type TEXT,
                    timestamp TEXT,
                    ip_address TEXT,
                    user_agent TEXT,
                    data TEXT,
                    FOREIGN KEY (campaign_id) REFERENCES campaigns (id)
                )
            """)

            conn.commit()
            logger.info("Database initialized")

    @contextmanager
    def _get_db(self):
        """Get database connection context manager"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    def create_campaign(
        self,
        name: str,
        description: str,
        template_type: str,
        target_domain: str,
        phishing_url: str
    ) -> Campaign:
        """Create a new campaign"""

        campaign_id = datetime.now().strftime("%Y%m%d%H%M%S")

        campaign = Campaign(
            id=campaign_id,
            name=name,
            description=description,
            template_type=template_type,
            target_domain=target_domain,
            phishing_url=phishing_url,
            status="draft",
            created_at=datetime.now().isoformat()
        )

        with self._get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO campaigns (
                    id, name, description, template_type, target_domain,
                    phishing_url, status, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                campaign.id,
                campaign.name,
                campaign.description,
                campaign.template_type,
                campaign.target_domain,
                campaign.phishing_url,
                campaign.status,
                campaign.created_at
            ))
            conn.commit()

        logger.info(f"Campaign created: {campaign.id} - {campaign.name}")
        return campaign

    def add_targets(self, campaign_id: str, targets: List[Target]) -> int:
        """Add targets to a campaign"""

        with self._get_db() as conn:
            cursor = conn.cursor()

            for target in targets:
                cursor.execute("""
                    INSERT INTO targets (
                        campaign_id, email, name, company, position, department, custom_fields
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    campaign_id,
                    target.email,
                    target.name,
                    target.company,
                    target.position,
                    target.department,
                    json.dumps(target.custom_fields) if target.custom_fields else None
                ))

            # Update campaign targets count
            cursor.execute("""
                UPDATE campaigns
                SET targets_count = (SELECT COUNT(*) FROM targets WHERE campaign_id = ?)
                WHERE id = ?
            """, (campaign_id, campaign_id))

            conn.commit()

        logger.info(f"Added {len(targets)} targets to campaign {campaign_id}")
        return len(targets)

    def start_campaign(self, campaign_id: str) -> bool:
        """Start a campaign"""

        with self._get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE campaigns
                SET status = 'active', started_at = ?
                WHERE id = ?
            """, (datetime.now().isoformat(), campaign_id))
            conn.commit()

        logger.info(f"Campaign started: {campaign_id}")
        return True

    def pause_campaign(self, campaign_id: str) -> bool:
        """Pause a campaign"""

        with self._get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE campaigns
                SET status = 'paused'
                WHERE id = ?
            """, (campaign_id,))
            conn.commit()

        logger.info(f"Campaign paused: {campaign_id}")
        return True

    def complete_campaign(self, campaign_id: str) -> bool:
        """Complete a campaign"""

        with self._get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE campaigns
                SET status = 'completed', ended_at = ?
                WHERE id = ?
            """, (datetime.now().isoformat(), campaign_id))
            conn.commit()

        logger.info(f"Campaign completed: {campaign_id}")
        return True

    def log_event(
        self,
        campaign_id: str,
        target_email: str,
        event_type: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        data: Optional[Dict] = None
    ) -> bool:
        """Log a campaign event"""

        with self._get_db() as conn:
            cursor = conn.cursor()

            # Insert event
            cursor.execute("""
                INSERT INTO results (
                    campaign_id, target_email, event_type, timestamp,
                    ip_address, user_agent, data
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                campaign_id,
                target_email,
                event_type,
                datetime.now().isoformat(),
                ip_address,
                user_agent,
                json.dumps(data) if data else None
            ))

            # Update campaign statistics
            if event_type == "sent":
                cursor.execute("UPDATE campaigns SET emails_sent = emails_sent + 1 WHERE id = ?", (campaign_id,))
            elif event_type == "opened":
                cursor.execute("UPDATE campaigns SET emails_opened = emails_opened + 1 WHERE id = ?", (campaign_id,))
            elif event_type == "clicked":
                cursor.execute("UPDATE campaigns SET links_clicked = links_clicked + 1 WHERE id = ?", (campaign_id,))
            elif event_type == "submitted":
                cursor.execute("UPDATE campaigns SET credentials_captured = credentials_captured + 1 WHERE id = ?", (campaign_id,))

            conn.commit()

        logger.debug(f"Event logged: {event_type} for {target_email}")
        return True

    def get_campaign(self, campaign_id: str) -> Optional[Campaign]:
        """Get campaign by ID"""

        with self._get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM campaigns WHERE id = ?", (campaign_id,))
            row = cursor.fetchone()

            if row:
                return Campaign(**dict(row))

        return None

    def list_campaigns(self, status: Optional[str] = None) -> List[Campaign]:
        """List all campaigns, optionally filtered by status"""

        with self._get_db() as conn:
            cursor = conn.cursor()

            if status:
                cursor.execute("SELECT * FROM campaigns WHERE status = ? ORDER BY created_at DESC", (status,))
            else:
                cursor.execute("SELECT * FROM campaigns ORDER BY created_at DESC")

            rows = cursor.fetchall()
            return [Campaign(**dict(row)) for row in rows]

    def get_campaign_targets(self, campaign_id: str) -> List[Target]:
        """Get all targets for a campaign"""

        with self._get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM targets WHERE campaign_id = ?", (campaign_id,))
            rows = cursor.fetchall()

            targets = []
            for row in rows:
                target_dict = dict(row)
                if target_dict.get('custom_fields'):
                    target_dict['custom_fields'] = json.loads(target_dict['custom_fields'])
                targets.append(Target(**{k: v for k, v in target_dict.items() if k in Target.__annotations__}))

            return targets

    def get_campaign_results(self, campaign_id: str) -> List[CampaignResult]:
        """Get all results for a campaign"""

        with self._get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM results WHERE campaign_id = ? ORDER BY timestamp DESC", (campaign_id,))
            rows = cursor.fetchall()

            results = []
            for row in rows:
                result_dict = dict(row)
                if result_dict.get('data'):
                    result_dict['data'] = json.loads(result_dict['data'])
                results.append(CampaignResult(**{k: v for k, v in result_dict.items() if k in CampaignResult.__annotations__}))

            return results

    def get_campaign_statistics(self, campaign_id: str) -> Dict:
        """Get detailed statistics for a campaign"""

        campaign = self.get_campaign(campaign_id)
        if not campaign:
            return {}

        # Calculate rates
        open_rate = (campaign.emails_opened / campaign.emails_sent * 100) if campaign.emails_sent > 0 else 0
        click_rate = (campaign.links_clicked / campaign.emails_sent * 100) if campaign.emails_sent > 0 else 0
        capture_rate = (campaign.credentials_captured / campaign.emails_sent * 100) if campaign.emails_sent > 0 else 0

        return {
            "campaign_id": campaign.id,
            "name": campaign.name,
            "status": campaign.status,
            "targets": campaign.targets_count,
            "sent": campaign.emails_sent,
            "opened": campaign.emails_opened,
            "clicked": campaign.links_clicked,
            "captured": campaign.credentials_captured,
            "open_rate": round(open_rate, 2),
            "click_rate": round(click_rate, 2),
            "capture_rate": round(capture_rate, 2),
            "duration": self._calculate_duration(campaign.started_at, campaign.ended_at)
        }

    def _calculate_duration(self, start: Optional[str], end: Optional[str]) -> Optional[str]:
        """Calculate campaign duration"""

        if not start:
            return None

        start_time = datetime.fromisoformat(start)
        end_time = datetime.fromisoformat(end) if end else datetime.now()

        duration = end_time - start_time
        days = duration.days
        hours = duration.seconds // 3600
        minutes = (duration.seconds % 3600) // 60

        if days > 0:
            return f"{days}d {hours}h"
        elif hours > 0:
            return f"{hours}h {minutes}m"
        else:
            return f"{minutes}m"

    def export_campaign_report(self, campaign_id: str, output_file: str) -> bool:
        """Export campaign report to JSON"""

        campaign = self.get_campaign(campaign_id)
        if not campaign:
            return False

        statistics = self.get_campaign_statistics(campaign_id)
        targets = self.get_campaign_targets(campaign_id)
        results = self.get_campaign_results(campaign_id)

        report = {
            "campaign": asdict(campaign),
            "statistics": statistics,
            "targets": [asdict(t) for t in targets],
            "results": [asdict(r) for r in results],
            "generated_at": datetime.now().isoformat()
        }

        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)

        logger.info(f"Campaign report exported to {output_file}")
        return True


if __name__ == "__main__":
    # Example usage
    manager = CampaignManager()

    # Create a campaign
    campaign = manager.create_campaign(
        name="Q4 Security Awareness Test",
        description="Testing employee awareness of phishing attacks",
        template_type="it_support",
        target_domain="example.com",
        phishing_url="https://secure-login-portal.com/auth"
    )

    print(f"Campaign created: {campaign.id}")

    # Add targets
    targets = [
        Target(email="john@example.com", name="John Smith", company="Acme Corp", position="Engineer"),
        Target(email="jane@example.com", name="Jane Doe", company="Acme Corp", position="Manager"),
    ]
    manager.add_targets(campaign.id, targets)

    # List campaigns
    print("\nActive campaigns:")
    for c in manager.list_campaigns():
        print(f"  - {c.name} ({c.status}): {c.targets_count} targets")
