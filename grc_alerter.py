"""
Lesson 14: Notification and Alerting System
==============================================
A GRC tool that sends compliance alerts via webhooks (Slack) and email.
Implements retry logic with exponential backoff for resilient delivery.

Python concepts covered:
  - requests library for HTTP calls
  - Webhook integrations (Slack, Teams, generic)
  - SMTP email sending
  - Retry logic with exponential backoff
  - JSON payload construction
  - Environment variables for secrets

GRC relevance:
  - Real-time alerting on compliance violations
  - Integration with previous tools (drift detector, risk register, etc.)
  - Audit trail of notifications sent
  - NIST 800-53 AU-6 (Audit Review and Analysis)
"""

import sys
import os
import json
import time
import smtplib
import ssl
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from collections import deque


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ALERT_HISTORY_FILE = os.path.join(SCRIPT_DIR, "alert_history.jsonl")


# ═══════════════════════════════════════════════════════════════════════
# CONFIGURATION VIA ENVIRONMENT VARIABLES
# ═══════════════════════════════════════════════════════════════════════

SLACK_WEBHOOK_URL = os.environ.get("GRC_SLACK_WEBHOOK_URL")
TEAMS_WEBHOOK_URL = os.environ.get("GRC_TEAMS_WEBHOOK_URL")
SMTP_SERVER = os.environ.get("GRC_SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT = int(os.environ.get("GRC_SMTP_PORT", "587"))
SMTP_USERNAME = os.environ.get("GRC_SMTP_USERNAME")
SMTP_PASSWORD = os.environ.get("GRC_SMTP_PASSWORD")
EMAIL_FROM = os.environ.get("GRC_EMAIL_FROM", "grc-alerts@company.com")
EMAIL_TO = os.environ.get("GRC_EMAIL_TO", "security-team@company.com")


# ═══════════════════════════════════════════════════════════════════════
# RETRY LOGIC WITH EXPONENTIAL BACKOFF
# ═══════════════════════════════════════════════════════════════════════

def send_with_retry(send_func, max_retries=3, base_delay=1):
    """
    Execute a send function with exponential backoff retry logic.
    
    Exponential backoff: delay doubles after each failure
    1st retry: 1 second
    2nd retry: 2 seconds  
    3rd retry: 4 seconds
    etc.
    
    This prevents hammering a failing service and gives transient
    failures time to resolve.
    """
    for attempt in range(max_retries):
        try:
            result = send_func()
            if result:
                return True, attempt + 1  # Success, attempts used
        except Exception as e:
            print(f"  Attempt {attempt + 1} failed: {e}")
            
        if attempt < max_retries - 1:
            delay = base_delay * (2 ** attempt)  # Exponential: 1, 2, 4, 8...
            print(f"  Retrying in {delay}s...")
            time.sleep(delay)
    
    return False, max_retries  # All retries exhausted


# ═══════════════════════════════════════════════════════════════════════
# WEBHOOK ALERTERS
# ═══════════════════════════════════════════════════════════════════════

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False
    print("⚠️  requests library not installed. Webhooks will use mock mode.")
    print("   Install with: pip install requests")


def send_slack_alert(alert_data):
    """Send alert to Slack via webhook."""
    if not SLACK_WEBHOOK_URL:
        print("  ⚠️  SLACK_WEBHOOK_URL not configured")
        return False
    
    if not HAS_REQUESTS:
        # Mock mode for demonstration
        print(f"  [MOCK] Would send to Slack: {alert_data['title']}")
        return True
    
    # Build Slack message payload
    severity_colors = {
        "CRITICAL": "#FF0000",
        "HIGH": "#FF8C00", 
        "MEDIUM": "#FFD700",
        "LOW": "#00FF00",
        "INFO": "#808080"
    }
    
    payload = {
        "attachments": [{
            "color": severity_colors.get(alert_data.get("severity", "INFO"), "#808080"),
            "title": f"🚨 {alert_data.get('severity', 'ALERT')}: {alert_data.get('title', 'GRC Alert')}",
            "fields": [
                {"title": "Control", "value": alert_data.get("control", "N/A"), "short": True},
                {"title": "Finding", "value": alert_data.get("finding", "N/A")[:100], "short": True},
                {"title": "Timestamp", "value": alert_data.get("timestamp", datetime.now().isoformat()), "short": True},
                {"title": "Source", "value": alert_data.get("source", "GRC System"), "short": True}
            ],
            "footer": "GRC Alerting System",
            "ts": int(time.time())
        }]
    }
    
    def _send():
        response = requests.post(
            SLACK_WEBHOOK_URL,
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        response.raise_for_status()
        return response.status_code == 200
    
    return send_with_retry(_send)[0]


def send_teams_alert(alert_data):
    """Send alert to Microsoft Teams via webhook."""
    if not TEAMS_WEBHOOK_URL:
        print("  ⚠️  TEAMS_WEBHOOK_URL not configured")
        return False
    
    if not HAS_REQUESTS:
        print(f"  [MOCK] Would send to Teams: {alert_data['title']}")
        return True
    
    # Build Teams adaptive card payload
    payload = {
        "@type": "MessageCard",
        "@context": "https://schema.org/extensions",
        "themeColor": "FF0000" if alert_data.get("severity") == "CRITICAL" else "FF8C00",
        "summary": f"GRC Alert: {alert_data.get('title')}",
        "sections": [{
            "activityTitle": f"🚨 {alert_data.get('severity', 'ALERT')}: {alert_data.get('title')}",
            "facts": [
                {"name": "Control:", "value": alert_data.get("control", "N/A")},
                {"name": "Finding:", "value": alert_data.get("finding", "N/A")},
                {"name": "Source:", "value": alert_data.get("source", "GRC System")},
                {"name": "Time:", "value": alert_data.get("timestamp", datetime.now().isoformat())}
            ]
        }]
    }
    
    def _send():
        response = requests.post(
            TEAMS_WEBHOOK_URL,
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        response.raise_for_status()
        return True
    
    return send_with_retry(_send)[0]


def send_generic_webhook(url, alert_data, headers=None):
    """Send alert to any generic webhook endpoint."""
    if not HAS_REQUESTS:
        print(f"  [MOCK] Would send to {url}: {alert_data['title']}")
        return True
    
    default_headers = {"Content-Type": "application/json"}
    if headers:
        default_headers.update(headers)
    
    def _send():
        response = requests.post(
            url,
            json=alert_data,
            headers=default_headers,
            timeout=10
        )
        response.raise_for_status()
        return True
    
    return send_with_retry(_send)[0]


# ═══════════════════════════════════════════════════════════════════════
# EMAIL ALERTER
# ═══════════════════════════════════════════════════════════════════════

def send_email_alert(alert_data):
    """Send alert via SMTP email."""
    if not all([SMTP_USERNAME, SMTP_PASSWORD]):
        print("  ⚠️  SMTP credentials not configured")
        return False
    
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"[GRC ALERT] {alert_data.get('severity', 'INFO')}: {alert_data.get('title', 'Alert')}"
        msg["From"] = EMAIL_FROM
        msg["To"] = EMAIL_TO
        
        # Plain text version
        text_body = f"""
GRC Security Alert
====================

Severity: {alert_data.get('severity', 'INFO')}
Title: {alert_data.get('title', 'Alert')}
Control: {alert_data.get('control', 'N/A')}
Finding: {alert_data.get('finding', 'N/A')}
Source: {alert_data.get('source', 'GRC System')}
Timestamp: {alert_data.get('timestamp', datetime.now().isoformat())}

---
Sent by GRC Alerting System
        """
        
        # HTML version
        html_body = f"""
<html>
<body style="font-family: Arial, sans-serif;">
    <h2 style="color: {'#FF0000' if alert_data.get('severity') == 'CRITICAL' else '#FF8C00'};">
        🚨 {alert_data.get('severity', 'ALERT')}: {alert_data.get('title', 'GRC Alert')}
    </h2>
    <table style="border-collapse: collapse; width: 100%;">
        <tr><td style="padding: 8px; border: 1px solid #ddd;"><b>Control</b></td><td style="padding: 8px; border: 1px solid #ddd;">{alert_data.get('control', 'N/A')}</td></tr>
        <tr><td style="padding: 8px; border: 1px solid #ddd;"><b>Finding</b></td><td style="padding: 8px; border: 1px solid #ddd;">{alert_data.get('finding', 'N/A')}</td></tr>
        <tr><td style="padding: 8px; border: 1px solid #ddd;"><b>Source</b></td><td style="padding: 8px; border: 1px solid #ddd;">{alert_data.get('source', 'GRC System')}</td></tr>
        <tr><td style="padding: 8px; border: 1px solid #ddd;"><b>Time</b></td><td style="padding: 8px; border: 1px solid #ddd;">{alert_data.get('timestamp', datetime.now().isoformat())}</td></tr>
    </table>
    <hr>
    <p style="color: #666; font-size: 12px;">Sent by GRC Alerting System</p>
</body>
</html>
        """
        
        msg.attach(MIMEText(text_body, "plain"))
        msg.attach(MIMEText(html_body, "html"))
        
        def _send():
            context = ssl.create_default_context()
            with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
                server.starttls(context=context)
                server.login(SMTP_USERNAME, SMTP_PASSWORD)
                server.sendmail(EMAIL_FROM, EMAIL_TO.split(","), msg.as_string())
            return True
        
        return send_with_retry(_send, max_retries=2)[0]
        
    except Exception as e:
        print(f"  ❌ Email send failed: {e}")
        return False


# ═══════════════════════════════════════════════════════════════════════
# ALERT HISTORY
# ═══════════════════════════════════════════════════════════════════════

def log_alert(alert_data, channels_sent, success):
    """Log alert to history file for audit trail."""
    record = {
        "timestamp": datetime.now().isoformat(),
        "alert": alert_data,
        "channels": channels_sent,
        "success": success
    }
    
    with open(ALERT_HISTORY_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")


def get_recent_alerts(limit=50):
    """Get recent alerts from history."""
    try:
        with open(ALERT_HISTORY_FILE, "r", encoding="utf-8") as f:
            lines = deque(f, maxlen=limit)
        return [json.loads(line) for line in lines]
    except FileNotFoundError:
        return []


# ═══════════════════════════════════════════════════════════════════════
# MAIN ALERT FUNCTION
# ═══════════════════════════════════════════════════════════════════════

def send_alert(title, finding, severity="HIGH", control="N/A", source="GRC System", 
               channels=None, **extra_data):
    """
    Send an alert through configured channels.
    
    Args:
        title: Alert title/summary
        finding: Detailed finding description
        severity: CRITICAL, HIGH, MEDIUM, LOW, INFO
        control: Related control ID (e.g., "AC-2", "SI-4")
        source: Tool/system that generated the alert
        channels: List of channels to use ['slack', 'email', 'teams'] or None for all
        **extra_data: Any additional fields to include
    
    Returns:
        dict with success status per channel
    """
    alert_data = {
        "title": title,
        "finding": finding,
        "severity": severity,
        "control": control,
        "source": source,
        "timestamp": datetime.now().isoformat(),
        **extra_data
    }
    
    print(f"\n  🚨 Sending Alert: {title}")
    print(f"  Severity: {severity} | Control: {control}")
    
    results = {}
    channels = channels or ["slack", "email", "teams"]
    
    for channel in channels:
        print(f"  → {channel}...", end=" ")
        
        if channel == "slack":
            success = send_slack_alert(alert_data)
        elif channel == "email":
            success = send_email_alert(alert_data)
        elif channel == "teams":
            success = send_teams_alert(alert_data)
        else:
            print(f"Unknown channel: {channel}")
            success = False
        
        results[channel] = success
        print("✅" if success else "❌")
    
    # Log to history
    log_alert(alert_data, channels, results)
    
    return results


# ═══════════════════════════════════════════════════════════════════════
# CLI INTERFACE
# ═══════════════════════════════════════════════════════════════════════

def print_usage():
    print("""
Usage:
  grc_alerter.py send --title "Alert Title" --finding "Description" [options]
  grc_alerter.py test                          Send test alert to all channels
  grc_alerter.py history [N]                    Show last N alerts (default: 10)
  grc_alerter.py config                         Show current configuration

Options:
  --title TEXT        Alert title (required)
  --finding TEXT      Alert description/finding (required)
  --severity LEVEL    CRITICAL, HIGH, MEDIUM, LOW, INFO (default: HIGH)
  --control ID        Related control (e.g., AC-2, SI-4)
  --source TEXT       Alert source system (default: GRC System)
  --channels LIST     Comma-separated: slack,email,teams (default: all)

Environment Variables:
  GRC_SLACK_WEBHOOK_URL     Slack incoming webhook URL
  GRC_TEAMS_WEBHOOK_URL     Teams incoming webhook URL
  GRC_SMTP_USERNAME         SMTP username
  GRC_SMTP_PASSWORD         SMTP password
  GRC_EMAIL_FROM            From address
  GRC_EMAIL_TO              To address(es), comma-separated

Examples:
  # Send critical drift alert
  grc_alerter.py send --title "Drift Detected" --finding "S3 bucket public" \\
                     --severity CRITICAL --control "AC-3" --channels slack,email

  # Send from another tool (stdout parseable)
  python drift_detector.py scan | grc_alerter.py send --title "Drift Report" --finding "-"
""")


def show_config():
    """Display current configuration (without secrets)."""
    print("\n  GRC Alert System Configuration")
    print("  " + "=" * 50)
    
    config = {
        "Slack Webhook": "✅ Configured" if SLACK_WEBHOOK_URL else "❌ Not set",
        "Teams Webhook": "✅ Configured" if TEAMS_WEBHOOK_URL else "❌ Not set",
        "SMTP Server": f"{SMTP_SERVER}:{SMTP_PORT}",
        "SMTP Username": "✅ Configured" if SMTP_USERNAME else "❌ Not set",
        "Email From": EMAIL_FROM,
        "Email To": EMAIL_TO,
    }
    
    for key, value in config.items():
        print(f"  {key}: {value}")
    
    print(f"\n  Alert History: {ALERT_HISTORY_FILE}")
    print(f"  requests library: {'✅ Available' if HAS_REQUESTS else '❌ Not installed'}\n")


# ═══════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    args = sys.argv[1:]
    
    if not args or args[0] in ("-h", "--help", "help"):
        print_usage()
        sys.exit(0)
    
    command = args[0].lower()
    
    if command == "config":
        show_config()
    
    elif command == "test":
        # Send a test alert to all configured channels
        results = send_alert(
            title="Test Alert - GRC System",
            finding="This is a test alert to verify notification channels are working.",
            severity="INFO",
            control="TEST-001",
            source="GRC Alert Tester"
        )
        
        print(f"\n  Test Results:")
        for channel, success in results.items():
            print(f"    {channel}: {'✅ OK' if success else '❌ Failed'}")
    
    elif command == "send":
        # Parse arguments
        import argparse
        parser = argparse.ArgumentParser(description="Send GRC alert")
        parser.add_argument("--title", required=True, help="Alert title")
        parser.add_argument("--finding", required=True, help="Alert finding/description")
        parser.add_argument("--severity", default="HIGH", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"])
        parser.add_argument("--control", default="N/A", help="Related control ID")
        parser.add_argument("--source", default="GRC System", help="Alert source")
        parser.add_argument("--channels", default="slack,email,teams", help="Comma-separated channels")
        
        try:
            parsed = parser.parse_args(args[1:])
        except SystemExit:
            sys.exit(1)
        
        channel_list = [c.strip() for c in parsed.channels.split(",")]
        
        results = send_alert(
            title=parsed.title,
            finding=parsed.finding,
            severity=parsed.severity,
            control=parsed.control,
            source=parsed.source,
            channels=channel_list
        )
        
        # Exit code based on success
        sys.exit(0 if any(results.values()) else 1)
    
    elif command == "history":
        limit = int(args[1]) if len(args) > 1 and args[1].isdigit() else 10
        alerts = get_recent_alerts(limit)
        
        print(f"\n  Recent Alerts (last {len(alerts)}):")
        print("  " + "=" * 70)
        
        for alert in reversed(alerts):  # Newest first
            a = alert["alert"]
            print(f"\n  [{alert['timestamp'][:19]}] {a.get('severity', 'INFO')}: {a.get('title')}")
            print(f"    Finding: {a.get('finding', 'N/A')[:60]}...")
            print(f"    Channels: {', '.join(alert['channels'])} | Success: {alert['success']}")
    
    else:
        print(f"Unknown command: {command}")
        print_usage()
        sys.exit(1)
