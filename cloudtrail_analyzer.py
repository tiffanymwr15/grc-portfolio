"""
Lesson 8: CloudTrail Log Analyzer
===================================
A GRC tool that parses CloudTrail log events, aggregates activity,
and flags suspicious patterns like root usage and unusual logins.

Python concepts covered:
  - JSON parsing of complex nested structures
  - Nested loops and filtering
  - collections.Counter for aggregation
  - Pattern detection with rule-based logic

GRC relevance:
  - NIST 800-53 AU-2 (Event Logging)
  - NIST 800-53 AU-6 (Audit Review, Analysis, and Reporting)
  - NIST 800-53 SI-4 (System Monitoring)
  - CIS Benchmark 3.x (Monitoring and Logging)
"""

import sys
import os
import json
from collections import Counter
from datetime import datetime


# ─── CONFIGURATION ────────────────────────────────────────────────────

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# IP addresses considered "known/trusted" — anything else is flagged
TRUSTED_IPS = [
    "198.51.100.10",   # Corporate office
    "203.0.113.50",    # VPN endpoint
]

# Actions that are always suspicious
SENSITIVE_ACTIONS = [
    "DeleteTrail",
    "StopLogging",
    "DeleteBucket",
    "PutBucketPolicy",
    "CreateUser",
    "AttachUserPolicy",
    "CreateAccessKey",
    "DeleteAccessKey",
    "PutUserPolicy",
    "DeactivateMFADevice",
]


# ─── MOCK DATA ────────────────────────────────────────────────────────
# Mirrors real CloudTrail JSON structure. In production, you'd download
# these from S3 or use boto3's lookup_events().

def get_mock_events():
    """
    Return mock CloudTrail events matching real API structure.

    Real CloudTrail logs are JSON files stored in S3 with this shape:
    {
        "Records": [
            {
                "eventTime": "...",
                "eventName": "...",
                "userIdentity": { "type": "...", "userName": "..." },
                "sourceIPAddress": "...",
                ...
            }
        ]
    }
    """
    return {
        "Records": [
            {
                "eventTime": "2026-04-03T08:00:00Z",
                "eventName": "ConsoleLogin",
                "eventSource": "signin.amazonaws.com",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "198.51.100.10",
                "userIdentity": {"type": "IAMUser", "userName": "admin-jane"},
                "responseElements": {"ConsoleLogin": "Success"},
                "errorCode": None,
            },
            {
                "eventTime": "2026-04-03T08:15:00Z",
                "eventName": "ListBuckets",
                "eventSource": "s3.amazonaws.com",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "198.51.100.10",
                "userIdentity": {"type": "IAMUser", "userName": "admin-jane"},
                "responseElements": None,
                "errorCode": None,
            },
            {
                "eventTime": "2026-04-03T08:30:00Z",
                "eventName": "CreateUser",
                "eventSource": "iam.amazonaws.com",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "198.51.100.10",
                "userIdentity": {"type": "IAMUser", "userName": "admin-jane"},
                "responseElements": {"user": {"userName": "new-intern"}},
                "errorCode": None,
            },
            {
                "eventTime": "2026-04-03T09:00:00Z",
                "eventName": "ConsoleLogin",
                "eventSource": "signin.amazonaws.com",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "45.33.32.156",
                "userIdentity": {"type": "Root", "userName": "root"},
                "responseElements": {"ConsoleLogin": "Success"},
                "errorCode": None,
            },
            {
                "eventTime": "2026-04-03T09:05:00Z",
                "eventName": "StopLogging",
                "eventSource": "cloudtrail.amazonaws.com",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "45.33.32.156",
                "userIdentity": {"type": "Root", "userName": "root"},
                "responseElements": None,
                "errorCode": None,
            },
            {
                "eventTime": "2026-04-03T09:10:00Z",
                "eventName": "DeleteBucket",
                "eventSource": "s3.amazonaws.com",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "45.33.32.156",
                "userIdentity": {"type": "Root", "userName": "root"},
                "responseElements": None,
                "errorCode": None,
            },
            {
                "eventTime": "2026-04-03T10:00:00Z",
                "eventName": "RunInstances",
                "eventSource": "ec2.amazonaws.com",
                "awsRegion": "us-west-2",
                "sourceIPAddress": "203.0.113.50",
                "userIdentity": {"type": "IAMUser", "userName": "dev-mike"},
                "responseElements": {"instancesSet": {"items": [{"instanceId": "i-0abc123"}]}},
                "errorCode": None,
            },
            {
                "eventTime": "2026-04-03T10:30:00Z",
                "eventName": "AuthorizeSecurityGroupIngress",
                "eventSource": "ec2.amazonaws.com",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "203.0.113.50",
                "userIdentity": {"type": "IAMUser", "userName": "dev-mike"},
                "responseElements": None,
                "errorCode": None,
            },
            {
                "eventTime": "2026-04-03T11:00:00Z",
                "eventName": "ConsoleLogin",
                "eventSource": "signin.amazonaws.com",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "192.0.2.99",
                "userIdentity": {"type": "IAMUser", "userName": "old-contractor"},
                "responseElements": {"ConsoleLogin": "Failure"},
                "errorCode": "Failed authentication",
            },
            {
                "eventTime": "2026-04-03T11:01:00Z",
                "eventName": "ConsoleLogin",
                "eventSource": "signin.amazonaws.com",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "192.0.2.99",
                "userIdentity": {"type": "IAMUser", "userName": "old-contractor"},
                "responseElements": {"ConsoleLogin": "Failure"},
                "errorCode": "Failed authentication",
            },
            {
                "eventTime": "2026-04-03T11:02:00Z",
                "eventName": "ConsoleLogin",
                "eventSource": "signin.amazonaws.com",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "192.0.2.99",
                "userIdentity": {"type": "IAMUser", "userName": "old-contractor"},
                "responseElements": {"ConsoleLogin": "Failure"},
                "errorCode": "Failed authentication",
            },
            {
                "eventTime": "2026-04-03T12:00:00Z",
                "eventName": "CreateAccessKey",
                "eventSource": "iam.amazonaws.com",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "198.51.100.10",
                "userIdentity": {"type": "IAMUser", "userName": "admin-jane"},
                "responseElements": {"accessKey": {"userName": "svc-deploy"}},
                "errorCode": None,
            },
            {
                "eventTime": "2026-04-03T13:00:00Z",
                "eventName": "DescribeInstances",
                "eventSource": "ec2.amazonaws.com",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "203.0.113.50",
                "userIdentity": {"type": "IAMUser", "userName": "grcengtest-1"},
                "responseElements": None,
                "errorCode": None,
            },
            {
                "eventTime": "2026-04-03T13:30:00Z",
                "eventName": "GetBucketEncryption",
                "eventSource": "s3.amazonaws.com",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "203.0.113.50",
                "userIdentity": {"type": "IAMUser", "userName": "grcengtest-1"},
                "responseElements": None,
                "errorCode": None,
            },
            {
                "eventTime": "2026-04-03T14:00:00Z",
                "eventName": "AttachUserPolicy",
                "eventSource": "iam.amazonaws.com",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "10.0.0.5",
                "userIdentity": {"type": "IAMUser", "userName": "dev-mike"},
                "responseElements": None,
                "errorCode": None,
            },
        ]
    }


# ─── PARSING FUNCTIONS ───────────────────────────────────────────────

def parse_event(event):
    """
    Extract key fields from a single CloudTrail event.

    CloudTrail events are deeply nested dicts. This function
    flattens the structure into something easier to work with.

    .get() with defaults is critical here — not every event
    has every field.
    """
    identity = event.get("userIdentity", {})

    return {
        "time": event.get("eventTime", ""),
        "action": event.get("eventName", ""),
        "service": event.get("eventSource", "").replace(".amazonaws.com", ""),
        "region": event.get("awsRegion", ""),
        "ip": event.get("sourceIPAddress", ""),
        "user_type": identity.get("type", "Unknown"),
        "user": identity.get("userName", identity.get("type", "Unknown")),
        "error": event.get("errorCode"),
    }


def parse_all_events(raw_data):
    """
    Parse all events from CloudTrail JSON.

    Uses a list comprehension to transform every raw event
    into our simplified format.
    """
    records = raw_data.get("Records", [])
    return [parse_event(event) for event in records]


# ─── AGGREGATION FUNCTIONS ────────────────────────────────────────────

def aggregate(events):
    """
    Aggregate events using collections.Counter.

    Counter is a specialized dictionary that counts occurrences:
        Counter(["a", "b", "a", "c", "a"])
        → Counter({"a": 3, "b": 1, "c": 1})

    .most_common(n) returns the top N items as a list of tuples:
        → [("a", 3), ("b", 1), ("c", 1)]
    """

    # Count events by different dimensions
    by_user = Counter(e["user"] for e in events)
    by_action = Counter(e["action"] for e in events)
    by_service = Counter(e["service"] for e in events)
    by_ip = Counter(e["ip"] for e in events)
    by_region = Counter(e["region"] for e in events)

    # Count errors
    errors = [e for e in events if e["error"]]
    error_count = len(errors)
    errors_by_user = Counter(e["user"] for e in errors)

    return {
        "total": len(events),
        "by_user": by_user,
        "by_action": by_action,
        "by_service": by_service,
        "by_ip": by_ip,
        "by_region": by_region,
        "error_count": error_count,
        "errors_by_user": errors_by_user,
    }


# ─── PATTERN DETECTION ───────────────────────────────────────────────

def detect_suspicious(events):
    """
    Scan events for suspicious patterns.

    Each detection rule is a separate check that appends findings
    to the alerts list. This rule-based approach is easy to extend —
    just add another check function.
    """
    alerts = []

    # ─── Rule 1: Root account usage ──────────────────────────────
    # The root account should almost never be used directly
    root_events = [e for e in events if e["user_type"] == "Root"]
    if root_events:
        actions = [e["action"] for e in root_events]
        alerts.append({
            "severity": "CRITICAL",
            "rule": "Root Account Usage",
            "detail": f"Root account used {len(root_events)} time(s): {', '.join(actions)}",
            "events": root_events,
        })

    # ─── Rule 2: Logins from untrusted IPs ───────────────────────
    logins = [e for e in events if e["action"] == "ConsoleLogin"]
    untrusted_logins = [e for e in logins if e["ip"] not in TRUSTED_IPS]
    if untrusted_logins:
        # Group by IP using a dict comprehension
        ips = set(e["ip"] for e in untrusted_logins)
        for ip in ips:
            ip_logins = [e for e in untrusted_logins if e["ip"] == ip]
            users = set(e["user"] for e in ip_logins)
            alerts.append({
                "severity": "HIGH",
                "rule": "Login from Untrusted IP",
                "detail": f"IP {ip}: {len(ip_logins)} login(s) by {', '.join(users)}",
                "events": ip_logins,
            })

    # ─── Rule 3: Failed login attempts (brute force indicator) ───
    failed_logins = [e for e in logins if e["error"]]
    # Group failed logins by user
    failed_by_user = Counter(e["user"] for e in failed_logins)
    for user, count in failed_by_user.items():
        if count >= 3:
            alerts.append({
                "severity": "HIGH",
                "rule": "Multiple Failed Logins",
                "detail": f"User '{user}' had {count} failed login attempts (possible brute force)",
                "events": [e for e in failed_logins if e["user"] == user],
            })

    # ─── Rule 4: Sensitive/destructive actions ───────────────────
    sensitive = [e for e in events if e["action"] in SENSITIVE_ACTIONS]
    if sensitive:
        for event in sensitive:
            alerts.append({
                "severity": "MEDIUM",
                "rule": "Sensitive Action Performed",
                "detail": f"{event['user']} performed {event['action']} from {event['ip']}",
                "events": [event],
            })

    # ─── Rule 5: Activity from unusual regions ───────────────────
    # If most activity is in us-east-1, flag other regions
    region_counts = Counter(e["region"] for e in events)
    if region_counts:
        primary_region = region_counts.most_common(1)[0][0]
        unusual_region_events = [e for e in events if e["region"] != primary_region]
        if unusual_region_events:
            regions = set(e["region"] for e in unusual_region_events)
            alerts.append({
                "severity": "LOW",
                "rule": "Activity in Non-Primary Region",
                "detail": f"{len(unusual_region_events)} event(s) in {', '.join(regions)} (primary: {primary_region})",
                "events": unusual_region_events,
            })

    # Sort alerts by severity
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    alerts.sort(key=lambda a: severity_order.get(a["severity"], 99))

    return alerts


# ─── REPORT FUNCTIONS ─────────────────────────────────────────────────

def print_report(events, stats, alerts):
    """Print a formatted CloudTrail analysis report."""

    print("\n" + "=" * 70)
    print("  CLOUDTRAIL LOG ANALYSIS REPORT")
    print(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Events analyzed: {stats['total']}")
    print("=" * 70)

    # ─── Activity by user ─────────────────────────────────────────
    print(f"\n  ACTIVITY BY USER")
    print(f"  {'User':<25} {'Events':<10} {'Errors'}")
    print(f"  {'-'*25} {'-'*10} {'-'*10}")
    for user, count in stats["by_user"].most_common():
        errors = stats["errors_by_user"].get(user, 0)
        err_str = str(errors) if errors > 0 else "-"
        print(f"  {user:<25} {count:<10} {err_str}")

    # ─── Activity by service ──────────────────────────────────────
    print(f"\n  ACTIVITY BY SERVICE")
    print(f"  {'Service':<25} {'Events'}")
    print(f"  {'-'*25} {'-'*10}")
    for service, count in stats["by_service"].most_common():
        print(f"  {service:<25} {count}")

    # ─── Top actions ──────────────────────────────────────────────
    print(f"\n  TOP ACTIONS")
    print(f"  {'Action':<35} {'Count'}")
    print(f"  {'-'*35} {'-'*10}")
    for action, count in stats["by_action"].most_common(10):
        print(f"  {action:<35} {count}")

    # ─── Source IPs ───────────────────────────────────────────────
    print(f"\n  SOURCE IPs")
    print(f"  {'IP Address':<20} {'Events':<10} {'Trusted'}")
    print(f"  {'-'*20} {'-'*10} {'-'*10}")
    for ip, count in stats["by_ip"].most_common():
        trusted = "✅ Yes" if ip in TRUSTED_IPS else "⚠️  No"
        print(f"  {ip:<20} {count:<10} {trusted}")

    # ─── Alerts ───────────────────────────────────────────────────
    if alerts:
        print(f"\n{'=' * 70}")
        print(f"  ⚠️  SECURITY ALERTS ({len(alerts)})")
        print(f"{'=' * 70}")

        for i, alert in enumerate(alerts, 1):
            sev = alert["severity"]
            icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}.get(sev, "⚪")
            print(f"\n  {icon} [{sev}] {alert['rule']}")
            print(f"     {alert['detail']}")
    else:
        print(f"\n  ✅ No suspicious patterns detected.")

    # ─── Summary ──────────────────────────────────────────────────
    crit = len([a for a in alerts if a["severity"] == "CRITICAL"])
    high = len([a for a in alerts if a["severity"] == "HIGH"])
    med = len([a for a in alerts if a["severity"] == "MEDIUM"])
    low = len([a for a in alerts if a["severity"] == "LOW"])

    print(f"\n{'=' * 70}")
    print(f"  SUMMARY: {stats['total']} events, {len(alerts)} alerts")
    print(f"  🔴 Critical: {crit}  🟠 High: {high}  🟡 Medium: {med}  🔵 Low: {low}")
    print("=" * 70 + "\n")

    return len(alerts)


def save_report_json(events, stats, alerts, filepath):
    """Save analysis results to a JSON file."""

    # Convert Counter objects to regular dicts for JSON serialization
    output = {
        "report_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_events": stats["total"],
        "total_alerts": len(alerts),
        "activity_by_user": dict(stats["by_user"]),
        "activity_by_action": dict(stats["by_action"]),
        "activity_by_service": dict(stats["by_service"]),
        "activity_by_ip": dict(stats["by_ip"]),
        "activity_by_region": dict(stats["by_region"]),
        "error_count": stats["error_count"],
        "alerts": [
            {
                "severity": a["severity"],
                "rule": a["rule"],
                "detail": a["detail"],
            }
            for a in alerts
        ],
    }

    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    print(f"  📄 Analysis report saved to: {filepath}\n")


# ─── MAIN ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\n  🔎 CloudTrail Log Analyzer")
    print("  " + "─" * 35)

    # Load events — from a JSON file argument or mock data
    if len(sys.argv) > 1 and os.path.isfile(sys.argv[1]):
        filepath = sys.argv[1]
        print(f"  [INFO] Loading events from: {filepath}")
        with open(filepath, "r", encoding="utf-8") as f:
            raw_data = json.load(f)
    else:
        print("  [INFO] Using mock CloudTrail data.")
        raw_data = get_mock_events()

    # Step 1: Parse
    events = parse_all_events(raw_data)
    print(f"  [INFO] Parsed {len(events)} events.\n")

    # Step 2: Aggregate
    stats = aggregate(events)

    # Step 3: Detect suspicious patterns
    alerts = detect_suspicious(events)

    # Step 4: Print report
    alert_count = print_report(events, stats, alerts)

    # Step 5: Save JSON
    report_path = os.path.join(SCRIPT_DIR, "cloudtrail_analysis.json")
    save_report_json(events, stats, alerts, report_path)

    sys.exit(0 if alert_count == 0 else 1)
