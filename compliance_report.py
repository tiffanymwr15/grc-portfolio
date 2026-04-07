"""
Lesson 9: Automated Compliance Report Generator
=================================================
A GRC tool that runs a series of compliance checks, collects results
using a ComplianceCheck class, and generates a formatted Markdown report.

Python concepts covered:
  - Classes (intro to OOP): __init__, methods, __repr__
  - Reusing code from previous lessons (Lessons 6-8)
  - String formatting and template generation
  - Generating structured Markdown reports

GRC relevance:
  - NIST 800-53 CA-2 (Security Assessments)
  - NIST 800-53 CA-7 (Continuous Monitoring)
  - Audit report generation and evidence packaging
"""

import sys
import os
import json
from datetime import datetime, timezone, timedelta
from collections import Counter


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


# ═══════════════════════════════════════════════════════════════════════
# THE ComplianceCheck CLASS — Introduction to Object-Oriented Programming
# ═══════════════════════════════════════════════════════════════════════
#
# A class is a blueprint for creating objects. Think of it like a form
# template — every form has the same fields, but each filled-out form
# has different values.
#
# Why use a class here?
#   - Every compliance check has the same structure (control_id, description,
#     status, evidence, severity)
#   - A class ensures consistency — you can't accidentally forget a field
#   - Methods let each check "know how to" do things (like format itself)

class ComplianceCheck:
    """
    Represents a single compliance check result.

    __init__ is the "constructor" — it runs when you create a new object:
        check = ComplianceCheck("AC-2", "MFA Check", "PASS", "All users have MFA")

    'self' refers to the specific object being created. Every method
    receives 'self' as its first argument automatically.
    """

    def __init__(self, control_id, description, status, evidence, severity="MEDIUM", category="General"):
        """
        Initialize a new ComplianceCheck.

        Parameters are stored as 'attributes' on the object using self.
        After this runs, you can access them like: check.control_id, check.status, etc.
        """
        self.control_id = control_id
        self.description = description
        self.status = status          # "PASS", "FAIL", "WARNING", "ERROR"
        self.evidence = evidence      # Details/proof of the finding
        self.severity = severity      # "CRITICAL", "HIGH", "MEDIUM", "LOW"
        self.category = category      # Grouping for the report
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def is_passing(self):
        """
        A method — a function that belongs to an object.
        Called like: check.is_passing()

        Returns True if the check passed.
        """
        return self.status == "PASS"

    def to_dict(self):
        """Convert this check to a dictionary (useful for JSON export)."""
        return {
            "control_id": self.control_id,
            "description": self.description,
            "status": self.status,
            "evidence": self.evidence,
            "severity": self.severity,
            "category": self.category,
            "timestamp": self.timestamp,
        }

    def __repr__(self):
        """
        __repr__ is a "magic method" — Python calls it when you print the object.
        Without it, print(check) shows something unhelpful like:
            <__main__.ComplianceCheck object at 0x...>
        With it, you get a readable summary.
        """
        icon = "✅" if self.is_passing() else "❌"
        return f"{icon} [{self.control_id}] {self.description}: {self.status}"


# ═══════════════════════════════════════════════════════════════════════
# COMPLIANCE CHECK FUNCTIONS — Reusing logic from Lessons 6, 7, 8
# ═══════════════════════════════════════════════════════════════════════
# Each function runs a specific check and returns a ComplianceCheck object.
# This is the same audit logic from previous lessons, now wrapped in classes.

def check_iam_mfa(mock=True):
    """Run IAM MFA check (from Lesson 6) and return ComplianceCheck objects."""
    checks = []
    now = datetime.now(timezone.utc)

    if mock:
        users = [
            {"UserName": "admin-jane", "MFADevices": [{"SerialNumber": "arn:..."}]},
            {"UserName": "dev-mike", "MFADevices": []},
            {"UserName": "svc-deploy", "MFADevices": []},
            {"UserName": "grcengtest-1", "MFADevices": [{"SerialNumber": "arn:..."}]},
            {"UserName": "old-contractor", "MFADevices": []},
        ]
    else:
        # In production, you'd call get_live_users() from iam_auditor.py
        users = []

    users_without_mfa = [u["UserName"] for u in users if not u["MFADevices"]]
    total = len(users)
    mfa_count = total - len(users_without_mfa)

    if not users_without_mfa:
        status = "PASS"
        evidence = f"All {total} IAM users have MFA enabled"
    else:
        status = "FAIL"
        evidence = f"{len(users_without_mfa)}/{total} users lack MFA: {', '.join(users_without_mfa)}"

    checks.append(ComplianceCheck(
        control_id="IA-2",
        description="IAM users have MFA enabled",
        status=status,
        evidence=evidence,
        severity="HIGH",
        category="Identity & Access",
    ))

    return checks


def check_iam_key_rotation(mock=True):
    """Run access key age check (from Lesson 6)."""
    checks = []
    now = datetime.now(timezone.utc)
    max_age = 90

    if mock:
        keys = [
            {"UserName": "admin-jane", "KeyAge": 45},
            {"UserName": "dev-mike", "KeyAge": 150},
            {"UserName": "svc-deploy", "KeyAge": 95},
            {"UserName": "grcengtest-1", "KeyAge": 2},
        ]
    else:
        keys = []

    overdue = [k for k in keys if k["KeyAge"] > max_age]

    if not overdue:
        status = "PASS"
        evidence = f"All access keys are within {max_age}-day rotation policy"
    else:
        status = "FAIL"
        names = [f"{k['UserName']} ({k['KeyAge']}d)" for k in overdue]
        evidence = f"{len(overdue)} key(s) overdue: {', '.join(names)}"

    checks.append(ComplianceCheck(
        control_id="IA-5",
        description="Access keys rotated within 90 days",
        status=status,
        evidence=evidence,
        severity="HIGH",
        category="Identity & Access",
    ))

    return checks


def check_s3_encryption(mock=True):
    """Run S3 encryption check (from Lesson 7)."""
    if mock:
        buckets = [
            {"Name": "company-logs-prod", "Encrypted": True},
            {"Name": "dev-test-data", "Encrypted": False},
            {"Name": "public-assets-demo", "Encrypted": True},
            {"Name": "backup-archive-2025", "Encrypted": True},
            {"Name": "marketing-uploads", "Encrypted": True},
            {"Name": "company-access-logs", "Encrypted": True},
        ]
    else:
        buckets = []

    unencrypted = [b["Name"] for b in buckets if not b["Encrypted"]]

    if not unencrypted:
        status = "PASS"
        evidence = f"All {len(buckets)} S3 buckets have encryption enabled"
    else:
        status = "FAIL"
        evidence = f"{len(unencrypted)}/{len(buckets)} bucket(s) lack encryption: {', '.join(unencrypted)}"

    return [ComplianceCheck(
        control_id="SC-28",
        description="S3 buckets encrypted at rest",
        status=status,
        evidence=evidence,
        severity="HIGH",
        category="Data Protection",
    )]


def check_s3_public_access(mock=True):
    """Run S3 public access check (from Lesson 7)."""
    if mock:
        buckets = [
            {"Name": "company-logs-prod", "PublicBlocked": True},
            {"Name": "dev-test-data", "PublicBlocked": True},
            {"Name": "public-assets-demo", "PublicBlocked": False},
            {"Name": "backup-archive-2025", "PublicBlocked": True},
            {"Name": "marketing-uploads", "PublicBlocked": False},
            {"Name": "company-access-logs", "PublicBlocked": True},
        ]
    else:
        buckets = []

    public = [b["Name"] for b in buckets if not b["PublicBlocked"]]

    if not public:
        status = "PASS"
        evidence = f"All {len(buckets)} S3 buckets have public access blocked"
    else:
        status = "FAIL"
        evidence = f"{len(public)}/{len(buckets)} bucket(s) allow public access: {', '.join(public)}"

    return [ComplianceCheck(
        control_id="AC-3",
        description="S3 buckets block public access",
        status=status,
        evidence=evidence,
        severity="CRITICAL",
        category="Data Protection",
    )]


def check_cloudtrail_logging(mock=True):
    """Check CloudTrail is active (from Lesson 8)."""
    if mock:
        trails_active = True
        trail_name = "main-trail"
    else:
        trails_active = False
        trail_name = "N/A"

    if trails_active:
        status = "PASS"
        evidence = f"CloudTrail '{trail_name}' is active and logging"
    else:
        status = "FAIL"
        evidence = "No active CloudTrail found"

    return [ComplianceCheck(
        control_id="AU-2",
        description="CloudTrail logging enabled",
        status=status,
        evidence=evidence,
        severity="CRITICAL",
        category="Logging & Monitoring",
    )]


def check_root_usage(mock=True):
    """Check for recent root account usage (from Lesson 8)."""
    if mock:
        root_events = 3
        root_actions = "ConsoleLogin, StopLogging, DeleteBucket"
    else:
        root_events = 0
        root_actions = ""

    if root_events == 0:
        status = "PASS"
        evidence = "No root account activity detected in the review period"
    else:
        status = "FAIL"
        evidence = f"Root account used {root_events} time(s): {root_actions}"

    return [ComplianceCheck(
        control_id="AC-6",
        description="Root account not used for daily operations",
        status=status,
        evidence=evidence,
        severity="CRITICAL",
        category="Identity & Access",
    )]


def check_password_policy(mock=True):
    """Check password policy meets requirements (from Lesson 2)."""
    if mock:
        min_length = 12
        requires_upper = True
        requires_lower = True
        requires_digit = True
        requires_special = True
        meets_all = True
    else:
        meets_all = False

    if meets_all:
        status = "PASS"
        evidence = f"Password policy: min {min_length} chars, upper+lower+digit+special required"
    else:
        status = "FAIL"
        evidence = "Password policy does not meet minimum complexity requirements"

    return [ComplianceCheck(
        control_id="IA-5(1)",
        description="Password policy meets complexity requirements",
        status=status,
        evidence=evidence,
        severity="MEDIUM",
        category="Identity & Access",
    )]


# ═══════════════════════════════════════════════════════════════════════
# REPORT GENERATOR
# ═══════════════════════════════════════════════════════════════════════

def run_all_checks():
    """
    Run all compliance checks and return a list of ComplianceCheck objects.

    Each check function returns a list (some checks produce multiple results),
    so we use .extend() to add them all to one flat list.
    """
    all_checks = []

    # Each function returns a list of ComplianceCheck objects
    all_checks.extend(check_iam_mfa())
    all_checks.extend(check_iam_key_rotation())
    all_checks.extend(check_s3_encryption())
    all_checks.extend(check_s3_public_access())
    all_checks.extend(check_cloudtrail_logging())
    all_checks.extend(check_root_usage())
    all_checks.extend(check_password_policy())

    return all_checks


def print_report(checks):
    """Print a formatted compliance report to the console."""

    total = len(checks)
    passed = len([c for c in checks if c.is_passing()])
    failed = total - passed
    pass_rate = (passed / total * 100) if total > 0 else 0

    print("\n" + "=" * 70)
    print("  AUTOMATED COMPLIANCE ASSESSMENT REPORT")
    print(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Data source: Mock data")
    print("=" * 70)

    print(f"\n  Overall: {passed}/{total} checks passed ({pass_rate:.0f}%)\n")

    # Group by category using a dict
    categories = {}
    for check in checks:
        if check.category not in categories:
            categories[check.category] = []
        categories[check.category].append(check)

    for category, cat_checks in categories.items():
        cat_passed = len([c for c in cat_checks if c.is_passing()])
        print(f"  ┌─ {category} ({cat_passed}/{len(cat_checks)} passed)")

        for check in cat_checks:
            icon = "✅" if check.is_passing() else "❌"
            print(f"  │  {icon} [{check.control_id}] {check.description}")
            print(f"  │     {check.evidence}")

        print(f"  └{'─' * 55}")

    # Failed checks summary
    failed_checks = [c for c in checks if not c.is_passing()]
    if failed_checks:
        print(f"\n  ⚠️  FAILED CHECKS ({len(failed_checks)}):")
        for c in failed_checks:
            sev_icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}.get(c.severity, "⚪")
            print(f"    {sev_icon} [{c.severity}] {c.control_id} — {c.description}")

    print("\n" + "=" * 70 + "\n")
    return passed, failed


def generate_markdown_report(checks, filepath):
    """
    Generate a Markdown compliance report file.

    This demonstrates building a document programmatically using
    string formatting and list joining.
    """
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total = len(checks)
    passed = len([c for c in checks if c.is_passing()])
    failed = total - passed
    pass_rate = (passed / total * 100) if total > 0 else 0

    lines = []

    # ─── Header ───────────────────────────────────────────────────
    lines.append("# Automated Compliance Assessment Report")
    lines.append("")
    lines.append(f"**Generated:** {now}  ")
    lines.append(f"**Data source:** Mock data  ")
    lines.append(f"**Framework:** NIST 800-53  ")
    lines.append("")

    # ─── Summary table ────────────────────────────────────────────
    lines.append("## Executive Summary")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("|--------|-------|")
    lines.append(f"| Total checks | {total} |")
    lines.append(f"| Passed | {passed} |")
    lines.append(f"| Failed | {failed} |")
    lines.append(f"| Pass rate | {pass_rate:.0f}% |")
    lines.append("")

    # Severity breakdown of failures
    failed_checks = [c for c in checks if not c.is_passing()]
    if failed_checks:
        sev_counts = Counter(c.severity for c in failed_checks)
        lines.append("### Failed by Severity")
        lines.append("")
        lines.append("| Severity | Count |")
        lines.append("|----------|-------|")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            count = sev_counts.get(sev, 0)
            if count > 0:
                lines.append(f"| {sev} | {count} |")
        lines.append("")

    # ─── Detailed results by category ─────────────────────────────
    lines.append("## Detailed Results")
    lines.append("")

    categories = {}
    for check in checks:
        if check.category not in categories:
            categories[check.category] = []
        categories[check.category].append(check)

    for category, cat_checks in categories.items():
        cat_passed = len([c for c in cat_checks if c.is_passing()])
        lines.append(f"### {category} ({cat_passed}/{len(cat_checks)} passed)")
        lines.append("")
        lines.append("| Status | Control | Description | Evidence |")
        lines.append("|--------|---------|-------------|----------|")

        for check in cat_checks:
            status_icon = "✅ PASS" if check.is_passing() else "❌ FAIL"
            lines.append(f"| {status_icon} | {check.control_id} | {check.description} | {check.evidence} |")

        lines.append("")

    # ─── Remediation section ──────────────────────────────────────
    if failed_checks:
        lines.append("## Remediation Required")
        lines.append("")

        for i, check in enumerate(failed_checks, 1):
            sev_icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}.get(check.severity, "⚪")
            lines.append(f"### {i}. {sev_icon} [{check.severity}] {check.control_id} — {check.description}")
            lines.append(f"- **Finding:** {check.evidence}")
            lines.append(f"- **Checked:** {check.timestamp}")
            lines.append("")

    # ─── Footer ───────────────────────────────────────────────────
    lines.append("---")
    lines.append(f"*Report generated by GRC Compliance Report Generator (Lesson 9)*")

    # Write the file
    with open(filepath, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    print(f"  📄 Markdown report saved to: {filepath}\n")


def save_json_report(checks, filepath):
    """Save all check results as JSON."""
    output = {
        "report_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total": len(checks),
        "passed": len([c for c in checks if c.is_passing()]),
        "failed": len([c for c in checks if not c.is_passing()]),
        "checks": [c.to_dict() for c in checks],
    }

    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    print(f"  📄 JSON report saved to: {filepath}\n")


# ═══════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("\n  📊 Automated Compliance Report Generator")
    print("  " + "─" * 40)
    print("  [INFO] Running all compliance checks (mock data)...\n")

    # Step 1: Run all checks
    checks = run_all_checks()
    print(f"  [INFO] Completed {len(checks)} checks.\n")

    # Step 2: Print console report
    passed, failed = print_report(checks)

    # Step 3: Generate Markdown report
    md_path = os.path.join(SCRIPT_DIR, "compliance_assessment.md")
    generate_markdown_report(checks, md_path)

    # Step 4: Save JSON
    json_path = os.path.join(SCRIPT_DIR, "compliance_assessment.json")
    save_json_report(checks, json_path)

    print(f"  Done! {passed} passed, {failed} failed.\n")
    sys.exit(0 if failed == 0 else 1)
