"""
Lesson 12: Infrastructure Drift Detector
==========================================
A GRC tool that captures baseline snapshots of AWS resource configurations,
saves them to JSON, re-scans, and reports any drift (added, removed, changed).

Python concepts covered:
  - Advanced boto3 usage (multiple services, pagination)
  - Snapshotting complex state to JSON
  - Diffing nested data structures (manual comparison)
  - deepcopy for safe object cloning
  - Sets for detecting added/removed items
  - Recursive dict comparison

GRC relevance:
  - NIST 800-53 CM-3 (Configuration Change Control)
  - NIST 800-53 CM-6 (Configuration Settings)
  - NIST 800-53 SI-7 (Software, Firmware, and Information Integrity)
  - CIS Benchmark — detecting unauthorized changes
"""

import sys
import os
import json
import copy
from datetime import datetime


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BASELINE_FILE = os.path.join(SCRIPT_DIR, "drift_baseline.json")


# ═══════════════════════════════════════════════════════════════════════
# MOCK AWS STATE — Simulates what boto3 would return
# ═══════════════════════════════════════════════════════════════════════
# Two snapshots: the "baseline" and the "current" state.
# The differences between them represent drift.

def get_mock_baseline():
    """
    Simulated AWS state at baseline capture time.
    This is the "known good" configuration.
    """
    return {
        "snapshot_time": "2026-04-01T10:00:00Z",
        "security_groups": {
            "sg-web-prod": {
                "GroupId": "sg-0abc111",
                "GroupName": "web-prod",
                "Description": "Production web servers",
                "IngressRules": [
                    {"Protocol": "tcp", "FromPort": 443, "ToPort": 443, "Source": "0.0.0.0/0"},
                    {"Protocol": "tcp", "FromPort": 80, "ToPort": 80, "Source": "0.0.0.0/0"},
                ],
                "EgressRules": [
                    {"Protocol": "-1", "FromPort": 0, "ToPort": 0, "Source": "0.0.0.0/0"},
                ],
            },
            "sg-db-prod": {
                "GroupId": "sg-0abc222",
                "GroupName": "db-prod",
                "Description": "Production database",
                "IngressRules": [
                    {"Protocol": "tcp", "FromPort": 5432, "ToPort": 5432, "Source": "10.0.0.0/8"},
                ],
                "EgressRules": [
                    {"Protocol": "-1", "FromPort": 0, "ToPort": 0, "Source": "0.0.0.0/0"},
                ],
            },
            "sg-internal": {
                "GroupId": "sg-0abc333",
                "GroupName": "internal-only",
                "Description": "Internal services",
                "IngressRules": [
                    {"Protocol": "tcp", "FromPort": 8080, "ToPort": 8080, "Source": "10.0.0.0/8"},
                ],
                "EgressRules": [
                    {"Protocol": "-1", "FromPort": 0, "ToPort": 0, "Source": "0.0.0.0/0"},
                ],
            },
        },
        "s3_buckets": {
            "company-logs-prod": {
                "Encryption": "aws:kms",
                "Versioning": "Enabled",
                "PublicAccessBlocked": True,
                "LoggingEnabled": True,
            },
            "dev-test-data": {
                "Encryption": "AES256",
                "Versioning": "Suspended",
                "PublicAccessBlocked": True,
                "LoggingEnabled": False,
            },
            "backup-archive": {
                "Encryption": "aws:kms",
                "Versioning": "Enabled",
                "PublicAccessBlocked": True,
                "LoggingEnabled": True,
            },
        },
        "iam_policies": {
            "admin-jane": {
                "MFA": True,
                "AccessKeyAge": 45,
                "AttachedPolicies": ["IAMFullAccess", "S3FullAccess"],
                "Groups": ["admins"],
            },
            "dev-mike": {
                "MFA": True,
                "AccessKeyAge": 30,
                "AttachedPolicies": ["PowerUserAccess"],
                "Groups": ["developers"],
            },
            "svc-deploy": {
                "MFA": False,
                "AccessKeyAge": 60,
                "AttachedPolicies": ["CodeDeployRole"],
                "Groups": ["service-accounts"],
            },
        },
    }


def get_mock_current():
    """
    Simulated AWS state at re-scan time.
    Contains intentional drift from the baseline.

    We use copy.deepcopy() to start from baseline and then mutate.
    deepcopy creates a completely independent copy — changes to the
    copy don't affect the original. This is critical when working
    with nested dicts/lists (regular copy only copies the top level).
    """
    state = copy.deepcopy(get_mock_baseline())
    state["snapshot_time"] = "2026-04-05T11:00:00Z"

    # ─── DRIFT 1: SSH opened on web security group (CRITICAL) ────
    state["security_groups"]["sg-web-prod"]["IngressRules"].append(
        {"Protocol": "tcp", "FromPort": 22, "ToPort": 22, "Source": "0.0.0.0/0"}
    )

    # ─── DRIFT 2: Security group deleted (HIGH) ─────────────────
    del state["security_groups"]["sg-internal"]

    # ─── DRIFT 3: New unknown security group appeared (MEDIUM) ───
    state["security_groups"]["sg-temp-debug"] = {
        "GroupId": "sg-0abc999",
        "GroupName": "temp-debug",
        "Description": "Temporary debug access",
        "IngressRules": [
            {"Protocol": "tcp", "FromPort": 22, "ToPort": 22, "Source": "0.0.0.0/0"},
            {"Protocol": "tcp", "FromPort": 3389, "ToPort": 3389, "Source": "0.0.0.0/0"},
        ],
        "EgressRules": [
            {"Protocol": "-1", "FromPort": 0, "ToPort": 0, "Source": "0.0.0.0/0"},
        ],
    }

    # ─── DRIFT 4: S3 bucket encryption removed (HIGH) ───────────
    state["s3_buckets"]["dev-test-data"]["Encryption"] = None

    # ─── DRIFT 5: S3 bucket public access unblocked (CRITICAL) ──
    state["s3_buckets"]["dev-test-data"]["PublicAccessBlocked"] = False

    # ─── DRIFT 6: New S3 bucket appeared (LOW) ──────────────────
    state["s3_buckets"]["temp-uploads-042026"] = {
        "Encryption": None,
        "Versioning": "Disabled",
        "PublicAccessBlocked": False,
        "LoggingEnabled": False,
    }

    # ─── DRIFT 7: IAM policy escalation (CRITICAL) ──────────────
    state["iam_policies"]["dev-mike"]["AttachedPolicies"].append("AdministratorAccess")

    # ─── DRIFT 8: Access key aged (MEDIUM) ──────────────────────
    state["iam_policies"]["svc-deploy"]["AccessKeyAge"] = 95

    # ─── DRIFT 9: MFA disabled (HIGH) ───────────────────────────
    state["iam_policies"]["dev-mike"]["MFA"] = False

    # ─── DRIFT 10: New IAM user appeared (MEDIUM) ───────────────
    state["iam_policies"]["unknown-user"] = {
        "MFA": False,
        "AccessKeyAge": 1,
        "AttachedPolicies": ["AdministratorAccess"],
        "Groups": [],
    }

    return state


# ═══════════════════════════════════════════════════════════════════════
# DIFFING ENGINE
# ═══════════════════════════════════════════════════════════════════════
#
# Comparing nested data structures is one of the harder problems in
# programming. We use three techniques:
#   1. Set operations (added/removed keys)
#   2. Recursive value comparison (changed fields)
#   3. List diffing (added/removed items in lists)

class DriftFinding:
    """Represents a single drift finding."""

    def __init__(self, category, resource, drift_type, severity, detail, baseline_val=None, current_val=None):
        self.category = category       # "security_groups", "s3_buckets", "iam_policies"
        self.resource = resource       # resource name/ID
        self.drift_type = drift_type   # "added", "removed", "changed"
        self.severity = severity       # "CRITICAL", "HIGH", "MEDIUM", "LOW"
        self.detail = detail           # human-readable description
        self.baseline_val = baseline_val
        self.current_val = current_val

    def to_dict(self):
        result = {
            "category": self.category,
            "resource": self.resource,
            "drift_type": self.drift_type,
            "severity": self.severity,
            "detail": self.detail,
        }
        if self.baseline_val is not None:
            result["baseline"] = self.baseline_val
        if self.current_val is not None:
            result["current"] = self.current_val
        return result


def diff_keys(baseline_dict, current_dict):
    """
    Use SET OPERATIONS to find added and removed keys.

    set(dict.keys()) converts dict keys to a set.
    Set math:
      current - baseline = keys in current but NOT in baseline (added)
      baseline - current = keys in baseline but NOT in current (removed)
      baseline & current = keys in BOTH (may have changed values)
    """
    baseline_keys = set(baseline_dict.keys())
    current_keys = set(current_dict.keys())

    added = current_keys - baseline_keys
    removed = baseline_keys - current_keys
    common = baseline_keys & current_keys

    return added, removed, common


def diff_values(baseline, current, path=""):
    """
    Recursively compare two values and return a list of differences.

    This handles:
      - Dicts: recurse into matching keys
      - Lists: compare as sets of items (order-insensitive)
      - Scalars: direct equality check

    The 'path' parameter tracks where we are in the nested structure,
    building strings like "IngressRules[2].Source" for readable output.
    """
    changes = []

    if type(baseline) != type(current):
        changes.append((path or "value", baseline, current))

    elif isinstance(baseline, dict):
        all_keys = set(baseline.keys()) | set(current.keys())
        for key in all_keys:
            sub_path = f"{path}.{key}" if path else key
            if key not in baseline:
                changes.append((sub_path, "<missing>", current[key]))
            elif key not in current:
                changes.append((sub_path, baseline[key], "<missing>"))
            else:
                changes.extend(diff_values(baseline[key], current[key], sub_path))

    elif isinstance(baseline, list):
        # Convert list items to comparable strings for set operations
        baseline_strs = [json.dumps(item, sort_keys=True) if isinstance(item, (dict, list)) else str(item) for item in baseline]
        current_strs = [json.dumps(item, sort_keys=True) if isinstance(item, (dict, list)) else str(item) for item in current]

        added = set(current_strs) - set(baseline_strs)
        removed = set(baseline_strs) - set(current_strs)

        for item in added:
            changes.append((f"{path}[+]", None, item))
        for item in removed:
            changes.append((f"{path}[-]", item, None))

    else:
        # Scalar comparison
        if baseline != current:
            changes.append((path or "value", baseline, current))

    return changes


# ═══════════════════════════════════════════════════════════════════════
# DRIFT DETECTION PER CATEGORY
# ═══════════════════════════════════════════════════════════════════════

def detect_sg_drift(baseline_sgs, current_sgs):
    """Detect drift in security groups."""
    findings = []
    added, removed, common = diff_keys(baseline_sgs, current_sgs)

    for name in added:
        sg = current_sgs[name]
        # Check if the new SG has dangerous rules
        has_ssh = any(r.get("FromPort") == 22 and r.get("Source") == "0.0.0.0/0"
                      for r in sg.get("IngressRules", []))
        severity = "HIGH" if has_ssh else "MEDIUM"
        findings.append(DriftFinding(
            "security_groups", name, "added", severity,
            f"New security group '{name}' appeared",
            current_val=sg,
        ))

    for name in removed:
        findings.append(DriftFinding(
            "security_groups", name, "removed", "HIGH",
            f"Security group '{name}' was deleted",
            baseline_val=baseline_sgs[name],
        ))

    for name in common:
        changes = diff_values(baseline_sgs[name], current_sgs[name])
        if changes:
            # Check for SSH/RDP being opened
            critical = any("22" in str(c) or "3389" in str(c) for c in changes)
            severity = "CRITICAL" if critical else "MEDIUM"
            detail_parts = [f"{path}: {old} → {new}" for path, old, new in changes[:5]]
            findings.append(DriftFinding(
                "security_groups", name, "changed", severity,
                f"Security group '{name}' modified: {'; '.join(detail_parts)}",
                baseline_val=str(changes),
            ))

    return findings


def detect_s3_drift(baseline_s3, current_s3):
    """Detect drift in S3 bucket configurations."""
    findings = []
    added, removed, common = diff_keys(baseline_s3, current_s3)

    for name in added:
        bucket = current_s3[name]
        no_enc = bucket.get("Encryption") is None
        public = not bucket.get("PublicAccessBlocked", True)
        severity = "HIGH" if (no_enc or public) else "LOW"
        findings.append(DriftFinding(
            "s3_buckets", name, "added", severity,
            f"New S3 bucket '{name}' appeared (encrypted: {not no_enc}, public blocked: {not public})",
            current_val=bucket,
        ))

    for name in removed:
        findings.append(DriftFinding(
            "s3_buckets", name, "removed", "HIGH",
            f"S3 bucket '{name}' was deleted",
            baseline_val=baseline_s3[name],
        ))

    for name in common:
        changes = diff_values(baseline_s3[name], current_s3[name])
        if changes:
            # Encryption removal or public access unblocking is critical
            critical = any("Encryption" in str(c) or "PublicAccess" in str(c) for c in changes)
            severity = "CRITICAL" if critical else "MEDIUM"
            detail_parts = [f"{path}: {old} → {new}" for path, old, new in changes]
            findings.append(DriftFinding(
                "s3_buckets", name, "changed", severity,
                f"S3 bucket '{name}' modified: {'; '.join(detail_parts)}",
            ))

    return findings


def detect_iam_drift(baseline_iam, current_iam):
    """Detect drift in IAM user configurations."""
    findings = []
    added, removed, common = diff_keys(baseline_iam, current_iam)

    for name in added:
        user = current_iam[name]
        has_admin = "AdministratorAccess" in user.get("AttachedPolicies", [])
        severity = "CRITICAL" if has_admin else "MEDIUM"
        findings.append(DriftFinding(
            "iam_policies", name, "added", severity,
            f"New IAM user '{name}' appeared (admin: {has_admin}, MFA: {user.get('MFA')})",
            current_val=user,
        ))

    for name in removed:
        findings.append(DriftFinding(
            "iam_policies", name, "removed", "MEDIUM",
            f"IAM user '{name}' was removed",
            baseline_val=baseline_iam[name],
        ))

    for name in common:
        changes = diff_values(baseline_iam[name], current_iam[name])
        if changes:
            # MFA disabled or policy escalation is critical
            mfa_change = any("MFA" in str(c) for c in changes)
            policy_change = any("Administrator" in str(c) or "Policies" in str(c) for c in changes)
            if mfa_change or policy_change:
                severity = "CRITICAL"
            else:
                severity = "MEDIUM"
            detail_parts = [f"{path}: {old} → {new}" for path, old, new in changes]
            findings.append(DriftFinding(
                "iam_policies", name, "changed", severity,
                f"IAM user '{name}' modified: {'; '.join(detail_parts)}",
            ))

    return findings


def detect_all_drift(baseline, current):
    """Run drift detection across all resource categories."""
    findings = []

    findings.extend(detect_sg_drift(
        baseline.get("security_groups", {}),
        current.get("security_groups", {}),
    ))
    findings.extend(detect_s3_drift(
        baseline.get("s3_buckets", {}),
        current.get("s3_buckets", {}),
    ))
    findings.extend(detect_iam_drift(
        baseline.get("iam_policies", {}),
        current.get("iam_policies", {}),
    ))

    # Sort by severity
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    findings.sort(key=lambda f: severity_order.get(f.severity, 99))

    return findings


# ═══════════════════════════════════════════════════════════════════════
# BASELINE MANAGEMENT
# ═══════════════════════════════════════════════════════════════════════

def save_baseline(state, filepath):
    """Save a baseline snapshot to a JSON file."""
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2, ensure_ascii=False)
    print(f"  📄 Baseline saved to: {filepath}")


def load_baseline(filepath):
    """Load a baseline snapshot from a JSON file."""
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return None
    except json.JSONDecodeError as e:
        print(f"  ❌ Error reading baseline: {e}")
        return None


# ═══════════════════════════════════════════════════════════════════════
# REPORT
# ═══════════════════════════════════════════════════════════════════════

SEVERITY_ICONS = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}
DRIFT_ICONS = {"added": "➕", "removed": "➖", "changed": "🔄"}


def print_report(findings, baseline_time, current_time):
    """Print a formatted drift detection report."""

    print("\n" + "=" * 70)
    print("  INFRASTRUCTURE DRIFT DETECTION REPORT")
    print(f"  Baseline:  {baseline_time}")
    print(f"  Current:   {current_time}")
    print(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)

    if not findings:
        print("\n  ✅ No drift detected — infrastructure matches baseline.\n")
        print("=" * 70 + "\n")
        return 0

    # Summary counts
    by_severity = {}
    by_type = {}
    by_category = {}
    for f in findings:
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
        by_type[f.drift_type] = by_type.get(f.drift_type, 0) + 1
        by_category[f.category] = by_category.get(f.category, 0) + 1

    print(f"\n  ⚠️  {len(findings)} DRIFT FINDING(S) DETECTED\n")

    print(f"  {'Severity':<12} {'Count'}")
    print(f"  {'-'*12} {'-'*6}")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        count = by_severity.get(sev, 0)
        if count > 0:
            print(f"  {SEVERITY_ICONS.get(sev, '')} {sev:<9} {count}")

    print(f"\n  {'Type':<12} {'Count'}")
    print(f"  {'-'*12} {'-'*6}")
    for dtype in ["added", "removed", "changed"]:
        count = by_type.get(dtype, 0)
        if count > 0:
            print(f"  {DRIFT_ICONS.get(dtype, '')} {dtype:<9} {count}")

    # Detailed findings
    print(f"\n{'=' * 70}")
    print("  DETAILED FINDINGS")
    print("=" * 70)

    current_category = None
    for finding in findings:
        if finding.category != current_category:
            current_category = finding.category
            label = current_category.replace("_", " ").title()
            cat_count = by_category.get(current_category, 0)
            print(f"\n  ┌─ {label} ({cat_count} finding(s))")

        sev_icon = SEVERITY_ICONS.get(finding.severity, "⚪")
        drift_icon = DRIFT_ICONS.get(finding.drift_type, "?")
        print(f"  │")
        print(f"  │  {sev_icon} [{finding.severity}] {drift_icon} {finding.drift_type.upper()}: {finding.resource}")
        print(f"  │     {finding.detail}")

    print(f"  └{'─' * 55}")

    # Final verdict
    crit = by_severity.get("CRITICAL", 0)
    high = by_severity.get("HIGH", 0)
    print(f"\n{'=' * 70}")
    print(f"  VERDICT: {len(findings)} drift(s) — {crit} critical, {high} high")
    if crit > 0:
        print("  🚨 IMMEDIATE ACTION REQUIRED — critical drift detected")
    elif high > 0:
        print("  ⚠️  Investigation recommended — high-severity drift detected")
    else:
        print("  ℹ️  Low-risk drift — review at next audit cycle")
    print("=" * 70 + "\n")

    return len(findings)


def save_report_json(findings, baseline_time, current_time, filepath):
    """Save drift report as JSON."""
    output = {
        "report_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "baseline_time": baseline_time,
        "current_time": current_time,
        "total_findings": len(findings),
        "by_severity": {},
        "findings": [f.to_dict() for f in findings],
    }

    for f in findings:
        output["by_severity"][f.severity] = output["by_severity"].get(f.severity, 0) + 1

    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    print(f"  📄 Drift report saved to: {filepath}\n")


# ═══════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════

def show_usage():
    print("""
  Usage:
    drift_detector.py baseline     — Capture and save a baseline snapshot
    drift_detector.py scan         — Scan current state and compare to baseline
    drift_detector.py demo         — Run a demo with mock data (no baseline file needed)
    drift_detector.py help         — Show this message
    """)


if __name__ == "__main__":
    print(f"\n  🔎 Infrastructure Drift Detector")
    print(f"  {'─' * 40}")

    command = sys.argv[1].lower() if len(sys.argv) > 1 else "demo"

    if command == "help":
        show_usage()
        sys.exit(0)

    elif command == "baseline":
        print("  [INFO] Capturing baseline snapshot (mock data)...")
        state = get_mock_baseline()
        save_baseline(state, BASELINE_FILE)
        resource_count = (
            len(state.get("security_groups", {})) +
            len(state.get("s3_buckets", {})) +
            len(state.get("iam_policies", {}))
        )
        print(f"  [INFO] Baseline captured: {resource_count} resources across 3 categories.\n")

    elif command == "scan":
        print("  [INFO] Loading baseline...")
        baseline = load_baseline(BASELINE_FILE)
        if baseline is None:
            print("  ❌ No baseline found. Run 'baseline' command first.")
            sys.exit(1)

        print(f"  [INFO] Baseline from: {baseline.get('snapshot_time', 'unknown')}")
        print("  [INFO] Scanning current state (mock data)...")
        current = get_mock_current()

        findings = detect_all_drift(baseline, current)
        drift_count = print_report(
            findings,
            baseline.get("snapshot_time", "unknown"),
            current.get("snapshot_time", "unknown"),
        )

        report_path = os.path.join(SCRIPT_DIR, "drift_report.json")
        save_report_json(findings, baseline.get("snapshot_time"), current.get("snapshot_time"), report_path)

        sys.exit(0 if drift_count == 0 else 1)

    elif command == "demo":
        print("  [INFO] Running demo with mock baseline and current state...")
        baseline = get_mock_baseline()
        current = get_mock_current()

        findings = detect_all_drift(baseline, current)
        drift_count = print_report(
            findings,
            baseline.get("snapshot_time", "unknown"),
            current.get("snapshot_time", "unknown"),
        )

        report_path = os.path.join(SCRIPT_DIR, "drift_report.json")
        save_report_json(findings, baseline.get("snapshot_time"), current.get("snapshot_time"), report_path)

        sys.exit(0 if drift_count == 0 else 1)

    else:
        print(f"  ❌ Unknown command: '{command}'")
        show_usage()
        sys.exit(1)
