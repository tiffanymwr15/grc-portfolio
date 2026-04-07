"""
Lesson 7: S3 Bucket Security Scanner
======================================
A GRC tool that scans S3 buckets for security misconfigurations:
public access, encryption, versioning, and logging.

Python concepts covered:
  - List comprehensions
  - boto3 S3 API calls
  - Boolean logic and combining conditions
  - JSON output for integration

GRC relevance:
  - CIS Benchmark 2.1.1 (S3 encryption)
  - CIS Benchmark 2.1.2 (S3 public access)
  - NIST 800-53 SC-28 (Protection of Information at Rest)
  - NIST 800-53 AU-2 (Event Logging — access logging)
"""

import sys
import os
import json
from datetime import datetime, timezone


# ─── CONFIGURATION ────────────────────────────────────────────────────

USE_MOCK_DATA = True   # Set to False once S3 read permissions are granted
AWS_PROFILE = "grcengtest-1"
AWS_REGION = "us-east-1"

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


# ─── MOCK DATA ────────────────────────────────────────────────────────
# Simulates the results of multiple boto3 S3 API calls for each bucket.

def get_mock_buckets():
    """
    Return mock S3 bucket data that mirrors what we'd get from
    multiple boto3 API calls combined together.
    """
    now = datetime.now(timezone.utc)

    return [
        {
            "Name": "company-logs-prod",
            "CreationDate": "2025-06-15",
            "Region": "us-east-1",
            "Encryption": {"SSEAlgorithm": "aws:kms", "KMSMasterKeyID": "arn:aws:kms:us-east-1:891376962416:key/abc-123"},
            "Versioning": "Enabled",
            "PublicAccessBlock": {"BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True},
            "Logging": {"TargetBucket": "company-access-logs", "TargetPrefix": "logs/company-logs-prod/"},
        },
        {
            "Name": "dev-test-data",
            "CreationDate": "2025-09-20",
            "Region": "us-east-1",
            "Encryption": None,
            "Versioning": "Suspended",
            "PublicAccessBlock": {"BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True},
            "Logging": None,
        },
        {
            "Name": "public-assets-demo",
            "CreationDate": "2026-01-10",
            "Region": "us-east-1",
            "Encryption": {"SSEAlgorithm": "AES256", "KMSMasterKeyID": None},
            "Versioning": "Disabled",
            "PublicAccessBlock": {"BlockPublicAcls": False, "IgnorePublicAcls": False, "BlockPublicPolicy": False, "RestrictPublicBuckets": False},
            "Logging": None,
        },
        {
            "Name": "backup-archive-2025",
            "CreationDate": "2025-03-01",
            "Region": "us-east-1",
            "Encryption": {"SSEAlgorithm": "aws:kms", "KMSMasterKeyID": "arn:aws:kms:us-east-1:891376962416:key/def-456"},
            "Versioning": "Enabled",
            "PublicAccessBlock": {"BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True},
            "Logging": {"TargetBucket": "company-access-logs", "TargetPrefix": "logs/backup-archive/"},
        },
        {
            "Name": "marketing-uploads",
            "CreationDate": "2026-02-14",
            "Region": "us-west-2",
            "Encryption": {"SSEAlgorithm": "AES256", "KMSMasterKeyID": None},
            "Versioning": "Disabled",
            "PublicAccessBlock": {"BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": False, "RestrictPublicBuckets": False},
            "Logging": None,
        },
        {
            "Name": "company-access-logs",
            "CreationDate": "2025-06-15",
            "Region": "us-east-1",
            "Encryption": {"SSEAlgorithm": "AES256", "KMSMasterKeyID": None},
            "Versioning": "Enabled",
            "PublicAccessBlock": {"BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True},
            "Logging": None,
        },
    ]


# ─── LIVE AWS FUNCTIONS ──────────────────────────────────────────────

def get_live_buckets():
    """
    Fetch S3 bucket details from a real AWS account using boto3.

    This requires multiple API calls per bucket because S3 stores
    configuration in separate endpoints:
      - list_buckets()                    → bucket names
      - get_bucket_encryption()           → encryption config
      - get_bucket_versioning()           → versioning status
      - get_public_access_block()         → public access settings
      - get_bucket_logging()              → access logging config
      - get_bucket_location()             → region
    """
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError, ProfileNotFound

    try:
        session = boto3.Session(profile_name=AWS_PROFILE, region_name=AWS_REGION)
        s3 = session.client("s3")
    except (NoCredentialsError, ProfileNotFound) as e:
        print(f"\n  ❌ AWS credential error: {e}")
        sys.exit(1)

    buckets = []

    try:
        response = s3.list_buckets()
    except ClientError as e:
        print(f"\n  ❌ AWS API error: {e}")
        sys.exit(1)

    for bucket_info in response.get("Buckets", []):
        name = bucket_info["Name"]
        creation_date = bucket_info.get("CreationDate", "")
        if hasattr(creation_date, "strftime"):
            creation_date = creation_date.strftime("%Y-%m-%d")

        bucket = {
            "Name": name,
            "CreationDate": creation_date,
            "Region": None,
            "Encryption": None,
            "Versioning": "Disabled",
            "PublicAccessBlock": None,
            "Logging": None,
        }

        # Each of these calls can fail independently, so we wrap each in try/except
        # get_bucket_location
        try:
            loc = s3.get_bucket_location(Bucket=name)
            bucket["Region"] = loc.get("LocationConstraint") or "us-east-1"
        except ClientError:
            bucket["Region"] = "unknown"

        # get_bucket_encryption
        try:
            enc = s3.get_bucket_encryption(Bucket=name)
            rules = enc.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
            if rules:
                sse = rules[0].get("ApplyServerSideEncryptionByDefault", {})
                bucket["Encryption"] = {
                    "SSEAlgorithm": sse.get("SSEAlgorithm"),
                    "KMSMasterKeyID": sse.get("KMSMasterKeyID"),
                }
        except ClientError as e:
            if e.response["Error"]["Code"] == "ServerSideEncryptionConfigurationNotFoundError":
                bucket["Encryption"] = None
            # else leave as None

        # get_bucket_versioning
        try:
            ver = s3.get_bucket_versioning(Bucket=name)
            bucket["Versioning"] = ver.get("Status", "Disabled")
        except ClientError:
            pass

        # get_public_access_block
        try:
            pab = s3.get_public_access_block(Bucket=name)
            bucket["PublicAccessBlock"] = pab.get("PublicAccessBlockConfiguration")
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
                bucket["PublicAccessBlock"] = None

        # get_bucket_logging
        try:
            log = s3.get_bucket_logging(Bucket=name)
            bucket["Logging"] = log.get("LoggingEnabled")
        except ClientError:
            pass

        buckets.append(bucket)

    return buckets


# ─── SECURITY CHECK FUNCTIONS ────────────────────────────────────────

def check_encryption(bucket):
    """Check if server-side encryption is enabled."""
    enc = bucket.get("Encryption")
    if enc and enc.get("SSEAlgorithm"):
        algo = enc["SSEAlgorithm"]
        kms = enc.get("KMSMasterKeyID")
        detail = f"{algo}" + (f" (KMS: ...{kms[-8:]})" if kms else "")
        return True, detail
    return False, "No encryption configured"


def check_versioning(bucket):
    """Check if versioning is enabled."""
    status = bucket.get("Versioning", "Disabled")
    if status == "Enabled":
        return True, "Versioning enabled"
    elif status == "Suspended":
        return False, "Versioning SUSPENDED (was enabled, now off)"
    else:
        return False, "Versioning not enabled"


def check_public_access(bucket):
    """
    Check if the public access block is fully enabled.

    All four settings must be True for full protection:
      - BlockPublicAcls
      - IgnorePublicAcls
      - BlockPublicPolicy
      - RestrictPublicBuckets

    This is where LIST COMPREHENSIONS shine:
      all([settings[k] for k in settings])
    is a compact way to check that every value is True.
    """
    pab = bucket.get("PublicAccessBlock")

    if not pab:
        return False, "No public access block configured"

    # List comprehension: build a list of True/False from all 4 settings
    # [True, True, False, True] → not all True → FAIL
    all_blocked = all([pab.get(key, False) for key in [
        "BlockPublicAcls",
        "IgnorePublicAcls",
        "BlockPublicPolicy",
        "RestrictPublicBuckets",
    ]])

    if all_blocked:
        return True, "All public access blocked"

    # List comprehension to find which settings are off
    # This filters only the items where the value is False
    open_settings = [key for key, val in pab.items() if not val]
    return False, f"PUBLIC — {', '.join(open_settings)} not blocked"


def check_logging(bucket):
    """Check if access logging is enabled."""
    log = bucket.get("Logging")
    if log:
        target = log.get("TargetBucket", "unknown")
        return True, f"Logging to {target}"
    return False, "Access logging not enabled"


# ─── SCAN AND REPORT ─────────────────────────────────────────────────

def scan_all_buckets(buckets):
    """
    Run all security checks on all buckets.

    Uses a LIST COMPREHENSION to build the results list in one expression:
        results = [scan_one(b) for b in buckets]
    This is equivalent to:
        results = []
        for b in buckets:
            results.append(scan_one(b))
    """

    def scan_one(bucket):
        """Scan a single bucket and return its results dict."""
        enc_pass, enc_detail = check_encryption(bucket)
        ver_pass, ver_detail = check_versioning(bucket)
        pub_pass, pub_detail = check_public_access(bucket)
        log_pass, log_detail = check_logging(bucket)

        # all() with a list of booleans — True only if every check passed
        overall = all([enc_pass, ver_pass, pub_pass, log_pass])

        return {
            "name": bucket["Name"],
            "region": bucket.get("Region", "unknown"),
            "created": bucket.get("CreationDate", "unknown"),
            "overall": overall,
            "checks": {
                "encryption": {"passed": enc_pass, "detail": enc_detail},
                "versioning": {"passed": ver_pass, "detail": ver_detail},
                "public_access": {"passed": pub_pass, "detail": pub_detail},
                "logging": {"passed": log_pass, "detail": log_detail},
            },
        }

    # ── LIST COMPREHENSION ────────────────────────────────────────
    # Builds the full results list in a single, readable line.
    # Equivalent to a for-loop + append, but more Pythonic.
    results = [scan_one(bucket) for bucket in buckets]

    return results


def print_report(results):
    """Print a formatted S3 security scan report."""

    print("\n" + "=" * 70)
    print("  S3 BUCKET SECURITY SCAN REPORT")
    print(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Data source: {'Mock data' if USE_MOCK_DATA else f'Live — profile: {AWS_PROFILE}'}")
    print("=" * 70)

    pass_count = 0
    fail_count = 0

    for result in results:
        overall = result["overall"]
        icon = "✅" if overall else "❌"

        if overall:
            pass_count += 1
        else:
            fail_count += 1

        print(f"\n  {icon} {result['name']}  ({result['region']})")
        print(f"  {'─' * 55}")

        for check_name, check in result["checks"].items():
            chk_icon = "[+]" if check["passed"] else "[-]"
            # .replace("_", " ").title() turns "public_access" into "Public Access"
            label = check_name.replace("_", " ").title()
            print(f"    {chk_icon} {label:<18} {check['detail']}")

    # ── Summary using list comprehensions ─────────────────────────
    # Count how many buckets failed each specific check
    enc_fails = len([r for r in results if not r["checks"]["encryption"]["passed"]])
    ver_fails = len([r for r in results if not r["checks"]["versioning"]["passed"]])
    pub_fails = len([r for r in results if not r["checks"]["public_access"]["passed"]])
    log_fails = len([r for r in results if not r["checks"]["logging"]["passed"]])

    total = len(results)
    print(f"\n{'=' * 70}")
    print(f"  SUMMARY: {pass_count}/{total} buckets fully compliant\n")
    print(f"  {'Check':<20} {'Failing'}")
    print(f"  {'-'*20} {'-'*10}")
    print(f"  {'Encryption':<20} {enc_fails}/{total}")
    print(f"  {'Versioning':<20} {ver_fails}/{total}")
    print(f"  {'Public Access':<20} {pub_fails}/{total}")
    print(f"  {'Access Logging':<20} {log_fails}/{total}")

    if fail_count > 0:
        print(f"\n  ❌ {fail_count} bucket(s) need remediation:")
        # List comprehension to filter only failed buckets
        failed_names = [r["name"] for r in results if not r["overall"]]
        for name in failed_names:
            print(f"     → {name}")
    else:
        print(f"\n  ✅ All buckets are compliant!")

    print("=" * 70 + "\n")

    return pass_count, fail_count


def save_report_json(results, filepath):
    """Save scan results to a JSON file."""
    output = {
        "report_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "data_source": "mock" if USE_MOCK_DATA else f"live:{AWS_PROFILE}",
        "total_buckets": len(results),
        "compliant": len([r for r in results if r["overall"]]),
        "non_compliant": len([r for r in results if not r["overall"]]),
        "buckets": results,
    }

    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    print(f"  📄 Scan report saved to: {filepath}\n")


# ─── MAIN ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\n  🪣 S3 Bucket Security Scanner")
    print("  " + "─" * 35)

    if USE_MOCK_DATA:
        print("  [INFO] Using mock S3 data for testing.")
        buckets = get_mock_buckets()
    else:
        print(f"  [INFO] Connecting to AWS (profile: {AWS_PROFILE})...")
        buckets = get_live_buckets()

    print(f"  [INFO] Found {len(buckets)} S3 buckets.\n")

    # Scan
    results = scan_all_buckets(buckets)

    # Report
    pass_count, fail_count = print_report(results)

    # Save JSON
    report_path = os.path.join(SCRIPT_DIR, "s3_scan_report.json")
    save_report_json(results, report_path)

    sys.exit(0 if fail_count == 0 else 1)
