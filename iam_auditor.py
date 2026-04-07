"""
Lesson 6: AWS IAM User Auditor
================================
A GRC tool that audits IAM users for MFA, access key age, and last login.
Connects to AWS via boto3 or uses mock data for testing.

Python concepts covered:
  - boto3: Session, client, API calls
  - Functions with return values
  - try/except with AWS-specific errors
  - Mock data pattern for safe testing

GRC relevance:
  - NIST 800-53 AC-2 (Account Management)
  - NIST 800-53 IA-2 (Identification and Authentication)
  - CIS Benchmark 1.10 (Ensure MFA is enabled for all IAM users)
  - CIS Benchmark 1.12 (Ensure access keys are rotated every 90 days)
"""

import sys
import os
import json
from datetime import datetime, timedelta, timezone


# ─── CONFIGURATION ────────────────────────────────────────────────────

USE_MOCK_DATA = True   # Set to False once IAM read permissions are granted
AWS_PROFILE = "grcengtest-1"
AWS_REGION = "us-east-1"

ACCESS_KEY_MAX_AGE_DAYS = 90     # CIS Benchmark: rotate keys every 90 days
INACTIVE_THRESHOLD_DAYS = 90     # Flag users who haven't logged in for 90 days

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


# ─── MOCK DATA ────────────────────────────────────────────────────────
# Mirrors the structure of real boto3 IAM API responses so the same
# parsing code works for both mock and live data.

def get_mock_users():
    """
    Return mock IAM user data that mirrors real boto3 responses.

    In a real AWS account, boto3 returns datetime objects (not strings)
    for date fields. Our mock data uses datetime objects too, so the
    parsing code works identically for both.
    """
    now = datetime.now(timezone.utc)

    return [
        {
            "UserName": "admin-jane",
            "UserId": "AIDA47CRVBNYEXAMPLE01",
            "CreateDate": now - timedelta(days=400),
            "PasswordLastUsed": now - timedelta(days=2),
            "MFADevices": [{"SerialNumber": "arn:aws:iam::891376962416:mfa/admin-jane"}],
            "AccessKeys": [
                {
                    "AccessKeyId": "AKIA47CRVBNYEXAMPL01",
                    "Status": "Active",
                    "CreateDate": now - timedelta(days=45),
                }
            ],
        },
        {
            "UserName": "dev-mike",
            "UserId": "AIDA47CRVBNYEXAMPLE02",
            "CreateDate": now - timedelta(days=300),
            "PasswordLastUsed": now - timedelta(days=120),
            "MFADevices": [],
            "AccessKeys": [
                {
                    "AccessKeyId": "AKIA47CRVBNYEXAMPL02",
                    "Status": "Active",
                    "CreateDate": now - timedelta(days=150),
                },
                {
                    "AccessKeyId": "AKIA47CRVBNYEXAMPL03",
                    "Status": "Active",
                    "CreateDate": now - timedelta(days=30),
                },
            ],
        },
        {
            "UserName": "svc-deploy",
            "UserId": "AIDA47CRVBNYEXAMPLE03",
            "CreateDate": now - timedelta(days=200),
            "PasswordLastUsed": None,  # Service account — never logged into console
            "MFADevices": [],
            "AccessKeys": [
                {
                    "AccessKeyId": "AKIA47CRVBNYEXAMPL04",
                    "Status": "Active",
                    "CreateDate": now - timedelta(days=95),
                }
            ],
        },
        {
            "UserName": "grcengtest-1",
            "UserId": "AIDA47CRVBNYCW6K6QNAF",
            "CreateDate": now - timedelta(days=5),
            "PasswordLastUsed": now - timedelta(days=1),
            "MFADevices": [{"SerialNumber": "arn:aws:iam::891376962416:mfa/grcengtest-1"}],
            "AccessKeys": [
                {
                    "AccessKeyId": "AKIA47CRVBNYEXAMPL05",
                    "Status": "Active",
                    "CreateDate": now - timedelta(days=2),
                }
            ],
        },
        {
            "UserName": "old-contractor",
            "UserId": "AIDA47CRVBNYEXAMPLE05",
            "CreateDate": now - timedelta(days=500),
            "PasswordLastUsed": now - timedelta(days=180),
            "MFADevices": [],
            "AccessKeys": [
                {
                    "AccessKeyId": "AKIA47CRVBNYEXAMPL06",
                    "Status": "Inactive",
                    "CreateDate": now - timedelta(days=365),
                }
            ],
        },
    ]


# ─── LIVE AWS FUNCTIONS ──────────────────────────────────────────────

def get_live_users():
    """
    Fetch IAM users and their details from a real AWS account using boto3.

    boto3.Session() creates a connection using a named profile.
    session.client("iam") creates an IAM client for making API calls.

    Key boto3 IAM API calls:
      - list_users()              → get all IAM users
      - list_mfa_devices()        → check if MFA is enabled
      - list_access_keys()        → get access key metadata
    """
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError, ProfileNotFound

    try:
        # boto3.Session() reads credentials from ~/.aws/credentials
        # using the named profile we configured in Lesson 1
        session = boto3.Session(
            profile_name=AWS_PROFILE,
            region_name=AWS_REGION
        )
        iam = session.client("iam")

    except (NoCredentialsError, ProfileNotFound) as e:
        print(f"\n  ❌ AWS credential error: {e}")
        print(f"  Make sure profile '{AWS_PROFILE}' is configured.\n")
        sys.exit(1)

    users = []

    try:
        # list_users() returns a dict with a "Users" key containing a list
        # Pagination: if there are many users, we'd need a paginator
        # For simplicity, this handles up to 100 users
        response = iam.list_users()

        for user_data in response["Users"]:
            username = user_data["UserName"]

            # Get MFA devices for this user
            mfa_response = iam.list_mfa_devices(UserName=username)
            mfa_devices = mfa_response.get("MFADevices", [])

            # Get access keys for this user
            keys_response = iam.list_access_keys(UserName=username)
            access_keys = keys_response.get("AccessKeyMetadata", [])

            users.append({
                "UserName": username,
                "UserId": user_data.get("UserId", ""),
                "CreateDate": user_data.get("CreateDate"),
                "PasswordLastUsed": user_data.get("PasswordLastUsed"),
                "MFADevices": mfa_devices,
                "AccessKeys": access_keys,
            })

    except ClientError as e:
        # ClientError is the base exception for all AWS API errors
        error_code = e.response["Error"]["Code"]
        error_msg = e.response["Error"]["Message"]
        print(f"\n  ❌ AWS API error ({error_code}): {error_msg}")
        print("  You may need additional IAM permissions. Required policies:")
        print("    - iam:ListUsers")
        print("    - iam:ListMFADevices")
        print("    - iam:ListAccessKeys\n")
        sys.exit(1)

    return users


# ─── AUDIT FUNCTIONS ─────────────────────────────────────────────────
# Each function checks ONE thing and returns a result.
# This makes the code reusable and testable.

def check_mfa(user):
    """
    Check if MFA is enabled for a user.

    Returns a tuple: (passed: bool, detail: str)

    A function that returns a value is more useful than one that just
    prints — the caller decides what to do with the result.
    """
    mfa_devices = user.get("MFADevices", [])
    has_mfa = len(mfa_devices) > 0

    if has_mfa:
        return True, f"MFA enabled ({len(mfa_devices)} device(s))"
    else:
        return False, "No MFA device configured"


def check_access_key_age(user):
    """
    Check if any active access keys are older than the threshold.

    Returns a list of tuples: [(key_id, passed, age_days, status)]
    A user can have 0, 1, or 2 access keys.
    """
    now = datetime.now(timezone.utc)
    access_keys = user.get("AccessKeys", [])
    results = []

    if not access_keys:
        return [("(none)", True, 0, "No keys")]

    for key in access_keys:
        key_id = key.get("AccessKeyId", "unknown")
        status = key.get("Status", "unknown")
        create_date = key.get("CreateDate")

        if create_date:
            # Make sure we're comparing timezone-aware datetimes
            if create_date.tzinfo is None:
                create_date = create_date.replace(tzinfo=timezone.utc)
            age_days = (now - create_date).days
        else:
            age_days = -1

        if status != "Active":
            results.append((key_id, True, age_days, f"Inactive ({age_days}d old)"))
        elif age_days > ACCESS_KEY_MAX_AGE_DAYS:
            results.append((key_id, False, age_days, f"OVERDUE — {age_days}d old (max {ACCESS_KEY_MAX_AGE_DAYS}d)"))
        else:
            results.append((key_id, True, age_days, f"OK — {age_days}d old"))

    return results


def check_last_login(user):
    """
    Check when the user last logged into the AWS console.

    Returns a tuple: (passed: bool, detail: str)
    """
    now = datetime.now(timezone.utc)
    last_used = user.get("PasswordLastUsed")

    if last_used is None:
        return True, "No console login (service account or new user)"

    if last_used.tzinfo is None:
        last_used = last_used.replace(tzinfo=timezone.utc)

    days_ago = (now - last_used).days

    if days_ago > INACTIVE_THRESHOLD_DAYS:
        return False, f"Inactive — last login {days_ago}d ago (threshold {INACTIVE_THRESHOLD_DAYS}d)"
    else:
        return True, f"Active — last login {days_ago}d ago"


# ─── REPORT FUNCTIONS ─────────────────────────────────────────────────

def audit_all_users(users):
    """
    Run all audit checks on all users and collect results.

    Returns a list of audit result dicts.
    """
    results = []

    for user in users:
        username = user["UserName"]

        mfa_passed, mfa_detail = check_mfa(user)
        key_results = check_access_key_age(user)
        login_passed, login_detail = check_last_login(user)

        # Determine overall pass: all checks must pass
        keys_all_pass = all(passed for _, passed, _, _ in key_results)
        overall_pass = mfa_passed and keys_all_pass and login_passed

        results.append({
            "username": username,
            "overall": overall_pass,
            "mfa": {"passed": mfa_passed, "detail": mfa_detail},
            "access_keys": key_results,
            "last_login": {"passed": login_passed, "detail": login_detail},
        })

    return results


def print_report(results):
    """Print a formatted IAM audit report to the console."""

    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print("\n" + "=" * 70)
    print("  AWS IAM USER AUDIT REPORT")
    print(f"  Generated: {now_str}")
    print(f"  Data source: {'Mock data' if USE_MOCK_DATA else f'Live — profile: {AWS_PROFILE}'}")
    print(f"  Thresholds: key age ≤ {ACCESS_KEY_MAX_AGE_DAYS}d, inactive ≤ {INACTIVE_THRESHOLD_DAYS}d")
    print("=" * 70)

    pass_count = 0
    fail_count = 0

    for result in results:
        username = result["username"]
        overall = result["overall"]
        icon = "✅" if overall else "❌"

        if overall:
            pass_count += 1
        else:
            fail_count += 1

        print(f"\n  {icon} {username}")
        print(f"  {'─' * 50}")

        # MFA check
        mfa = result["mfa"]
        mfa_icon = "[+]" if mfa["passed"] else "[-]"
        print(f"    {mfa_icon} MFA:         {mfa['detail']}")

        # Access key checks
        for key_id, passed, age, detail in result["access_keys"]:
            key_icon = "[+]" if passed else "[-]"
            # Show last 4 chars of key ID for identification
            short_id = f"...{key_id[-4:]}" if len(key_id) > 4 else key_id
            print(f"    {key_icon} Key {short_id}:  {detail}")

        # Last login check
        login = result["last_login"]
        login_icon = "[+]" if login["passed"] else "[-]"
        print(f"    {login_icon} Last login:  {login['detail']}")

    # Summary
    total = pass_count + fail_count
    print(f"\n{'=' * 70}")
    print(f"  SUMMARY: {pass_count}/{total} users compliant")

    if fail_count > 0:
        print(f"\n  ❌ {fail_count} user(s) need attention:")
        for result in results:
            if not result["overall"]:
                issues = []
                if not result["mfa"]["passed"]:
                    issues.append("MFA")
                if not all(p for _, p, _, _ in result["access_keys"]):
                    issues.append("Key rotation")
                if not result["last_login"]["passed"]:
                    issues.append("Inactive")
                print(f"     → {result['username']}: {', '.join(issues)}")
    else:
        print("\n  ✅ All users are compliant!")

    print("=" * 70 + "\n")

    return pass_count, fail_count


def save_report_json(results, filepath):
    """Save audit results to a JSON file for evidence/integration."""

    # We need to make the results JSON-serializable
    # (the originals contain tuples which JSON doesn't support)
    serializable = []
    for r in results:
        entry = {
            "username": r["username"],
            "overall_pass": r["overall"],
            "mfa": r["mfa"],
            "access_keys": [
                {"key_id": kid, "passed": p, "age_days": a, "detail": d}
                for kid, p, a, d in r["access_keys"]
            ],
            "last_login": r["last_login"],
        }
        serializable.append(entry)

    output = {
        "report_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "data_source": "mock" if USE_MOCK_DATA else f"live:{AWS_PROFILE}",
        "thresholds": {
            "access_key_max_age_days": ACCESS_KEY_MAX_AGE_DAYS,
            "inactive_threshold_days": INACTIVE_THRESHOLD_DAYS,
        },
        "users": serializable,
    }

    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    print(f"  📄 Audit report saved to: {filepath}\n")


# ─── MAIN ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\n  🔍 AWS IAM User Auditor")
    print("  " + "─" * 35)

    # Step 1: Get user data
    if USE_MOCK_DATA:
        print("  [INFO] Using mock IAM data for testing.")
        users = get_mock_users()
    else:
        print(f"  [INFO] Connecting to AWS (profile: {AWS_PROFILE})...")
        users = get_live_users()

    print(f"  [INFO] Found {len(users)} IAM users.\n")

    # Step 2: Audit
    results = audit_all_users(users)

    # Step 3: Print report
    pass_count, fail_count = print_report(results)

    # Step 4: Save JSON report
    report_path = os.path.join(SCRIPT_DIR, "iam_audit_report.json")
    save_report_json(results, report_path)

    # Exit code
    sys.exit(0 if fail_count == 0 else 1)
