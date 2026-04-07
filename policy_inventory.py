"""
Lesson 4: CSV Policy Inventory Parser
=======================================
A GRC tool that reads a policy inventory CSV, analyzes compliance,
and flags issues for remediation.

Python concepts covered:
  - csv module: csv.DictReader, csv.DictWriter
  - Lists and for loops
  - datetime date math (timedelta, strptime)
  - try/except error handling
  - Filtering and aggregation

GRC relevance:
  - NIST 800-53 PM-1 (Information Security Program Plan)
  - NIST 800-53 PL-1 (Policy and Procedures)
  - Annual policy review requirements
"""

import csv
import sys
import os
from datetime import datetime, timedelta


# ─── CONFIGURATION ────────────────────────────────────────────────────

REVIEW_THRESHOLD_DAYS = 365   # Policies older than this are "overdue"
DATE_FORMAT = "%Y-%m-%d"      # Expected date format in the CSV

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_INPUT = os.path.join(SCRIPT_DIR, "policy_inventory.csv")
DEFAULT_OUTPUT = os.path.join(SCRIPT_DIR, "flagged_policies.csv")


# ─── CORE FUNCTIONS ──────────────────────────────────────────────────

def load_policies(filepath):
    """
    Read a CSV file and return a list of dictionaries.

    csv.DictReader reads each row as a dictionary where the keys
    come from the header row. This is much easier than working with
    raw lists because you can access fields by name:
        row["policy_name"] instead of row[0]
    """
    policies = []

    # try/except catches errors so the program doesn't crash
    # FileNotFoundError happens when the file doesn't exist
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            # csv.DictReader automatically uses the first row as headers
            reader = csv.DictReader(f)

            for row in reader:
                # Each 'row' is an OrderedDict like:
                # {"policy_name": "...", "owner": "...", "last_reviewed": "...", "status": "..."}
                policies.append(row)

    except FileNotFoundError:
        print(f"\n  Error: File not found: {filepath}")
        print("  Make sure policy_inventory.csv exists in the same folder.\n")
        sys.exit(1)

    return policies


def analyze_policies(policies):
    """
    Analyze each policy and flag issues.

    Returns a dict with summary stats and a list of flagged policies.
    Each flagged policy gets a 'flags' list describing what's wrong.
    """
    today = datetime.now()
    flagged = []

    # Counters for the summary
    total = len(policies)
    active_count = 0
    draft_count = 0
    retired_count = 0
    overdue_count = 0
    missing_owner_count = 0

    for policy in policies:
        # .strip() removes extra whitespace; .lower() normalizes for comparison
        name = policy.get("policy_name", "").strip()
        owner = policy.get("owner", "").strip()
        last_reviewed = policy.get("last_reviewed", "").strip()
        status = policy.get("status", "").strip()

        # Count by status
        # .lower() lets us match "Active", "active", "ACTIVE" etc.
        if status.lower() == "active":
            active_count += 1
        elif status.lower() == "draft":
            draft_count += 1
        elif status.lower() == "retired":
            retired_count += 1

        # ─── Flag checks ─────────────────────────────────────────
        flags = []

        # Flag 1: Missing owner
        # 'not owner' is True when owner is an empty string ""
        if not owner:
            flags.append("Missing owner")
            missing_owner_count += 1

        # Flag 2: Overdue review
        # We need to parse the date string into a datetime object
        # then calculate how many days ago it was
        if last_reviewed:
            try:
                # strptime() = "string parse time" — converts a string to datetime
                # The format string must match the date format in the CSV
                review_date = datetime.strptime(last_reviewed, DATE_FORMAT)

                # Subtracting two datetime objects gives a timedelta
                # timedelta has a .days property
                days_since = (today - review_date).days

                if days_since > REVIEW_THRESHOLD_DAYS:
                    flags.append(f"Overdue by {days_since - REVIEW_THRESHOLD_DAYS} days (last: {last_reviewed})")
                    overdue_count += 1

            except ValueError:
                # strptime raises ValueError if the date format doesn't match
                flags.append(f"Invalid date format: '{last_reviewed}'")
        else:
            flags.append("No review date")

        # Flag 3: Non-active status
        if status.lower() != "active":
            flags.append(f"Status: {status}")

        # If any flags were raised, add to the flagged list
        if flags:
            flagged.append({
                "policy_name": name,
                "owner": owner if owner else "(none)",
                "last_reviewed": last_reviewed if last_reviewed else "(none)",
                "status": status,
                "flags": flags,
            })

    summary = {
        "total": total,
        "active": active_count,
        "draft": draft_count,
        "retired": retired_count,
        "overdue": overdue_count,
        "missing_owner": missing_owner_count,
        "flagged_count": len(flagged),
        "compliant": total - len(flagged),
    }

    return summary, flagged


def print_report(summary, flagged):
    """Print a formatted compliance report to the console."""

    print("\n" + "=" * 65)
    print("  POLICY INVENTORY — COMPLIANCE REVIEW REPORT")
    print(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Review threshold: {REVIEW_THRESHOLD_DAYS} days")
    print("=" * 65)

    # ─── Summary stats ────────────────────────────────────────────
    print(f"\n  {'Metric':<25} {'Count'}")
    print(f"  {'-'*25} {'-'*8}")
    print(f"  {'Total policies':<25} {summary['total']}")
    print(f"  {'Active':<25} {summary['active']}")
    print(f"  {'Draft':<25} {summary['draft']}")
    print(f"  {'Retired':<25} {summary['retired']}")
    print(f"  {'Overdue for review':<25} {summary['overdue']}")
    print(f"  {'Missing owner':<25} {summary['missing_owner']}")
    print(f"  {'Compliant':<25} {summary['compliant']}")
    print(f"  {'Flagged':<25} {summary['flagged_count']}")

    # ─── Flagged policies ─────────────────────────────────────────
    if flagged:
        print(f"\n  {'─' * 60}")
        print(f"  FLAGGED POLICIES ({len(flagged)})")
        print(f"  {'─' * 60}")

        for i, item in enumerate(flagged, start=1):
            print(f"\n  [{i}] {item['policy_name']}")
            print(f"      Owner:    {item['owner']}")
            print(f"      Reviewed: {item['last_reviewed']}")
            print(f"      Status:   {item['status']}")
            # ', '.join() combines a list of strings with a separator
            print(f"      Flags:    {', '.join(item['flags'])}")

    # ─── Overall verdict ──────────────────────────────────────────
    print(f"\n  {'─' * 60}")
    if summary['flagged_count'] == 0:
        print("  ✅ All policies are compliant")
    else:
        print(f"  ❌ {summary['flagged_count']}/{summary['total']} policies need attention")
    print("=" * 65 + "\n")


def export_flagged(flagged, filepath):
    """
    Write flagged policies to a new CSV file.

    csv.DictWriter is the counterpart to DictReader — it writes
    dictionaries as CSV rows. You specify the column names with
    'fieldnames', then call writeheader() and writerows().
    """
    if not flagged:
        print("  No flagged policies to export.\n")
        return

    # Define the columns for the output CSV
    fieldnames = ["policy_name", "owner", "last_reviewed", "status", "flags"]

    with open(filepath, "w", encoding="utf-8", newline="") as f:
        # newline="" is required on Windows to prevent extra blank rows in CSV
        writer = csv.DictWriter(f, fieldnames=fieldnames)

        # Write the header row
        writer.writeheader()

        for item in flagged:
            # Convert the flags list to a string for the CSV
            row = item.copy()
            row["flags"] = "; ".join(item["flags"])
            writer.writerow(row)

    print(f"  📄 Flagged policies exported to: {filepath}\n")


def show_usage():
    """Print help text."""
    print("""
  📋 Policy Inventory Parser
  ───────────────────────────

  Usage:
    python policy_inventory.py [csv_file]

  Arguments:
    csv_file  - Path to the policy inventory CSV (optional)
                Defaults to policy_inventory.csv in the same folder

  The tool will:
    1. Read and parse the CSV
    2. Flag overdue reviews, missing owners, non-active statuses
    3. Print a compliance report
    4. Export flagged items to flagged_policies.csv
    """)


# ─── MAIN ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    # Allow an optional file path argument, otherwise use the default
    if len(sys.argv) > 1 and sys.argv[1].lower() == "help":
        show_usage()
        sys.exit(0)

    input_file = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_INPUT

    print(f"\n  📋 Policy Inventory Parser")
    print(f"  Reading: {input_file}")

    # Step 1: Load the CSV
    policies = load_policies(input_file)
    print(f"  Loaded {len(policies)} policies")

    # Step 2: Analyze
    summary, flagged = analyze_policies(policies)

    # Step 3: Print report
    print_report(summary, flagged)

    # Step 4: Export flagged items
    export_flagged(flagged, DEFAULT_OUTPUT)

    # Exit code: 0 if all compliant, 1 if any flagged
    sys.exit(0 if summary["flagged_count"] == 0 else 1)
