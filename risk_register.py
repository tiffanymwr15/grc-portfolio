"""
Lesson 13: Risk Register Manager (SQLite)
===========================================
A GRC tool for managing risks using a SQLite database.
Implements full CRUD operations and exports to CSV.

Python concepts covered:
  - sqlite3 — Python's built-in database module
  - SQL: CREATE, INSERT, SELECT, UPDATE, DELETE
  - CRUD operations (Create, Read, Update, Delete)
  - Context managers (with conn:) for transactions
  - Parameterized queries (anti-SQL-injection)
  - CSV export using csv module
  - Risk scoring: likelihood × impact = score

GRC relevance:
  - NIST 800-53 RA-3 (Risk Assessment)
  - NIST 800-53 PM-9 (Risk Management Strategy)
  - ISO 27005 Risk Management
  - Maintaining a risk register is a core GRC practice
"""

import sys
import os
import sqlite3
import csv
from datetime import datetime
from collections import Counter


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.path.join(SCRIPT_DIR, "risk_register.db")
CSV_EXPORT_FILE = os.path.join(SCRIPT_DIR, "risk_register_export.csv")


# ═══════════════════════════════════════════════════════════════════════
# DATABASE SCHEMA
# ═══════════════════════════════════════════════════════════════════════
#
# SQLite is a zero-config database stored in a single file.
# sqlite3 is in the Python standard library — no pip install needed.
#
# Key concepts:
#   - CREATE TABLE IF NOT EXISTS — idempotent DDL
#   - TEXT, INTEGER, REAL — SQLite types
#   - PRIMARY KEY — unique identifier
#   - DEFAULT — auto-fill if not provided

INIT_SQL = """
CREATE TABLE IF NOT EXISTS risks (
    risk_id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    description TEXT,
    likelihood INTEGER NOT NULL CHECK (likelihood BETWEEN 1 AND 5),
    impact INTEGER NOT NULL CHECK (impact BETWEEN 1 AND 5),
    score INTEGER NOT NULL,
    owner TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'OPEN',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
    CHECK (status IN ('OPEN', 'MITIGATED', 'ACCEPTED', 'TRANSFERRED', 'CLOSED'))
);
"""


def init_db(db_path):
    """
    Initialize the database with the risks table.

    sqlite3.connect() creates the file if it doesn't exist.
    conn.execute() runs SQL. conn.commit() saves changes.
    'with conn:' is a context manager — auto-commits or rolls back.
    """
    conn = sqlite3.connect(db_path)
    with conn:
        conn.execute(INIT_SQL)
    return conn


def get_connection():
    """Get a database connection, initializing if needed."""
    return sqlite3.connect(DB_FILE)


# ═══════════════════════════════════════════════════════════════════════
# RISK SCORING
# ═══════════════════════════════════════════════════════════════════════
#
# Risk Score = Likelihood × Impact
# 1-5 scale for both → scores range from 1 (lowest) to 25 (highest)

def calculate_score(likelihood, impact):
    """Calculate risk score from 1-5 likelihood and 1-5 impact."""
    return likelihood * impact


def severity_label(score):
    """Return severity label based on risk score."""
    if score >= 20:
        return "CRITICAL"
    elif score >= 15:
        return "HIGH"
    elif score >= 8:
        return "MEDIUM"
    else:
        return "LOW"


def severity_icon(score):
    """Return icon based on risk score."""
    if score >= 20:
        return "🔴"
    elif score >= 15:
        return "🟠"
    elif score >= 8:
        return "🟡"
    else:
        return "🔵"


# ═══════════════════════════════════════════════════════════════════════
# CRUD OPERATIONS
# ═══════════════════════════════════════════════════════════════════════
#
# CRUD = Create, Read, Update, Delete
# These are the four fundamental operations for any data store.

def create_risk(risk_id, title, description, likelihood, impact, owner, status="OPEN"):
    """
    CREATE — Insert a new risk into the database.

    Uses parameterized query (? placeholders) to prevent SQL injection.
    Never use f-strings or string concatenation in SQL.
    """
    score = calculate_score(likelihood, impact)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn = get_connection()
    with conn:
        conn.execute("""
            INSERT INTO risks (risk_id, title, description, likelihood, impact,
                               score, owner, status, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (risk_id, title, description, likelihood, impact, score, owner, status, now, now))
    return True


def get_risk(risk_id):
    """
    READ (single) — Get one risk by ID.

    fetchone() returns a single row as a tuple, or None if not found.
    """
    conn = get_connection()
    with conn:
        row = conn.execute("SELECT * FROM risks WHERE risk_id = ?", (risk_id,)).fetchone()
    return row_to_dict(row) if row else None


def list_risks(status=None, owner=None, min_score=None, order_by="score DESC"):
    """
    READ (many) — List risks with optional filters.

    Builds SQL dynamically based on filters provided.
    Uses parameterized queries for all user input.
    """
    conn = get_connection()

    where_clauses = []
    params = []

    if status:
        where_clauses.append("status = ?")
        params.append(status)
    if owner:
        where_clauses.append("owner = ?")
        params.append(owner)
    if min_score:
        where_clauses.append("score >= ?")
        params.append(min_score)

    sql = "SELECT * FROM risks"
    if where_clauses:
        sql += " WHERE " + " AND ".join(where_clauses)

    # Only allow specific columns for ordering to prevent injection
    allowed_orders = {
        "score DESC": "score DESC",
        "score ASC": "score ASC",
        "created_at DESC": "created_at DESC",
        "likelihood DESC": "likelihood DESC",
        "impact DESC": "impact DESC",
        "owner": "owner",
    }
    sql += " ORDER BY " + allowed_orders.get(order_by, "score DESC")

    with conn:
        rows = conn.execute(sql, params).fetchall()

    return [row_to_dict(row) for row in rows]


def update_risk(risk_id, **kwargs):
    """
    UPDATE — Modify fields of an existing risk.

    kwargs is a dict of field=value pairs.
    We validate allowed fields and recalculate score if likelihood/impact changed.
    """
    allowed_fields = {"title", "description", "likelihood", "impact", "owner", "status"}

    # Filter to only allowed fields
    updates = {k: v for k, v in kwargs.items() if k in allowed_fields}

    if not updates:
        return False

    conn = get_connection()

    # Get current values to recalculate score if needed
    with conn:
        current = conn.execute("SELECT likelihood, impact FROM risks WHERE risk_id = ?",
                               (risk_id,)).fetchone()

    if not current:
        return False

    # Recalculate score if likelihood or impact changed
    if "likelihood" in updates or "impact" in updates:
        likelihood = updates.get("likelihood", current[0])
        impact = updates.get("impact", current[1])
        updates["score"] = calculate_score(likelihood, impact)

    updates["updated_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Build SET clause dynamically
    set_clause = ", ".join(f"{k} = ?" for k in updates.keys())
    params = list(updates.values()) + [risk_id]

    with conn:
        conn.execute(f"UPDATE risks SET {set_clause} WHERE risk_id = ?", params)

    return True


def delete_risk(risk_id):
    """
    DELETE — Remove a risk from the database.

    Returns True if a row was deleted, False if not found.
    """
    conn = get_connection()
    with conn:
        cursor = conn.execute("DELETE FROM risks WHERE risk_id = ?", (risk_id,))
    return cursor.rowcount > 0


def row_to_dict(row):
    """Convert a sqlite3 Row to a Python dict."""
    return {
        "risk_id": row[0],
        "title": row[1],
        "description": row[2],
        "likelihood": row[3],
        "impact": row[4],
        "score": row[5],
        "owner": row[6],
        "status": row[7],
        "created_at": row[8],
        "updated_at": row[9],
    }


# ═══════════════════════════════════════════════════════════════════════
# CSV EXPORT
# ═══════════════════════════════════════════════════════════════════════

import csv

def export_to_csv(risks, filepath):
    """
    Export risks to CSV.

    csv.DictWriter writes dicts as rows, using fieldnames as headers.
    """
    if not risks:
        return False

    fieldnames = ["risk_id", "title", "description", "likelihood", "impact",
                  "score", "owner", "status", "created_at", "updated_at"]

    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for risk in risks:
            writer.writerow(risk)

    return True


def import_from_csv(filepath):
    """Import risks from CSV."""
    imported = 0
    errors = []

    with open(filepath, "r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                # Handle both string and integer CSV files
                likelihood = int(row["likelihood"])
                impact = int(row["impact"])
                create_risk(
                    risk_id=row["risk_id"],
                    title=row["title"],
                    description=row.get("description", ""),
                    likelihood=likelihood,
                    impact=impact,
                    owner=row.get("owner", "Unassigned"),
                    status=row.get("status", "OPEN"),
                )
                imported += 1
            except Exception as e:
                errors.append(f"{row.get('risk_id', '?')}: {e}")

    return imported, errors


# ═══════════════════════════════════════════════════════════════════════
# REPORTING
# ═══════════════════════════════════════════════════════════════════════

def print_risk(risk):
    """Print a single risk in a formatted block."""
    icon = severity_icon(risk["score"])
    sev = severity_label(risk["score"])

    print(f"\n  {icon} [{risk['risk_id']}] {risk['title']}")
    print(f"  {'─' * 50}")
    print(f"  Score: {risk['score']}/25 ({sev}) | Likelihood: {risk['likelihood']} | Impact: {risk['impact']}")
    print(f"  Owner: {risk['owner']} | Status: {risk['status']}")
    print(f"  Description: {risk['description'][:60]}..." if len(risk['description']) > 60 else f"  Description: {risk['description']}")
    print(f"  Created: {risk['created_at']}")


def print_summary():
    """Print summary statistics of the risk register."""
    all_risks = list_risks()
    open_risks = [r for r in all_risks if r["status"] == "OPEN"]

    by_status = Counter(r["status"] for r in all_risks)
    by_owner = Counter(r["owner"] for r in all_risks)

    print(f"\n  📊 Risk Register Summary")
    print(f"  {'─' * 40}")
    print(f"  Total risks:    {len(all_risks)}")
    print(f"  Open risks:     {len(open_risks)}")

    if by_status:
        print(f"\n  By Status:")
        for status, count in by_status.most_common():
            print(f"    • {status}: {count}")

    if by_owner:
        print(f"\n  By Owner:")
        for owner, count in by_owner.most_common(5):
            print(f"    • {owner}: {count}")

    if open_risks:
        high_risks = [r for r in open_risks if r["score"] >= 15]
        print(f"\n  ⚠️  High/Critical open risks: {len(high_risks)}")


# ═══════════════════════════════════════════════════════════════════════
# INTERACTIVE CLI
# ═══════════════════════════════════════════════════════════════════════

def prompt_int(prompt, min_val=1, max_val=5):
    """Prompt for an integer in a range."""
    while True:
        try:
            val = int(input(f"  {prompt} [{min_val}-{max_val}]: "))
            if min_val <= val <= max_val:
                return val
            print(f"    Please enter a value between {min_val} and {max_val}.")
        except ValueError:
            print("    Please enter a valid integer.")


def interactive_add():
    """Interactive prompt to add a new risk."""
    print(f"\n  ➕ Add New Risk")
    print(f"  {'─' * 40}")

    risk_id = input("  Risk ID (e.g., RISK-2026-001): ").strip()
    if not risk_id:
        print("  ❌ Risk ID is required.")
        return False

    if get_risk(risk_id):
        print(f"  ⚠️  Risk '{risk_id}' already exists. Use 'update' to modify it.")
        return False

    title = input("  Title: ").strip()
    description = input("  Description: ").strip()
    likelihood = prompt_int("Likelihood (1=Rare, 5=Almost Certain)")
    impact = prompt_int("Impact (1=Negligible, 5=Catastrophic)")
    owner = input("  Owner: ").strip() or "Unassigned"

    create_risk(risk_id, title, description, likelihood, impact, owner)
    print(f"  ✅ Risk '{risk_id}' added with score {calculate_score(likelihood, impact)}.")
    return True


def interactive_update():
    """Interactive prompt to update a risk."""
    print(f"\n  🔄 Update Risk")
    print(f"  {'─' * 40}")

    risk_id = input("  Risk ID to update: ").strip()
    risk = get_risk(risk_id)

    if not risk:
        print(f"  ❌ Risk '{risk_id}' not found.")
        return False

    print(f"  Current: {risk['title']} (Score: {risk['score']})")

    updates = {}

    new_title = input(f"  New title [{risk['title']}]: ").strip()
    if new_title:
        updates["title"] = new_title

    new_status = input(f"  New status [{risk['status']}] (OPEN/MITIGATED/ACCEPTED/TRANSFERRED/CLOSED): ").strip().upper()
    if new_status in ["OPEN", "MITIGATED", "ACCEPTED", "TRANSFERRED", "CLOSED"]:
        updates["status"] = new_status

    new_owner = input(f"  New owner [{risk['owner']}]: ").strip()
    if new_owner:
        updates["owner"] = new_owner

    new_likelihood = input(f"  New likelihood [{risk['likelihood']}] (1-5, blank=no change): ").strip()
    if new_likelihood.isdigit():
        updates["likelihood"] = int(new_likelihood)

    new_impact = input(f"  New impact [{risk['impact']}] (1-5, blank=no change): ").strip()
    if new_impact.isdigit():
        updates["impact"] = int(new_impact)

    if not updates:
        print("  ℹ️  No changes made.")
        return False

    update_risk(risk_id, **updates)
    updated = get_risk(risk_id)
    print(f"  ✅ Risk '{risk_id}' updated. New score: {updated['score']}")
    return True


def interactive_menu():
    """Main interactive menu loop."""
    print(f"\n  📋 Risk Register Manager")
    print(f"  {'=' * 40}")

    while True:
        print(f"\n  Commands:")
        print(f"    1. add      — Add a new risk")
        print(f"    2. list     — List all risks")
        print(f"    3. open     — List open risks (sorted by score)")
        print(f"    4. high     — List high/critical risks only")
        print(f"    5. find     — Find a risk by ID")
        print(f"    6. update   — Update a risk")
        print(f"    7. delete   — Delete a risk")
        print(f"    8. summary  — Show summary statistics")
        print(f"    9. export   — Export to CSV")
        print(f"    0. exit     — Quit")

        choice = input(f"\n  Choice: ").strip().lower()

        if choice in ("0", "exit", "quit"):
            print("  Goodbye!")
            break

        elif choice in ("1", "add"):
            interactive_add()

        elif choice in ("2", "list"):
            risks = list_risks()
            print(f"\n  📋 All Risks ({len(risks)} total):")
            for risk in risks:
                print_risk(risk)

        elif choice in ("3", "open"):
            risks = list_risks(status="OPEN", order_by="score DESC")
            print(f"\n  📋 Open Risks ({len(risks)} total):")
            for risk in risks:
                print_risk(risk)

        elif choice in ("4", "high"):
            risks = list_risks(status="OPEN", min_score=15, order_by="score DESC")
            print(f"\n  🔥 High/Critical Open Risks ({len(risks)} total):")
            for risk in risks:
                print_risk(risk)

        elif choice in ("5", "find"):
            risk_id = input("  Risk ID: ").strip()
            risk = get_risk(risk_id)
            if risk:
                print_risk(risk)
            else:
                print(f"  ❌ Risk '{risk_id}' not found.")

        elif choice in ("6", "update"):
            interactive_update()

        elif choice in ("7", "delete"):
            risk_id = input("  Risk ID to delete: ").strip()
            if delete_risk(risk_id):
                print(f"  ✅ Risk '{risk_id}' deleted.")
            else:
                print(f"  ❌ Risk '{risk_id}' not found.")

        elif choice in ("8", "summary"):
            print_summary()

        elif choice in ("9", "export"):
            risks = list_risks()
            if export_to_csv(risks, CSV_EXPORT_FILE):
                print(f"  ✅ Exported {len(risks)} risks to {CSV_EXPORT_FILE}")
            else:
                print("  ❌ No risks to export.")

        else:
            print("  ❓ Unknown command. Try: add, list, open, high, find, update, delete, summary, export, exit")


# ═══════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    # Initialize database on first run
    init_db(DB_FILE)

    command = sys.argv[1].lower() if len(sys.argv) > 1 else "menu"

    if command == "menu" or command == "interactive":
        interactive_menu()

    elif command == "add":
        if len(sys.argv) < 7:
            print("Usage: risk_register.py add <risk_id> <title> <likelihood> <impact> <owner>")
            print("       risk_register.py add RISK-001 'Data Breach' 4 5 'CISO'")
            sys.exit(1)
        _, risk_id, title, likelihood, impact, owner = sys.argv[:6]
        description = " ".join(sys.argv[6:]) if len(sys.argv) > 6 else ""
        create_risk(risk_id, title, description, int(likelihood), int(impact), owner)
        print(f"✅ Risk '{risk_id}' added.")

    elif command == "list":
        status = sys.argv[2] if len(sys.argv) > 2 else None
        risks = list_risks(status=status)
        for risk in risks:
            print(f"{severity_icon(risk['score'])} [{risk['risk_id']}] {risk['title']} | Score: {risk['score']} | {risk['status']}")

    elif command == "find":
        if len(sys.argv) < 3:
            print("Usage: risk_register.py find <risk_id>")
            sys.exit(1)
        risk = get_risk(sys.argv[2])
        if risk:
            print_risk(risk)
        else:
            print(f"Risk '{sys.argv[2]}' not found.")
            sys.exit(1)

    elif command == "update":
        if len(sys.argv) < 4:
            print("Usage: risk_register.py update <risk_id> <field=value> ...")
            print("       risk_register.py update RISK-001 status=MITIGATED")
            sys.exit(1)
        risk_id = sys.argv[2]
        updates = {}
        for arg in sys.argv[3:]:
            if "=" in arg:
                k, v = arg.split("=", 1)
                if k in ("likelihood", "impact"):
                    v = int(v)
                updates[k] = v
        if update_risk(risk_id, **updates):
            print(f"✅ Risk '{risk_id}' updated.")
        else:
            print(f"❌ Risk '{risk_id}' not found or no changes made.")
            sys.exit(1)

    elif command == "delete":
        if len(sys.argv) < 3:
            print("Usage: risk_register.py delete <risk_id>")
            sys.exit(1)
        if delete_risk(sys.argv[2]):
            print(f"✅ Risk '{sys.argv[2]}' deleted.")
        else:
            print(f"❌ Risk '{sys.argv[2]}' not found.")
            sys.exit(1)

    elif command == "export":
        risks = list_risks()
        if export_to_csv(risks, CSV_EXPORT_FILE):
            print(f"✅ Exported {len(risks)} risks to {CSV_EXPORT_FILE}")
        else:
            print("No risks to export.")

    elif command == "import":
        filepath = sys.argv[2] if len(sys.argv) > 2 else CSV_EXPORT_FILE
        imported, errors = import_from_csv(filepath)
        print(f"✅ Imported {imported} risks.")
        if errors:
            print(f"⚠️  {len(errors)} errors:")
            for e in errors[:5]:
                print(f"   {e}")

    elif command == "summary":
        print_summary()

    elif command == "demo":
        # Add sample risks for demonstration
        sample_risks = [
            ("RISK-2026-001", "Cloud misconfiguration leading to data exposure", 4, 5, "Cloud Team", "OPEN"),
            ("RISK-2026-002", "Third-party vendor data breach", 3, 4, "Procurement", "OPEN"),
            ("RISK-2026-003", "Insider threat - privileged abuse", 2, 5, "HR/IT", "OPEN"),
            ("RISK-2026-004", "Ransomware on critical systems", 3, 5, "SOC", "MITIGATED"),
            ("RISK-2026-005", "Unpatched critical vulnerability", 4, 4, "Vuln Mgmt", "OPEN"),
            ("RISK-2026-006", "Compliance audit findings", 3, 3, "GRC", "OPEN"),
            ("RISK-2026-007", "Legacy system unsupported", 2, 3, "IT Ops", "ACCEPTED"),
        ]

        added = 0
        for risk_id, title, likelihood, impact, owner, status in sample_risks:
            try:
                create_risk(risk_id, title, f"Risk description for {risk_id}",
                           likelihood, impact, owner, status)
                added += 1
            except sqlite3.IntegrityError:
                pass  # Already exists

        print(f"✅ Added {added} sample risks. Run 'summary' or 'list' to view.")

    elif command == "help":
        print("""
Risk Register Manager — Commands:
  menu/interactive    Launch interactive menu
  demo                Load sample risks
  summary             Show summary statistics
  list [status]       List all risks (optionally filter by status)
  find <risk_id>      Find a specific risk
  add <id> <title> <likelihood> <impact> <owner> [description]
  update <id> field=value ...
  delete <id>
  export              Export to CSV
  import <file>       Import from CSV
  help                Show this message
""")

    else:
        print(f"Unknown command: '{command}'")
        print("Run 'risk_register.py help' for usage.")
        sys.exit(1)
