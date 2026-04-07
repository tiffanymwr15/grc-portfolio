"""
AI Risk Register Manager (SQLite)
====================================
A specialized risk register for AI/ML systems based on the general
risk register from Lesson 13. Tracks AI-specific risks including
algorithmic bias, model security, data privacy, and regulatory compliance.

AI Risk Categories:
  - Algorithmic Bias & Fairness
  - Model Security (poisoning, extraction, evasion)
  - Data Privacy (training data leaks, PII exposure)
  - Model Reliability (hallucinations, drift, failures)
  - Explainability & Transparency
  - Regulatory Compliance (EU AI Act, NIST AI RMF, etc.)

Python concepts:
  - Extends Lesson 13 sqlite3 patterns
  - Additional AI-specific schema fields
  - Risk scoring adapted for AI (complexity multiplier)
  - Export to CSV with AI fields

Standards alignment:
  - NIST AI Risk Management Framework (AI RMF)
  - EU AI Act risk classifications
  - ISO/IEC 42001 (AI Management Systems)
  - IEEE 2857 (Privacy Engineering for AI)
  - OWASP LLM Top 10 (2025)
  - OWASP Top 10 for Agentic AI

OWASP LLM Top 10 (2025):
  LLM01: Prompt Injection
  LLM02: Sensitive Information Disclosure
  LLM03: Supply Chain Vulnerabilities
  LLM04: Data and Model Poisoning
  LLM05: Insecure Output Handling
  LLM06: Excessive Agency
  LLM07: System Prompt Leakage
  LLM08: Vector and Embedding Weaknesses
  LLM09: Misinformation
  LLM10: Unbounded Consumption

OWASP Top 10 for Agentic AI:
  AGNT01: Prompt Injection in Agentic Systems
  AGNT02: Insecure Agent Communication
  AGNT03: Excessive Agency and Permission
  AGNT04: Over-Reliance on Agentic Systems
  AGNT05: Misalignment and Goal Drift
  AGNT06: Agent Session Hijacking
  AGNT07: Multi-Agent Conflicts
  AGNT08: Agent Memory Manipulation
  AGNT09: Tool Injection
  AGNT10: Agent Output Manipulation
"""

import sys
import os
import sqlite3
import csv
from datetime import datetime
from collections import Counter


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.path.join(SCRIPT_DIR, "ai_risk_register.db")
CSV_EXPORT_FILE = os.path.join(SCRIPT_DIR, "ai_risk_register_export.csv")


# ═══════════════════════════════════════════════════════════════════════
# OWASP REFERENCE DATA
# ═══════════════════════════════════════════════════════════════════════
# Pre-defined risks from OWASP LLM Top 10 (2025) and OWASP Agentic Top 10
# These can be loaded as templates or used for reference

OWASP_LLM_TOP10 = {
    "LLM01": {
        "title": "Prompt Injection",
        "description": "Attackers manipulate LLM inputs to bypass safety guardrails, execute unauthorized commands, or extract sensitive system information through crafted prompts.",
        "risk_category": "Security",
        "typical_likelihood": 4,
        "typical_impact": 4,
        "typical_complexity": 3,
    },
    "LLM02": {
        "title": "Sensitive Information Disclosure",
        "description": "LLMs may inadvertently expose confidential data, PII, or proprietary information through training data memorization or improper output filtering.",
        "risk_category": "Privacy",
        "typical_likelihood": 4,
        "typical_impact": 4,
        "typical_complexity": 3,
    },
    "LLM03": {
        "title": "Supply Chain Vulnerabilities",
        "description": "Compromised base models, malicious training data, or vulnerable dependencies in the ML pipeline can introduce backdoors or poisoned behavior.",
        "risk_category": "Security",
        "typical_likelihood": 3,
        "typical_impact": 5,
        "typical_complexity": 4,
    },
    "LLM04": {
        "title": "Data and Model Poisoning",
        "description": "Adversaries manipulate training data or fine-tuning datasets to inject backdoors, biases, or trigger specific malicious behaviors in production.",
        "risk_category": "Security",
        "typical_likelihood": 3,
        "typical_impact": 5,
        "typical_complexity": 4,
    },
    "LLM05": {
        "title": "Insecure Output Handling",
        "description": "LLM outputs containing executable code, SQL, or malicious content are passed directly to downstream systems without validation, leading to injection attacks.",
        "risk_category": "Security",
        "typical_likelihood": 4,
        "typical_impact": 4,
        "typical_complexity": 3,
    },
    "LLM06": {
        "title": "Excessive Agency",
        "description": "LLM-based systems granted excessive permissions or autonomous capabilities can perform unintended harmful actions without adequate human oversight.",
        "risk_category": "Reliability",
        "typical_likelihood": 3,
        "typical_impact": 5,
        "typical_complexity": 4,
    },
    "LLM07": {
        "title": "System Prompt Leakage",
        "description": "Attackers extract system prompts, instructions, or hidden context through prompt injection or side-channel attacks, exposing internal logic.",
        "risk_category": "Security",
        "typical_likelihood": 3,
        "typical_impact": 3,
        "typical_complexity": 3,
    },
    "LLM08": {
        "title": "Vector and Embedding Weaknesses",
        "description": "Vulnerabilities in RAG systems allowing embedding attacks, context injection, or retrieval of unauthorized information from vector databases.",
        "risk_category": "Security",
        "typical_likelihood": 3,
        "typical_impact": 4,
        "typical_complexity": 4,
    },
    "LLM09": {
        "title": "Misinformation",
        "description": "LLMs generate convincing but false information (hallucinations) that is relied upon for critical decisions, causing operational or reputational harm.",
        "risk_category": "Reliability",
        "typical_likelihood": 5,
        "typical_impact": 4,
        "typical_complexity": 4,
    },
    "LLM10": {
        "title": "Unbounded Consumption",
        "description": "Lack of rate limiting or resource controls allows attackers to cause financial harm through excessive API calls or denial-of-wallet attacks.",
        "risk_category": "Security",
        "typical_likelihood": 4,
        "typical_impact": 3,
        "typical_complexity": 2,
    },
}

OWASP_AGENTIC_TOP10 = {
    "AGNT01": {
        "title": "Prompt Injection in Agentic Systems",
        "description": "Multi-turn conversations in agentic systems allow cumulative prompt injection attacks where malicious inputs compound across interaction steps.",
        "risk_category": "Security",
        "typical_likelihood": 4,
        "typical_impact": 5,
        "typical_complexity": 4,
    },
    "AGNT02": {
        "title": "Insecure Agent Communication",
        "description": "Agents communicating with each other or external systems without proper authentication, encryption, or message integrity validation.",
        "risk_category": "Security",
        "typical_likelihood": 4,
        "typical_impact": 4,
        "typical_complexity": 3,
    },
    "AGNT03": {
        "title": "Excessive Agency and Permission",
        "description": "Agentic AI granted excessive permissions, tool access, or autonomous decision-making capability without human-in-the-loop safeguards.",
        "risk_category": "Reliability",
        "typical_likelihood": 4,
        "typical_impact": 5,
        "typical_complexity": 4,
    },
    "AGNT04": {
        "title": "Over-Reliance on Agentic Systems",
        "description": "Human operators develop excessive trust in AI agents, reducing oversight and allowing errors or malicious actions to go undetected.",
        "risk_category": "Reliability",
        "typical_likelihood": 4,
        "typical_impact": 4,
        "typical_complexity": 3,
    },
    "AGNT05": {
        "title": "Misalignment and Goal Drift",
        "description": "Agentic systems optimize for proxy metrics or reinterpret goals in unexpected ways, leading to harmful or unintended outcomes.",
        "risk_category": "Reliability",
        "typical_likelihood": 3,
        "typical_impact": 5,
        "typical_complexity": 5,
    },
    "AGNT06": {
        "title": "Agent Session Hijacking",
        "description": "Attackers take over active agent sessions to execute unauthorized actions with the agent's permissions and context.",
        "risk_category": "Security",
        "typical_likelihood": 3,
        "typical_impact": 5,
        "typical_complexity": 4,
    },
    "AGNT07": {
        "title": "Multi-Agent Conflicts",
        "description": "Conflicting goals, race conditions, or cascading failures when multiple agents interact in complex system environments.",
        "risk_category": "Reliability",
        "typical_likelihood": 3,
        "typical_impact": 4,
        "typical_complexity": 4,
    },
    "AGNT08": {
        "title": "Agent Memory Manipulation",
        "description": "Attacks targeting persistent agent memory or context stores to inject false information or erase critical safety constraints.",
        "risk_category": "Security",
        "typical_likelihood": 3,
        "typical_impact": 4,
        "typical_complexity": 4,
    },
    "AGNT09": {
        "title": "Tool Injection",
        "description": "Malicious actors inject unauthorized tools or APIs into agent toolkits, expanding attack surface and enabling harmful actions.",
        "risk_category": "Security",
        "typical_likelihood": 3,
        "typical_impact": 5,
        "typical_complexity": 4,
    },
    "AGNT10": {
        "title": "Agent Output Manipulation",
        "description": "Intercepting and modifying agent outputs to humans or other systems to hide malicious activity or inject false information.",
        "risk_category": "Security",
        "typical_likelihood": 3,
        "typical_impact": 4,
        "typical_complexity": 4,
    },
}


# AI Risk Register Schema with AI-specific fields
INIT_SQL = """
CREATE TABLE IF NOT EXISTS ai_risks (
    risk_id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    description TEXT,
    ai_system_type TEXT NOT NULL,
    ai_phase TEXT NOT NULL,
    risk_category TEXT NOT NULL,
    eu_ai_act_class TEXT,
    likelihood INTEGER NOT NULL,
    impact INTEGER NOT NULL,
    complexity INTEGER,
    score INTEGER NOT NULL,
    owner TEXT NOT NULL,
    data_steward TEXT,
    model_owner TEXT,
    status TEXT NOT NULL DEFAULT 'IDENTIFIED',
    detection_source TEXT,
    related_controls TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
    target_resolution_date TEXT
);
"""


def init_db(db_path):
    """Initialize the AI risk database."""
    conn = sqlite3.connect(db_path)
    with conn:
        conn.execute(INIT_SQL)
        # Create indexes for common queries
        conn.execute("CREATE INDEX IF NOT EXISTS idx_category ON ai_risks(risk_category)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_status ON ai_risks(status)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_eu_class ON ai_risks(eu_ai_act_class)")
    return conn


def get_connection():
    """Get a database connection."""
    return sqlite3.connect(DB_FILE)


# ═══════════════════════════════════════════════════════════════════════
# AI RISK SCORING
# ═══════════════════════════════════════════════════════════════════════

def calculate_score(likelihood, impact, complexity=3):
    """
    Calculate AI risk score with complexity multiplier.
    
    AI systems have unique characteristics:
    - Complexity increases uncertainty
    - Opacity makes detection harder
    - Scale amplifies impact
    
    Base: likelihood × impact (1-25)
    Complexity factor: 1.0 to 1.5 based on complexity (1-5)
    Final score: round(base × complexity_factor)
    """
    base_score = likelihood * impact
    complexity_factor = 1.0 + ((complexity - 1) * 0.125)  # 1.0 to 1.5
    return round(base_score * complexity_factor)


def severity_label(score):
    """Return severity label based on AI risk score."""
    if score >= 30:
        return "CRITICAL"
    elif score >= 22:
        return "HIGH"
    elif score >= 12:
        return "MEDIUM"
    else:
        return "LOW"


def severity_icon(score):
    """Return icon based on severity."""
    if score >= 30:
        return "🔴"
    elif score >= 22:
        return "🟠"
    elif score >= 12:
        return "🟡"
    else:
        return "🔵"


# ═══════════════════════════════════════════════════════════════════════
# CRUD OPERATIONS
# ═══════════════════════════════════════════════════════════════════════

def create_ai_risk(risk_id, title, description, ai_system_type, ai_phase,
                   risk_category, likelihood, impact, owner,
                   eu_ai_act_class=None, complexity=3, data_steward=None,
                   model_owner=None, detection_source=None, related_controls=None,
                   target_date=None, status="IDENTIFIED"):
    """Create a new AI risk record."""
    score = calculate_score(likelihood, impact, complexity)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn = get_connection()
    with conn:
        conn.execute("""
            INSERT INTO ai_risks (
                risk_id, title, description, ai_system_type, ai_phase, risk_category,
                eu_ai_act_class, likelihood, impact, complexity, score, owner,
                data_steward, model_owner, status, detection_source, related_controls,
                created_at, updated_at, target_resolution_date
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (risk_id, title, description, ai_system_type, ai_phase, risk_category,
              eu_ai_act_class, likelihood, impact, complexity, score, owner,
              data_steward, model_owner, status, detection_source, related_controls,
              now, now, target_date))
    return True


def get_risk(risk_id):
    """Get a single AI risk by ID."""
    conn = get_connection()
    with conn:
        row = conn.execute("SELECT * FROM ai_risks WHERE risk_id = ?", (risk_id,)).fetchone()
    return row_to_dict(row) if row else None


def list_risks(status=None, category=None, eu_class=None, owner=None,
               min_score=None, ai_phase=None, order_by="score DESC"):
    """List AI risks with flexible filtering."""
    conn = get_connection()

    where_clauses = []
    params = []

    if status:
        where_clauses.append("status = ?")
        params.append(status)
    if category:
        where_clauses.append("risk_category = ?")
        params.append(category)
    if eu_class:
        where_clauses.append("eu_ai_act_class = ?")
        params.append(eu_class)
    if owner:
        where_clauses.append("owner = ?")
        params.append(owner)
    if min_score:
        where_clauses.append("score >= ?")
        params.append(min_score)
    if ai_phase:
        where_clauses.append("ai_phase = ?")
        params.append(ai_phase)

    sql = "SELECT * FROM ai_risks"
    if where_clauses:
        sql += " WHERE " + " AND ".join(where_clauses)

    allowed_orders = {
        "score DESC": "score DESC",
        "score ASC": "score ASC",
        "created_at DESC": "created_at DESC",
        "likelihood DESC": "likelihood DESC",
        "impact DESC": "impact DESC",
        "risk_category": "risk_category",
        "ai_system_type": "ai_system_type",
    }
    sql += " ORDER BY " + allowed_orders.get(order_by, "score DESC")

    with conn:
        rows = conn.execute(sql, params).fetchall()

    return [row_to_dict(row) for row in rows]


def update_risk(risk_id, **kwargs):
    """Update an AI risk. Recalculates score if likelihood/impact/complexity changes."""
    allowed_fields = {"title", "description", "ai_system_type", "ai_phase", "risk_category",
                      "eu_ai_act_class", "likelihood", "impact", "complexity", "owner",
                      "data_steward", "model_owner", "status", "detection_source",
                      "related_controls", "target_resolution_date"}

    updates = {k: v for k, v in kwargs.items() if k in allowed_fields}

    if not updates:
        return False

    conn = get_connection()

    # Get current values for score recalculation
    with conn:
        current = conn.execute(
            "SELECT likelihood, impact, complexity FROM ai_risks WHERE risk_id = ?",
            (risk_id,)
        ).fetchone()

    if not current:
        return False

    # Recalculate score if any scoring factor changed
    if any(k in updates for k in ("likelihood", "impact", "complexity")):
        likelihood = updates.get("likelihood", current[0])
        impact = updates.get("impact", current[1])
        complexity = updates.get("complexity", current[2])
        updates["score"] = calculate_score(likelihood, impact, complexity)

    updates["updated_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    set_clause = ", ".join(f"{k} = ?" for k in updates.keys())
    params = list(updates.values()) + [risk_id]

    with conn:
        conn.execute(f"UPDATE ai_risks SET {set_clause} WHERE risk_id = ?", params)

    return True


def delete_risk(risk_id):
    """Delete an AI risk."""
    conn = get_connection()
    with conn:
        cursor = conn.execute("DELETE FROM ai_risks WHERE risk_id = ?", (risk_id,))
    return cursor.rowcount > 0


def row_to_dict(row):
    """Convert sqlite row to dict with all AI fields."""
    return {
        "risk_id": row[0], "title": row[1], "description": row[2],
        "ai_system_type": row[3], "ai_phase": row[4], "risk_category": row[5],
        "eu_ai_act_class": row[6], "likelihood": row[7], "impact": row[8],
        "complexity": row[9], "score": row[10], "owner": row[11],
        "data_steward": row[12], "model_owner": row[13], "status": row[14],
        "detection_source": row[15], "related_controls": row[16],
        "created_at": row[17], "updated_at": row[18], "target_resolution_date": row[19],
    }


# ═══════════════════════════════════════════════════════════════════════
# EXPORT / IMPORT
# ═══════════════════════════════════════════════════════════════════════

def export_to_csv(risks, filepath):
    """Export AI risks to CSV."""
    if not risks:
        return False

    fieldnames = ["risk_id", "title", "description", "ai_system_type", "ai_phase",
                  "risk_category", "eu_ai_act_class", "likelihood", "impact",
                  "complexity", "score", "owner", "data_steward", "model_owner",
                  "status", "detection_source", "related_controls",
                  "created_at", "updated_at", "target_resolution_date"]

    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for risk in risks:
            writer.writerow(risk)

    return True


def import_from_csv(filepath):
    """Import AI risks from CSV."""
    imported = 0
    errors = []

    with open(filepath, "r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                create_ai_risk(
                    risk_id=row["risk_id"],
                    title=row["title"],
                    description=row.get("description", ""),
                    ai_system_type=row["ai_system_type"],
                    ai_phase=row["ai_phase"],
                    risk_category=row["risk_category"],
                    likelihood=int(row["likelihood"]),
                    impact=int(row["impact"]),
                    owner=row["owner"],
                    eu_ai_act_class=row.get("eu_ai_act_class") or None,
                    complexity=int(row.get("complexity", 3)),
                    data_steward=row.get("data_steward"),
                    model_owner=row.get("model_owner"),
                    detection_source=row.get("detection_source"),
                    related_controls=row.get("related_controls"),
                    target_date=row.get("target_resolution_date"),
                    status=row.get("status", "IDENTIFIED"),
                )
                imported += 1
            except Exception as e:
                errors.append(f"{row.get('risk_id', '?')}: {e}")

    return imported, errors


# ═══════════════════════════════════════════════════════════════════════
# REPORTING
# ═══════════════════════════════════════════════════════════════════════

def print_risk(risk):
    """Print formatted AI risk."""
    icon = severity_icon(risk["score"])
    sev = severity_label(risk["score"])

    # EU AI Act indicator
    eu_indicator = ""
    if risk["eu_ai_act_class"] == "High_Risk":
        eu_indicator = " ⚠️ EU AI Act High-Risk"
    elif risk["eu_ai_act_class"] == "Prohibited":
        eu_indicator = " 🚫 EU AI Act Prohibited"

    print(f"\n  {icon} [{risk['risk_id']}] {risk['title']}{eu_indicator}")
    print(f"  {'─' * 60}")
    print(f"  Score: {risk['score']} ({sev}) | L:{risk['likelihood']} × I:{risk['impact']} × C:{risk['complexity']}")
    print(f"  Category: {risk['risk_category']} | System: {risk['ai_system_type']} | Phase: {risk['ai_phase']}")
    print(f"  Owner: {risk['owner']} | Status: {risk['status']}")
    if risk["data_steward"]:
        print(f"  Data Steward: {risk['data_steward']}")
    if risk["model_owner"]:
        print(f"  Model Owner: {risk['model_owner']}")
    print(f"  Created: {risk['created_at'][:10]}")


def print_summary():
    """Print AI risk summary with breakdowns by category and EU classification."""
    all_risks = list_risks()
    open_risks = [r for r in all_risks if r["status"] in ("IDENTIFIED", "ASSESSING", "MITIGATING")]
    high_risk = [r for r in all_risks if r["eu_ai_act_class"] == "High_Risk"]

    by_status = Counter(r["status"] for r in all_risks)
    by_category = Counter(r["risk_category"] for r in all_risks)
    by_eu_class = Counter(r["eu_ai_act_class"] for r in all_risks if r["eu_ai_act_class"])
    by_system = Counter(r["ai_system_type"] for r in all_risks)

    print(f"\n  🤖 AI Risk Register Summary")
    print(f"  {'=' * 50}")
    print(f"  Total AI risks:      {len(all_risks)}")
    print(f"  Open/active risks:   {len(open_risks)}")
    print(f"  EU High-Risk systems: {len(high_risk)}")

    if by_eu_class:
        print(f"\n  📋 EU AI Act Classification:")
        for cls, count in by_eu_class.most_common():
            print(f"    • {cls}: {count}")

    if by_category:
        print(f"\n  📊 By Risk Category:")
        for cat, count in by_category.most_common():
            print(f"    • {cat}: {count}")

    if by_system:
        print(f"\n  🤖 By System Type:")
        for sys, count in by_system.most_common():
            print(f"    • {sys}: {count}")

    if open_risks:
        critical = [r for r in open_risks if r["score"] >= 30]
        print(f"\n  🔴 Critical open risks (score ≥ 30): {len(critical)}")


# ═══════════════════════════════════════════════════════════════════════
# INTERACTIVE CLI
# ═══════════════════════════════════════════════════════════════════════

SYSTEM_TYPES = ["LLM", "Computer_Vision", "Tabular_ML", "Recommendation", "NLP", "Robotics", "Other"]
AI_PHASES = ["Design", "Data_Collection", "Training", "Validation", "Deployment", "Production", "Decommissioning"]
RISK_CATEGORIES = ["Bias_Fairness", "Security", "Privacy", "Reliability", "Explainability", "Safety", "Compliance"]
EU_CLASSES = ["Prohibited", "High_Risk", "Limited_Risk", "Minimal_Risk", ""]


def prompt_choice(prompt, options):
    """Prompt user to select from a list of options."""
    print(f"\n  {prompt}")
    for i, opt in enumerate(options, 1):
        display = opt if opt else "(None)"
        print(f"    {i}. {display}")
    while True:
        try:
            choice = int(input("  Select: "))
            if 1 <= choice <= len(options):
                return options[choice - 1]
        except ValueError:
            pass
        print("    Invalid selection.")


def prompt_int(prompt, min_val=1, max_val=5):
    """Prompt for integer in range."""
    while True:
        try:
            val = int(input(f"  {prompt} [{min_val}-{max_val}]: "))
            if min_val <= val <= max_val:
                return val
            print(f"    Enter value between {min_val} and {max_val}.")
        except ValueError:
            print("    Enter a valid integer.")


def interactive_add():
    """Interactive AI risk entry."""
    print(f"\n  ➕ Add New AI Risk")
    print(f"  {'─' * 50}")

    risk_id = input("  Risk ID (e.g., AI-RISK-2026-001): ").strip()
    if not risk_id:
        print("  ❌ Risk ID required.")
        return False

    if get_risk(risk_id):
        print(f"  ⚠️  Risk '{risk_id}' exists.")
        return False

    title = input("  Title: ").strip()
    description = input("  Description: ").strip()

    print(f"\n  System Classification:")
    ai_system_type = prompt_choice("AI System Type:", SYSTEM_TYPES)
    ai_phase = prompt_choice("AI Lifecycle Phase:", AI_PHASES)
    risk_category = prompt_choice("Risk Category:", RISK_CATEGORIES)
    eu_class = prompt_choice("EU AI Act Classification:", EU_CLASSES)

    print(f"\n  Risk Scoring (1-5 scale):")
    likelihood = prompt_int("Likelihood of occurrence")
    impact = prompt_int("Impact if realized")
    complexity = prompt_int("System complexity/uncertainty factor")

    owner = input("  Risk Owner: ").strip() or "AI Governance Team"
    data_steward = input("  Data Steward (optional): ").strip() or None
    model_owner = input("  Model Owner (optional): ").strip() or None

    detection = input("  Detection Source (Audit/Incident/Review/Testing): ").strip() or "Assessment"
    controls = input("  Related Controls (comma-separated, optional): ").strip() or None

    score = calculate_score(likelihood, impact, complexity)

    create_ai_risk(
        risk_id=risk_id, title=title, description=description,
        ai_system_type=ai_system_type, ai_phase=ai_phase,
        risk_category=risk_category, likelihood=likelihood,
        impact=impact, complexity=complexity, owner=owner,
        eu_ai_act_class=eu_class if eu_class else None,
        data_steward=data_steward, model_owner=model_owner,
        detection_source=detection, related_controls=controls
    )

    print(f"  ✅ AI risk '{risk_id}' added with score {score} ({severity_label(score)}).")
    return True


def interactive_menu():
    """Main interactive menu."""
    print(f"\n  🤖 AI Risk Register Manager")
    print(f"  {'=' * 50}")
    print(f"  Tracks AI/ML risks: Bias, Security, Privacy, Reliability, Compliance")
    print(f"  Aligns with: NIST AI RMF, EU AI Act, ISO 42001")

    while True:
        print(f"\n  Commands:")
        print(f"    1. add        — Add new AI risk")
        print(f"    2. list       — List all AI risks")
        print(f"    3. open       — List open/active risks")
        print(f"    4. high       — High/critical risks")
        print(f"    5. eu-high    — EU AI Act High-Risk systems")
        print(f"    6. category   — Filter by risk category")
        print(f"    7. find       — Find by ID")
        print(f"    8. update     — Update risk")
        print(f"    9. delete     — Delete risk")
        print(f"    10. summary   — Show statistics")
        print(f"    11. export    — Export to CSV")
        print(f"    0. exit       — Quit")

        choice = input(f"\n  Choice: ").strip().lower()

        if choice in ("0", "exit", "quit"):
            print("  Goodbye!")
            break

        elif choice in ("1", "add"):
            interactive_add()

        elif choice in ("2", "list"):
            risks = list_risks()
            print(f"\n  📋 All AI Risks ({len(risks)} total):")
            for risk in risks:
                print_risk(risk)

        elif choice in ("3", "open"):
            risks = list_risks(status="IDENTIFIED") + list_risks(status="ASSESSING") + list_risks(status="MITIGATING")
            risks.sort(key=lambda r: r["score"], reverse=True)
            print(f"\n  📋 Open/Active AI Risks ({len(risks)} total):")
            for risk in risks:
                print_risk(risk)

        elif choice in ("4", "high"):
            risks = list_risks(min_score=22)
            print(f"\n  🔥 High/Critical AI Risks ({len(risks)} total):")
            for risk in risks:
                print_risk(risk)

        elif choice in ("5", "eu-high"):
            risks = list_risks(eu_class="High_Risk")
            print(f"\n  ⚠️  EU AI Act High-Risk Systems ({len(risks)} total):")
            for risk in risks:
                print_risk(risk)

        elif choice in ("6", "category"):
            cat = prompt_choice("Select category:", RISK_CATEGORIES)
            risks = list_risks(category=cat)
            print(f"\n  📋 {cat} Risks ({len(risks)} total):")
            for risk in risks:
                print_risk(risk)

        elif choice in ("7", "find"):
            risk_id = input("  Risk ID: ").strip()
            risk = get_risk(risk_id)
            if risk:
                print_risk(risk)
            else:
                print(f"  ❌ Risk '{risk_id}' not found.")

        elif choice in ("8", "update"):
            risk_id = input("  Risk ID to update: ").strip()
            # Simple field update (can be extended)
            new_status = input("  New status (IDENTIFIED/ASSESSING/MITIGATING/MONITORING/RESOLVED/ACCEPTED): ").strip()
            if new_status and update_risk(risk_id, status=new_status):
                print(f"  ✅ Updated.")
            else:
                print(f"  ❌ Not found or no change.")

        elif choice in ("9", "delete"):
            risk_id = input("  Risk ID to delete: ").strip()
            if delete_risk(risk_id):
                print(f"  ✅ Deleted.")
            else:
                print(f"  ❌ Not found.")

        elif choice in ("10", "summary"):
            print_summary()

        elif choice in ("11", "export"):
            risks = list_risks()
            if export_to_csv(risks, CSV_EXPORT_FILE):
                print(f"  ✅ Exported {len(risks)} risks to {CSV_EXPORT_FILE}")

        else:
            print("  ❓ Unknown command.")


# ═══════════════════════════════════════════════════════════════════════
# DEMO DATA
# ═══════════════════════════════════════════════════════════════════════

def load_demo_data():
    """Load sample AI risks for demonstration."""
    sample_risks = [
        {
            "risk_id": "AI-2026-001",
            "title": "LLM hallucination in medical advice",
            "description": "Generative AI provides incorrect medical information to users",
            "ai_system_type": "LLM",
            "ai_phase": "Production",
            "risk_category": "Reliability",
            "eu_ai_act_class": "High_Risk",
            "likelihood": 4,
            "impact": 5,
            "complexity": 4,
            "owner": "AI Safety Team",
            "data_steward": "Healthcare Data Office",
            "model_owner": "Product Engineering",
            "status": "MITIGATING",
            "detection_source": "Testing",
        },
        {
            "risk_id": "AI-2026-002",
            "title": "Training data contains unlicensed copyrighted material",
            "description": "LLM training dataset includes scraped content with copyright issues",
            "ai_system_type": "LLM",
            "ai_phase": "Training",
            "risk_category": "Privacy",
            "eu_ai_act_class": "High_Risk",
            "likelihood": 4,
            "impact": 3,
            "complexity": 3,
            "owner": "Legal/Compliance",
            "status": "ASSESSING",
        },
        {
            "risk_id": "AI-2026-003",
            "title": "Facial recognition bias against demographic groups",
            "description": "Computer vision model shows disparate accuracy across demographics",
            "ai_system_type": "Computer_Vision",
            "ai_phase": "Production",
            "risk_category": "Bias_Fairness",
            "eu_ai_act_class": "High_Risk",
            "likelihood": 3,
            "impact": 4,
            "complexity": 3,
            "owner": "AI Ethics Board",
            "status": "IDENTIFIED",
        },
        {
            "risk_id": "AI-2026-004",
            "title": "Model inversion attack extracts training data",
            "description": "Adversarial attack could reconstruct sensitive training examples",
            "ai_system_type": "Tabular_ML",
            "ai_phase": "Production",
            "risk_category": "Security",
            "eu_ai_act_class": "High_Risk",
            "likelihood": 3,
            "impact": 5,
            "complexity": 4,
            "owner": "Security Team",
            "status": "MITIGATING",
        },
        {
            "risk_id": "AI-2026-005",
            "title": "Explainability gap for credit decisions",
            "description": "Black-box model cannot provide required explanations for loan denials",
            "ai_system_type": "Tabular_ML",
            "ai_phase": "Production",
            "risk_category": "Explainability",
            "eu_ai_act_class": "High_Risk",
            "likelihood": 4,
            "impact": 3,
            "complexity": 3,
            "owner": "Model Governance",
            "status": "ASSESSING",
        },
        {
            "risk_id": "AI-2026-006",
            "title": "Prompt injection in customer service bot",
            "description": "Attackers manipulate LLM to bypass safety guardrails",
            "ai_system_type": "LLM",
            "ai_phase": "Production",
            "risk_category": "Security",
            "eu_ai_act_class": "Limited_Risk",
            "likelihood": 4,
            "impact": 3,
            "complexity": 3,
            "owner": "AppSec Team",
            "status": "MITIGATING",
        },
        {
            "risk_id": "AI-2026-007",
            "title": "Autonomous vehicle edge case failure",
            "description": "Rare scenario not in training data causes unsafe behavior",
            "ai_system_type": "Computer_Vision",
            "ai_phase": "Validation",
            "risk_category": "Safety",
            "eu_ai_act_class": "High_Risk",
            "likelihood": 2,
            "impact": 5,
            "complexity": 5,
            "owner": "Safety Engineering",
            "status": "IDENTIFIED",
        },
    ]

    added = 0
    for risk_data in sample_risks:
        try:
            create_ai_risk(**risk_data)
            added += 1
        except sqlite3.IntegrityError:
            pass  # Already exists

    return added


def load_owasp_llm_risks():
    """
    Load the OWASP LLM Top 10 (2025) as pre-defined risks.
    
    These are reference risks that organizations can use as templates
    for their LLM security assessments.
    """
    added = 0
    skipped = 0
    
    for owasp_id, risk_template in OWASP_LLM_TOP10.items():
        risk_id = f"OWASP-{owasp_id}"
        
        # Check if already exists
        if get_risk(risk_id):
            skipped += 1
            continue
        
        try:
            create_ai_risk(
                risk_id=risk_id,
                title=f"[OWASP] {risk_template['title']}",
                description=risk_template['description'],
                ai_system_type="LLM",
                ai_phase="Production",
                risk_category=risk_template['risk_category'],
                likelihood=risk_template['typical_likelihood'],
                impact=risk_template['typical_impact'],
                complexity=risk_template['typical_complexity'],
                owner="Security Team",
                status="IDENTIFIED",
                detection_source="OWASP Reference",
                related_controls=f"OWASP LLM Top 10: {owasp_id}",
            )
            added += 1
        except sqlite3.IntegrityError:
            skipped += 1
    
    return added, skipped


def load_owasp_agentic_risks():
    """
    Load the OWASP Top 10 for Agentic AI as pre-defined risks.
    
    These are reference risks specific to autonomous AI agents and
    multi-agent systems.
    """
    added = 0
    skipped = 0
    
    for owasp_id, risk_template in OWASP_AGENTIC_TOP10.items():
        risk_id = f"OWASP-{owasp_id}"
        
        # Check if already exists
        if get_risk(risk_id):
            skipped += 1
            continue
        
        try:
            create_ai_risk(
                risk_id=risk_id,
                title=f"[OWASP Agentic] {risk_template['title']}",
                description=risk_template['description'],
                ai_system_type="LLM",  # Agentic systems are typically LLM-based
                ai_phase="Production",
                risk_category=risk_template['risk_category'],
                likelihood=risk_template['typical_likelihood'],
                impact=risk_template['typical_impact'],
                complexity=risk_template['typical_complexity'],
                owner="AI Security Team",
                status="IDENTIFIED",
                detection_source="OWASP Agentic Reference",
                related_controls=f"OWASP Agentic Top 10: {owasp_id}",
            )
            added += 1
        except sqlite3.IntegrityError:
            skipped += 1
    
    return added, skipped


def print_owasp_reference():
    """Print the OWASP Top 10 lists as reference."""
    print("\n" + "=" * 70)
    print("  OWASP LLM TOP 10 (2025)")
    print("=" * 70)
    for owasp_id, risk in OWASP_LLM_TOP10.items():
        score = calculate_score(risk['typical_likelihood'], risk['typical_impact'], risk['typical_complexity'])
        print(f"\n  {owasp_id}: {risk['title']}")
        print(f"     Category: {risk['risk_category']} | Typical Score: {score} ({severity_label(score)})")
        print(f"     {risk['description'][:80]}...")
    
    print("\n" + "=" * 70)
    print("  OWASP TOP 10 FOR AGENTIC AI")
    print("=" * 70)
    for owasp_id, risk in OWASP_AGENTIC_TOP10.items():
        score = calculate_score(risk['typical_likelihood'], risk['typical_impact'], risk['typical_complexity'])
        print(f"\n  {owasp_id}: {risk['title']}")
        print(f"     Category: {risk['risk_category']} | Typical Score: {score} ({severity_label(score)})")
        print(f"     {risk['description'][:80]}...")
    print("\n" + "=" * 70 + "\n")


# ═══════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    init_db(DB_FILE)

    command = sys.argv[1].lower() if len(sys.argv) > 1 else "menu"

    if command == "menu" or command == "interactive":
        interactive_menu()

    elif command == "demo":
        count = load_demo_data()
        print(f"✅ Added {count} sample AI risks.")
        print_summary()

    elif command == "owasp-llm":
        added, skipped = load_owasp_llm_risks()
        print(f"✅ Added {added} OWASP LLM Top 10 risks. ({skipped} already existed)")
        if added > 0:
            print("   Run 'list' to view them or 'summary' for statistics.")

    elif command == "owasp-agentic":
        added, skipped = load_owasp_agentic_risks()
        print(f"✅ Added {added} OWASP Agentic Top 10 risks. ({skipped} already existed)")
        if added > 0:
            print("   Run 'list' to view them or 'summary' for statistics.")

    elif command == "owasp-ref":
        print_owasp_reference()

    elif command == "summary":
        print_summary()

    elif command == "help":
        print("""
AI Risk Register Manager

Commands:
  menu / interactive   Launch interactive menu
  demo                 Load sample AI risks
  owasp-llm            Load OWASP LLM Top 10 (2025) as reference risks
  owasp-agentic        Load OWASP Top 10 for Agentic AI as reference risks
  owasp-ref            Display OWASP reference lists (no DB changes)
  summary              Show summary statistics
  help                 Show this message

Interactive Menu (run without arguments):
  1-11. Various commands for managing risks

OWASP Integration:
  The register includes pre-defined mappings for:
  - OWASP LLM Top 10 (2025): LLM01-LLM10
  - OWASP Top 10 for Agentic AI: AGNT01-AGNT10

  Use 'owasp-llm' or 'owasp-agentic' to add these as risks you can track,
  or 'owasp-ref' to view them as reference without adding to database.
""")

    else:
        print(f"Unknown command: '{command}'")
        print("Run 'ai_risk_register.py help' for usage.")
