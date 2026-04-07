"""
Lesson 15: GRC Dashboard (Web App)
====================================
A Flask web dashboard that displays compliance status, open risks,
recent alerts, and other GRC metrics in a clean web interface.

Python concepts covered:
  - Flask web framework basics
  - HTML templates with Jinja2
  - JSON API endpoints for data
  - Serving static CSS/JS
  - Auto-refresh with JavaScript fetch
  - SQLite integration for live data

GRC relevance:
  - Centralized visibility into compliance posture
  - Real-time risk and alert dashboards
  - Executive summary view
  - Integration point for all previous tools
"""

import os
import sys
import json
import sqlite3
from datetime import datetime, timedelta
from collections import Counter

# Flask is not in the standard library
try:
    from flask import Flask, render_template, jsonify, request, send_from_directory
except ImportError:
    print("\n  ❌ Flask is required. Install it with:")
    print('     pip install flask\n')
    sys.exit(1)


# ═══════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATE_DIR = os.path.join(SCRIPT_DIR, "templates")
STATIC_DIR = os.path.join(SCRIPT_DIR, "static")

# Database paths (from previous lessons)
RISK_DB = os.path.join(SCRIPT_DIR, "ai_risk_register.db")
ALERT_HISTORY = os.path.join(SCRIPT_DIR, "alert_history.jsonl")

app = Flask(__name__, template_folder=TEMPLATE_DIR, static_folder=STATIC_DIR)


# ═══════════════════════════════════════════════════════════════════════
# DATA HELPERS
# ═══════════════════════════════════════════════════════════════════════

def get_db_connection(db_path):
    """Get a database connection with row factory."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def get_risk_summary():
    """Get summary of AI risks from the risk register."""
    if not os.path.exists(RISK_DB):
        return {"total": 0, "open": 0, "critical": 0, "by_category": {}, "recent": []}
    
    conn = get_db_connection(RISK_DB)
    cursor = conn.cursor()
    
    # Overall counts
    cursor.execute("SELECT status, COUNT(*) FROM ai_risks GROUP BY status")
    by_status = dict(cursor.fetchall())
    
    # Critical count
    cursor.execute("SELECT COUNT(*) FROM ai_risks WHERE score >= 30 AND status IN ('IDENTIFIED', 'ASSESSING', 'MITIGATING')")
    critical = cursor.fetchone()[0]
    
    # By category
    cursor.execute("SELECT risk_category, COUNT(*) FROM ai_risks GROUP BY risk_category")
    by_category = dict(cursor.fetchall())
    
    # Recent high-risk
    cursor.execute("""
        SELECT risk_id, title, score, risk_category, status 
        FROM ai_risks 
        WHERE status IN ('IDENTIFIED', 'ASSESSING', 'MITIGATING')
        ORDER BY score DESC 
        LIMIT 5
    """)
    recent = [dict(row) for row in cursor.fetchall()]
    
    conn.close()
    
    return {
        "total": sum(by_status.values()),
        "open": by_status.get('IDENTIFIED', 0) + by_status.get('ASSESSING', 0) + by_status.get('MITIGATING', 0),
        "critical": critical,
        "by_category": by_category,
        "recent": recent
    }


def get_recent_alerts(limit=10):
    """Get recent alerts from history."""
    if not os.path.exists(ALERT_HISTORY):
        return []
    
    alerts = []
    try:
        with open(ALERT_HISTORY, "r", encoding="utf-8") as f:
            lines = f.readlines()
            for line in lines[-limit:]:
                data = json.loads(line.strip())
                alerts.append({
                    "timestamp": data.get("timestamp", "")[:19],
                    "severity": data.get("alert", {}).get("severity", "INFO"),
                    "title": data.get("alert", {}).get("title", "Unknown"),
                    "source": data.get("alert", {}).get("source", "System")
                })
    except Exception:
        pass
    
    return list(reversed(alerts))


def get_compliance_status():
    """Generate mock compliance status (integrates with previous tools)."""
    # In production, this would read from previous tool outputs
    # For now, return representative mock data
    return {
        "overall_score": 78,
        "status": "NEEDS_ATTENTION",
        "last_scan": datetime.now().isoformat(),
        "findings": {
            "critical": 2,
            "high": 5,
            "medium": 12,
            "low": 8
        },
        "categories": {
            "IAM": {"score": 85, "findings": 3},
            "S3": {"score": 72, "findings": 5},
            "CloudTrail": {"score": 90, "findings": 1},
            "Network": {"score": 68, "findings": 7}
        }
    }


def get_system_health():
    """Get system/health status."""
    return {
        "status": "OPERATIONAL",
        "last_check": datetime.now().isoformat(),
        "monitors": {
            "compliance_monitor": "running",
            "risk_register": "active",
            "alert_system": "ready"
        }
    }


# ═══════════════════════════════════════════════════════════════════════
# FLASK ROUTES
# ═══════════════════════════════════════════════════════════════════════

@app.route("/")
def dashboard():
    """
    Main dashboard page.
    Renders the HTML template with initial data.
    """
    initial_data = {
        "risk_summary": get_risk_summary(),
        "compliance": get_compliance_status(),
        "alerts": get_recent_alerts(5),
        "health": get_system_health(),
        "generated_at": datetime.now().isoformat()
    }
    return render_template("dashboard.html", data=initial_data)


@app.route("/api/status")
def api_status():
    """
    JSON API endpoint for dashboard data.
    Called by JavaScript to refresh data without page reload.
    """
    return jsonify({
        "risk_summary": get_risk_summary(),
        "compliance": get_compliance_status(),
        "alerts": get_recent_alerts(5),
        "health": get_system_health(),
        "generated_at": datetime.now().isoformat()
    })


@app.route("/api/risks")
def api_risks():
    """Get all risks as JSON."""
    if not os.path.exists(RISK_DB):
        return jsonify({"risks": []})
    
    conn = get_db_connection(RISK_DB)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT risk_id, title, score, risk_category, status, ai_system_type,
               likelihood, impact, complexity, owner
        FROM ai_risks
        WHERE status IN ('IDENTIFIED', 'ASSESSING', 'MITIGATING')
        ORDER BY score DESC
    """)
    risks = [dict(row) for row in cursor.fetchall()]
    conn.close()
    
    return jsonify({"risks": risks, "count": len(risks)})


@app.route("/api/alerts")
def api_alerts():
    """Get recent alerts as JSON."""
    limit = request.args.get("limit", 10, type=int)
    return jsonify({"alerts": get_recent_alerts(limit)})


@app.route("/api/compliance/score")
def api_compliance_score():
    """Get compliance score trend (mock data)."""
    # Generate 30 days of mock scores
    scores = []
    base_score = 75
    for i in range(30):
        date = datetime.now() - timedelta(days=29-i)
        # Random variation around base score
        variation = (i % 5) - 2  # -2 to +2
        score = min(100, max(0, base_score + variation))
        scores.append({
            "date": date.strftime("%Y-%m-%d"),
            "score": score
        })
    
    return jsonify({"scores": scores, "current": scores[-1]["score"]})


# ═══════════════════════════════════════════════════════════════════════
# TEMPLATE CREATION
# ═══════════════════════════════════════════════════════════════════════

def create_templates():
    """
    Create the templates directory and HTML template if they don't exist.
    This is a self-contained setup for the lesson.
    """
    if not os.path.exists(TEMPLATE_DIR):
        os.makedirs(TEMPLATE_DIR)
    
    if not os.path.exists(STATIC_DIR):
        os.makedirs(STATIC_DIR)
    
    # Create main dashboard template
    template_path = os.path.join(TEMPLATE_DIR, "dashboard.html")
    if not os.path.exists(template_path):
        with open(template_path, "w", encoding="utf-8") as f:
            f.write(DASHBOARD_TEMPLATE)
    
    # Create CSS file
    css_path = os.path.join(STATIC_DIR, "style.css")
    if not os.path.exists(css_path):
        with open(css_path, "w", encoding="utf-8") as f:
            f.write(DASHBOARD_CSS)


# HTML Template for the dashboard
DASHBOARD_TEMPLATE = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GRC Dashboard</title>
    <link rel="stylesheet" href="/static/style.css">
</head>
<body>
    <div class="container">
        <header>
            <h1>🛡️ GRC Dashboard</h1>
            <div class="last-updated">Last updated: <span id="last-updated">{{ data.generated_at[:19] }}</span></div>
        </header>

        <!-- System Health Status -->
        <section class="health-bar">
            <div class="health-item">
                <span class="status-indicator {{ 'green' if data.health.status == 'OPERATIONAL' else 'red' }}"></span>
                System: {{ data.health.status }}
            </div>
            <div class="health-item">Compliance Monitor: {{ data.health.monitors.compliance_monitor }}</div>
            <div class="health-item">Risk Register: {{ data.health.monitors.risk_register }}</div>
            <div class="health-item">Alert System: {{ data.health.monitors.alert_system }}</div>
        </section>

        <!-- Key Metrics Cards -->
        <section class="metrics-grid">
            <div class="metric-card critical">
                <div class="metric-value">{{ data.compliance.findings.critical }}</div>
                <div class="metric-label">Critical Findings</div>
            </div>
            <div class="metric-card high">
                <div class="metric-value">{{ data.compliance.findings.high }}</div>
                <div class="metric-label">High Findings</div>
            </div>
            <div class="metric-card medium">
                <div class="metric-value">{{ data.compliance.findings.medium }}</div>
                <div class="metric-label">Medium Findings</div>
            </div>
            <div class="metric-card info">
                <div class="metric-value">{{ data.compliance.overall_score }}%</div>
                <div class="metric-label">Compliance Score</div>
            </div>
        </section>

        <!-- Risk Summary -->
        <section class="panel">
            <h2>🤖 AI Risk Summary</h2>
            <div class="risk-stats">
                <div class="stat-box">
                    <div class="stat-number">{{ data.risk_summary.total }}</div>
                    <div class="stat-label">Total Risks</div>
                </div>
                <div class="stat-box">
                    <div class="stat-number warning">{{ data.risk_summary.open }}</div>
                    <div class="stat-label">Open Risks</div>
                </div>
                <div class="stat-box">
                    <div class="stat-number critical">{{ data.risk_summary.critical }}</div>
                    <div class="stat-label">Critical (Score ≥30)</div>
                </div>
            </div>
            
            {% if data.risk_summary.recent %}
            <h3>Top Open Risks</h3>
            <table class="data-table">
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Title</th>
                        <th>Category</th>
                        <th>Score</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
                    {% for risk in data.risk_summary.recent %}
                    <tr class="severity-{{ 'critical' if risk.score >= 30 else 'high' if risk.score >= 22 else 'medium' }}">
                        <td>{{ risk.risk_id }}</td>
                        <td>{{ risk.title }}</td>
                        <td>{{ risk.risk_category }}</td>
                        <td>{{ risk.score }}</td>
                        <td><span class="badge">{{ risk.status }}</span></td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
            {% else %}
            <p class="no-data">No active risks. Run the AI risk register demo to populate.</p>
            {% endif %}
        </section>

        <!-- Recent Alerts -->
        <section class="panel">
            <h2>🚨 Recent Alerts</h2>
            {% if data.alerts %}
            <ul class="alert-list">
                {% for alert in data.alerts %}
                <li class="alert-item severity-{{ alert.severity.lower() }}">
                    <div class="alert-time">{{ alert.timestamp }}</div>
                    <div class="alert-title">[{{ alert.severity }}] {{ alert.title }}</div>
                    <div class="alert-source">{{ alert.source }}</div>
                </li>
                {% endfor %}
            </ul>
            {% else %}
            <p class="no-data">No recent alerts. Use grc_alerter.py to send test alerts.</p>
            {% endif %}
        </section>

        <!-- Compliance by Category -->
        <section class="panel">
            <h2>📊 Compliance by Category</h2>
            <div class="category-grid">
                {% for category, metrics in data.compliance.categories.items() %}
                <div class="category-card">
                    <div class="category-name">{{ category }}</div>
                    <div class="category-score {{ 'good' if metrics.score >= 80 else 'warning' if metrics.score >= 60 else 'poor' }}">
                        {{ metrics.score }}%
                    </div>
                    <div class="category-findings">{{ metrics.findings }} findings</div>
                </div>
                {% endfor %}
            </div>
        </section>

        <footer>
            <p>GRC Dashboard | Auto-refreshes every 30 seconds | <a href="/api/status">API Status</a></p>
        </footer>
    </div>

    <script>
        // Auto-refresh data every 30 seconds
        async function refreshData() {
            try {
                const response = await fetch('/api/status');
                const data = await response.json();
                
                document.getElementById('last-updated').textContent = data.generated_at.slice(0, 19);
                
                // Could update all sections dynamically here
                // For now, we just update the timestamp to show it's working
                console.log('Dashboard refreshed:', data);
            } catch (error) {
                console.error('Refresh failed:', error);
            }
        }

        // Refresh every 30 seconds
        setInterval(refreshData, 30000);
        
        // Also refresh on page visibility change (tab becomes active)
        document.addEventListener('visibilitychange', () => {
            if (document.visibilityState === 'visible') {
                refreshData();
            }
        });
    </script>
</body>
</html>'''


# CSS for the dashboard
DASHBOARD_CSS = '''/* GRC Dashboard Styles */

:root {
    --bg-color: #0d1117;
    --card-bg: #161b22;
    --text-primary: #c9d1d9;
    --text-secondary: #8b949e;
    --border-color: #30363d;
    --accent-blue: #58a6ff;
    --success: #238636;
    --warning: #f0883e;
    --danger: #da3633;
    --info: #1f6feb;
}

* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background-color: var(--bg-color);
    color: var(--text-primary);
    line-height: 1.6;
}

.container {
    max-width: 1200px;
    margin: 0 auto;
    padding: 20px;
}

/* Header */
header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 20px 0;
    border-bottom: 1px solid var(--border-color);
    margin-bottom: 20px;
}

header h1 {
    font-size: 28px;
    font-weight: 600;
}

.last-updated {
    color: var(--text-secondary);
    font-size: 14px;
}

/* Health Bar */
.health-bar {
    display: flex;
    gap: 20px;
    padding: 12px 16px;
    background: var(--card-bg);
    border-radius: 8px;
    margin-bottom: 20px;
    border: 1px solid var(--border-color);
}

.health-item {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 14px;
}

.status-indicator {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: var(--text-secondary);
}

.status-indicator.green { background: var(--success); }
.status-indicator.red { background: var(--danger); }

/* Metrics Grid */
.metrics-grid {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 16px;
    margin-bottom: 24px;
}

.metric-card {
    background: var(--card-bg);
    border: 1px solid var(--border-color);
    border-radius: 12px;
    padding: 20px;
    text-align: center;
    border-left: 4px solid var(--border-color);
}

.metric-card.critical { border-left-color: var(--danger); }
.metric-card.high { border-left-color: var(--warning); }
.metric-card.medium { border-left-color: #d29922; }
.metric-card.info { border-left-color: var(--accent-blue); }

.metric-value {
    font-size: 36px;
    font-weight: 700;
    margin-bottom: 8px;
}

.metric-label {
    font-size: 14px;
    color: var(--text-secondary);
    text-transform: uppercase;
    letter-spacing: 0.5px;
}

/* Panels */
.panel {
    background: var(--card-bg);
    border: 1px solid var(--border-color);
    border-radius: 12px;
    padding: 24px;
    margin-bottom: 24px;
}

.panel h2 {
    font-size: 20px;
    margin-bottom: 20px;
    font-weight: 600;
}

.panel h3 {
    font-size: 16px;
    margin: 20px 0 12px;
    color: var(--text-secondary);
}

/* Risk Stats */
.risk-stats {
    display: flex;
    gap: 24px;
    margin-bottom: 20px;
}

.stat-box {
    text-align: center;
    padding: 16px 24px;
    background: rgba(88, 166, 255, 0.1);
    border-radius: 8px;
}

.stat-number {
    font-size: 32px;
    font-weight: 700;
    color: var(--accent-blue);
}

.stat-number.warning { color: var(--warning); }
.stat-number.critical { color: var(--danger); }

.stat-label {
    font-size: 12px;
    color: var(--text-secondary);
    text-transform: uppercase;
}

/* Tables */
.data-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 14px;
}

.data-table th,
.data-table td {
    padding: 12px;
    text-align: left;
    border-bottom: 1px solid var(--border-color);
}

.data-table th {
    color: var(--text-secondary);
    font-weight: 500;
    text-transform: uppercase;
    font-size: 12px;
}

.data-table tr:hover {
    background: rgba(255, 255, 255, 0.03);
}

.severity-critical { color: var(--danger); }
.severity-high { color: var(--warning); }
.severity-medium { color: #d29922; }

.badge {
    display: inline-block;
    padding: 4px 8px;
    border-radius: 4px;
    font-size: 12px;
    background: rgba(88, 166, 255, 0.2);
    color: var(--accent-blue);
}

/* Alert List */
.alert-list {
    list-style: none;
}

.alert-item {
    padding: 12px;
    border-left: 3px solid var(--border-color);
    margin-bottom: 8px;
    background: rgba(255, 255, 255, 0.02);
    border-radius: 0 8px 8px 0;
}

.alert-item.severity-critical { border-left-color: var(--danger); }
.alert-item.severity-high { border-left-color: var(--warning); }
.alert-item.severity-medium { border-left-color: #d29922; }
.alert-item.severity-low { border-left-color: var(--success); }

.alert-time {
    font-size: 12px;
    color: var(--text-secondary);
}

.alert-title {
    font-weight: 500;
    margin: 4px 0;
}

.alert-source {
    font-size: 12px;
    color: var(--text-secondary);
}

/* Category Grid */
.category-grid {
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    gap: 16px;
}

.category-card {
    background: rgba(255, 255, 255, 0.02);
    border: 1px solid var(--border-color);
    border-radius: 8px;
    padding: 16px;
}

.category-name {
    font-size: 14px;
    color: var(--text-secondary);
    text-transform: uppercase;
}

.category-score {
    font-size: 28px;
    font-weight: 700;
    margin: 8px 0;
}

.category-score.good { color: var(--success); }
.category-score.warning { color: var(--warning); }
.category-score.poor { color: var(--danger); }

.category-findings {
    font-size: 12px;
    color: var(--text-secondary);
}

/* No Data Message */
.no-data {
    color: var(--text-secondary);
    font-style: italic;
    padding: 20px;
    text-align: center;
}

/* Footer */
footer {
    text-align: center;
    padding: 20px;
    color: var(--text-secondary);
    font-size: 14px;
    border-top: 1px solid var(--border-color);
}

footer a {
    color: var(--accent-blue);
    text-decoration: none;
}

/* Responsive */
@media (max-width: 768px) {
    .metrics-grid {
        grid-template-columns: repeat(2, 1fr);
    }
    
    .category-grid {
        grid-template-columns: 1fr;
    }
    
    .risk-stats {
        flex-direction: column;
    }
}
'''


# ═══════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("\n  📊 GRC Dashboard")
    print("  " + "=" * 40)
    
    # Create templates on startup
    create_templates()
    
    # Configuration
    host = os.environ.get("GRC_DASHBOARD_HOST", "127.0.0.1")
    port = int(os.environ.get("GRC_DASHBOARD_PORT", "5000"))
    debug = os.environ.get("GRC_DASHBOARD_DEBUG", "false").lower() == "true"
    
    print(f"  Starting Flask server...")
    print(f"  URL: http://{host}:{port}/")
    print(f"  Press Ctrl+C to stop\n")
    
    # Run the Flask app
    app.run(host=host, port=port, debug=debug)
