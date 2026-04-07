# GRC Engineering Toolkit

A collection of Python-based Governance, Risk, and Compliance (GRC) automation tools built for cloud security operations. Each tool maps to real-world compliance frameworks including **NIST 800-53**, **CIS Benchmarks**, **ISO 27001**, **SOC 2**, **EU AI Act**, and **NIST AI RMF**.

All tools include mock/demo modes — no AWS credentials required to explore functionality.

---

## Tools at a Glance

| # | Tool | Purpose | Frameworks |
|---|------|---------|------------|
| 1 | [Evidence Logger](#evidence-logger) | Timestamped audit evidence collection | NIST AU-2, CA-7 |
| 2 | [Policy Inventory](#policy-inventory) | CSV policy review tracker with overdue detection | NIST PM-1, PL-1 |
| 3 | [Control Mapper](#control-mapper) | Cross-framework control mapping (NIST ↔ CIS ↔ ISO ↔ SOC 2) | NIST, CIS, ISO 27001, SOC 2 |
| 4 | [IAM Auditor](#iam-auditor) | AWS IAM user audit — MFA, key age, last login | NIST AC-2, IA-2; CIS 1.10, 1.12 |
| 5 | [S3 Security Scanner](#s3-security-scanner) | S3 bucket misconfiguration detection | CIS 2.1.1/2.1.2; NIST SC-28, AU-2 |
| 6 | [CloudTrail Analyzer](#cloudtrail-analyzer) | Log analysis with threat detection rules | NIST AU-2, AU-6, SI-4; CIS §3 |
| 7 | [Compliance Report Generator](#compliance-report-generator) | Automated assessment reports (Markdown + JSON) | NIST CA-2, CA-7 |
| 8 | [Compliance Monitor](#compliance-monitor) | Scheduled continuous compliance checks | NIST CA-7, AU-6 |
| 9 | [CloudFormation Validator](#cloudformation-validator) | IaC security validation (shift-left) | NIST SA-11, CM-6; CIS Benchmarks |
| 10 | [Infrastructure Drift Detector](#infrastructure-drift-detector) | Baseline vs. current state drift analysis | NIST CM-3, CM-6, SI-7 |
| 11 | [Risk Register](#risk-register) | SQLite-backed CRUD risk register | NIST RA-3, PM-9; ISO 27005 |
| 12 | [AI Risk Register](#ai-risk-register) | AI/ML-specific risk tracking with OWASP LLM Top 10 | NIST AI RMF, EU AI Act, ISO 42001 |
| 13 | [GRC Alerter](#grc-alerter) | Slack/Teams/email notifications with retry logic | NIST AU-6 |
| 14 | [GRC Dashboard](#grc-dashboard) | Flask web dashboard for centralized GRC visibility | — |
| 15 | [GRC Framework](#grc-framework) | Capstone package unifying all tools | All of the above |

---

## Evidence Logger

**`evidence_logger.py`** — Appends timestamped compliance evidence entries to a local log file for audit trail purposes.

```bash
python evidence_logger.py log AC-2 "IAM Console" "Reviewed user access list, 3 inactive users found"
python evidence_logger.py read
```

- Accepts control ID, source, and description as arguments
- Delimiter-separated log format for easy parsing
- Maps to **NIST 800-53 AU-2** (Event Logging)

---

## Policy Inventory

**`policy_inventory.py`** — Reads a CSV policy inventory and flags overdue reviews, missing owners, and non-active statuses.

```bash
python policy_inventory.py                    # Default: policy_inventory.csv
python policy_inventory.py /path/to/custom.csv
```

- Flags policies not reviewed within 365 days
- Exports flagged items to `flagged_policies.csv`
- Maps to **NIST 800-53 PM-1, PL-1**

---

## Control Mapper

**`control_mapper.py`** — Interactive cross-framework control mapping between NIST 800-53, CIS Benchmarks, ISO 27001, and SOC 2.

```bash
python control_mapper.py              # Interactive menu
python control_mapper.py AC-2         # Quick lookup
python control_mapper.py stats        # Database summary
```

- Ships with 8 pre-mapped NIST controls
- Add new mappings interactively and persist to JSON
- Search across all frameworks simultaneously

---

## IAM Auditor

**`iam_auditor.py`** — Audits AWS IAM users for MFA enrollment, access key rotation, and console login recency.

```bash
python iam_auditor.py    # Runs in mock mode by default
```

- **MFA check** — At least 1 device enrolled (CIS 1.10)
- **Key age check** — Access keys ≤ 90 days old (CIS 1.12)
- **Login recency** — Last console login within 90 days (NIST AC-2)
- Outputs JSON evidence file for audit records

---

## S3 Security Scanner

**`s3_security_scan.py`** — Scans all S3 buckets for encryption, public access, versioning, and logging misconfigurations.

```bash
python s3_security_scan.py    # Runs in mock mode by default
```

| Check | Standard |
|-------|----------|
| Server-side encryption enabled | CIS 2.1.1 |
| Public access block on all 4 settings | CIS 2.1.2 |
| Versioning enabled | Best practice |
| Access logging enabled | NIST AU-2 |

---

## CloudTrail Analyzer

**`cloudtrail_analyzer.py`** — Parses CloudTrail log events and flags suspicious activity patterns.

```bash
python cloudtrail_analyzer.py                          # Mock data
python cloudtrail_analyzer.py /path/to/cloudtrail.json # Real logs
```

| Detection Rule | Severity |
|----------------|----------|
| Root account usage | CRITICAL |
| Login from untrusted IP | HIGH |
| Multiple failed logins (brute force) | HIGH |
| Sensitive/destructive actions | MEDIUM |
| Non-primary region activity | LOW |

---

## Compliance Report Generator

**`compliance_report.py`** — Runs a suite of compliance checks and generates formatted assessment reports.

```bash
python compliance_report.py
```

- Checks IAM MFA, key rotation, password policy, root usage, S3 encryption, public access, CloudTrail logging
- Outputs Markdown report with executive summary + JSON for integration
- Object-oriented design with `ComplianceCheck` class

---

## Compliance Monitor

**`compliance_monitor.py`** — Runs compliance checks on a configurable schedule with proper logging.

```bash
python compliance_monitor.py                           # Default: 5 cycles, 60s interval
GRC_INTERVAL=10 GRC_MAX_CYCLES=3 python compliance_monitor.py  # Quick demo
```

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `GRC_INTERVAL` | `60` | Seconds between cycles |
| `GRC_MAX_CYCLES` | `5` | Number of cycles (0 = infinite) |
| `GRC_LOG_LEVEL` | `INFO` | Minimum log level |

- Dual output: console + `compliance_monitor.log`
- JSON Lines history in `monitor_history.jsonl`

---

## CloudFormation Validator

**`cfn_validator.py`** — Validates CloudFormation YAML templates against configurable security rules. Shift-left security for IaC.

```bash
python cfn_validator.py                                    # Default template + rules
python cfn_validator.py --template stack.yaml --format markdown --output report.md
python cfn_validator.py --severity HIGH                    # Only HIGH and CRITICAL
```

- 12 built-in rules covering S3, Security Groups, RDS, and IAM
- Rules defined in YAML — extend without changing code
- Outputs text, JSON, or Markdown reports

---

## Infrastructure Drift Detector

**`drift_detector.py`** — Captures baseline snapshots of AWS resource configurations and reports drift.

```bash
python drift_detector.py demo       # Mock data with 10 drift scenarios
python drift_detector.py baseline   # Capture baseline snapshot
python drift_detector.py scan       # Compare current state to baseline
```

- Detects added, removed, and changed resources across Security Groups, S3, and IAM
- Demo mode includes 10 realistic drift scenarios (open SSH, removed encryption, new admin users)
- Recursive dict comparison for deep configuration diffing

---

## Risk Register

**`risk_register.py`** — Full CRUD risk register backed by SQLite with likelihood × impact scoring.

```bash
python risk_register.py          # Interactive menu
python risk_register.py demo     # Load 7 sample risks
python risk_register.py summary  # Statistics
python risk_register.py export   # CSV export
```

| Score | Severity |
|-------|----------|
| 20–25 | CRITICAL |
| 15–19 | HIGH |
| 8–14 | MEDIUM |
| 1–7 | LOW |

---

## AI Risk Register

**`ai_risk_register.py`** — Specialized AI/ML risk register with EU AI Act classification and OWASP LLM Top 10 integration.

```bash
python ai_risk_register.py              # Interactive menu
python ai_risk_register.py demo         # 7 sample AI risks
python ai_risk_register.py owasp-llm    # Load OWASP LLM Top 10 (2025)
python ai_risk_register.py owasp-agentic # Load OWASP Agentic AI Top 10
```

- Tracks algorithmic bias, model security, training data privacy, hallucinations, explainability
- EU AI Act risk classification (Prohibited → Minimal Risk)
- AI complexity multiplier scoring: Likelihood × Impact × Complexity Factor
- Aligned to **NIST AI RMF 1.0**, **EU AI Act**, **ISO/IEC 42001**, **OWASP LLM Top 10 (2025)**

---

## GRC Alerter

**`grc_alerter.py`** — Sends compliance alerts via Slack webhooks, Microsoft Teams, and email with retry logic.

```bash
python grc_alerter.py config    # Show configuration
python grc_alerter.py test      # Send test alert (mock mode if unconfigured)
python grc_alerter.py send --title "Drift Detected" --finding "S3 bucket public" --severity CRITICAL --control "AC-3"
python grc_alerter.py history 20
```

- Exponential backoff retry (3 attempts)
- Severity-colored Slack message cards
- Audit trail in `alert_history.jsonl`
- Configure via environment variables (no hardcoded secrets)

---

## GRC Dashboard

**`grc_dashboard.py`** — Flask web dashboard providing centralized GRC posture visibility.

```bash
python grc_dashboard.py    # Start server at http://127.0.0.1:5000
```

- Dark-themed, responsive UI with auto-refresh (30s)
- Panels: system health, key metrics, AI risk summary, recent alerts, compliance by category
- REST API endpoints: `/api/status`, `/api/risks`, `/api/alerts`, `/api/compliance/score`
- Integrates with AI risk register database and alert history

---

## GRC Framework

**`grc_framework/`** — Capstone package that unifies all tools into a professional Python package with CLI, shared config, and unit tests.

```bash
python -m grc_framework version          # Show version
python -m grc_framework audit iam        # Run IAM audit
python -m grc_framework report compliance --markdown  # Generate report
python -m grc_framework scan s3          # Scan S3 buckets
python -m pytest grc_framework/tests/ -v # Run test suite
```

**Package structure:**
```
grc_framework/
├── __init__.py          # Package version and exports
├── __main__.py          # CLI entry point
├── config.py            # Shared configuration (dataclass)
├── core/                # Logging, JSON, timestamps
├── scanners/            # S3, IAM scanners
├── reports/             # JSON + Markdown report generation
├── risk/                # Risk register database abstraction
└── tests/               # pytest test suite
```

**Design patterns:** Singleton config, Template Method scanners, Strategy Pattern reports, Context Manager progress tracking, Fluent Interface report builder.

---

## Tech Stack

- **Language:** Python 3.13
- **Database:** SQLite (via `sqlite3`)
- **AWS SDK:** boto3 (with mock mode fallback)
- **Web:** Flask + Jinja2
- **IaC Parsing:** PyYAML
- **Notifications:** requests (webhooks), smtplib (email)
- **Testing:** pytest

## Requirements

```bash
pip install -r requirements.txt
```

## Standards Coverage

| Framework | Controls Mapped |
|-----------|----------------|
| NIST 800-53 | AC-2, AC-3, AC-6, AU-2, AU-6, CA-2, CA-7, CM-3, CM-6, IA-2, IA-5, PM-1, PM-9, PL-1, RA-3, SA-11, SC-28, SI-4, SI-7 |
| CIS Benchmarks | 1.10, 1.12, 1.16, 2.1.1, 2.1.2, 2.3.1, 2.3.2, 5.2, 5.3, §3 |
| ISO 27001/27005 | Control mapping + Risk management |
| SOC 2 | Trust Services Criteria mapping |
| NIST AI RMF 1.0 | Govern, Map, Measure, Manage |
| EU AI Act | Risk classification system |
| ISO/IEC 42001 | AI management system |
| OWASP LLM Top 10 | LLM01–LLM10 (2025) |
| OWASP Agentic AI | AGNT01–AGNT10 |

## License

MIT License — see [LICENSE](LICENSE).
