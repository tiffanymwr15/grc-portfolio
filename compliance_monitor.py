"""
Lesson 10: Scheduled Compliance Monitor
=========================================
A GRC tool that runs compliance checks on a schedule, logs results
with proper log levels, and uses environment variables for configuration.

Python concepts covered:
  - time.sleep() for scheduling
  - logging module (levels, formatters, file + console handlers)
  - os.environ / environment variables for config
  - signal handling for graceful shutdown
  - Reusing ComplianceCheck class from Lesson 9

GRC relevance:
  - NIST 800-53 CA-7 (Continuous Monitoring)
  - NIST 800-53 AU-6 (Audit Review, Analysis, and Reporting)
  - Continuous compliance monitoring and alerting
"""

import sys
import os
import time
import logging
import json
import signal
from datetime import datetime, timezone, timedelta
from collections import Counter


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


# ═══════════════════════════════════════════════════════════════════════
# CONFIGURATION VIA ENVIRONMENT VARIABLES
# ═══════════════════════════════════════════════════════════════════════
#
# Environment variables let you change behavior WITHOUT editing code.
# This is a security best practice — no secrets in source files.
#
# os.environ.get("KEY", "default") reads an env var with a fallback.
# In PowerShell, set them with: $env:GRC_INTERVAL = "300"

CHECK_INTERVAL = int(os.environ.get("GRC_INTERVAL", "60"))       # seconds between checks
MAX_CYCLES = int(os.environ.get("GRC_MAX_CYCLES", "5"))          # 0 = run forever
LOG_LEVEL = os.environ.get("GRC_LOG_LEVEL", "INFO").upper()      # DEBUG, INFO, WARNING, ERROR
AWS_PROFILE = os.environ.get("GRC_AWS_PROFILE", "grcengtest-1")
LOG_FILE = os.environ.get("GRC_LOG_FILE", os.path.join(SCRIPT_DIR, "compliance_monitor.log"))


# ═══════════════════════════════════════════════════════════════════════
# LOGGING SETUP
# ═══════════════════════════════════════════════════════════════════════
#
# The logging module is Python's built-in system for recording events.
# It's much better than print() because:
#   1. Log LEVELS: DEBUG < INFO < WARNING < ERROR < CRITICAL
#   2. Timestamps are automatic
#   3. Output goes to both console AND file simultaneously
#   4. You can filter by level (e.g., only show WARNING and above)
#
# Key objects:
#   - Logger: the main object you call .info(), .warning(), etc. on
#   - Handler: where logs go (console, file, network, etc.)
#   - Formatter: how log messages look

def setup_logging():
    """
    Configure the logging system with both console and file output.

    logging.getLogger(__name__) creates a logger named after this module.
    We add two handlers:
      - StreamHandler: prints to console (stdout)
      - FileHandler: writes to a log file
    """
    # Get (or create) a logger for this module
    logger = logging.getLogger("compliance_monitor")

    # Set the minimum level — messages below this are ignored
    # getattr(logging, "INFO") → logging.INFO (the constant 20)
    level = getattr(logging, LOG_LEVEL, logging.INFO)
    logger.setLevel(level)

    # Don't add handlers if they already exist (prevents duplicates on re-import)
    if logger.handlers:
        return logger

    # Define the log message format
    # %(asctime)s  → timestamp
    # %(name)s     → logger name
    # %(levelname)s → INFO, WARNING, etc.
    # %(message)s  → the actual message
    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-8s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # ─── Console handler ──────────────────────────────────────────
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # ─── File handler ─────────────────────────────────────────────
    file_handler = logging.FileHandler(LOG_FILE, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)  # File gets everything
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    return logger


# ═══════════════════════════════════════════════════════════════════════
# COMPLIANCE CHECK CLASS (reused from Lesson 9, simplified)
# ═══════════════════════════════════════════════════════════════════════

class ComplianceCheck:
    """A single compliance check result."""

    def __init__(self, control_id, description, status, evidence, severity="MEDIUM"):
        self.control_id = control_id
        self.description = description
        self.status = status
        self.evidence = evidence
        self.severity = severity
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def is_passing(self):
        return self.status == "PASS"

    def to_dict(self):
        return {
            "control_id": self.control_id,
            "description": self.description,
            "status": self.status,
            "evidence": self.evidence,
            "severity": self.severity,
            "timestamp": self.timestamp,
        }


# ═══════════════════════════════════════════════════════════════════════
# MOCK COMPLIANCE CHECKS
# ═══════════════════════════════════════════════════════════════════════
# In production, these would call boto3 APIs. For the lesson, we
# simulate some variability so the monitor has something to detect.

import random

def run_checks(cycle_number):
    """
    Run compliance checks with some simulated variability.

    The random element simulates real-world drift — a bucket might
    become public, a key might expire, etc. This makes the monitor
    output more interesting than static results.
    """
    checks = []

    # ─── MFA Check (usually passes, occasionally fails) ──────────
    mfa_fail = random.random() < 0.3  # 30% chance of failure
    if mfa_fail:
        checks.append(ComplianceCheck(
            "IA-2", "IAM MFA enrollment",
            "FAIL", "1 user lacks MFA: dev-mike",
            "HIGH",
        ))
    else:
        checks.append(ComplianceCheck(
            "IA-2", "IAM MFA enrollment",
            "PASS", "All users have MFA enabled",
            "HIGH",
        ))

    # ─── Key rotation (degrades over time) ────────────────────────
    key_age = 45 + (cycle_number * 10)  # Gets worse each cycle
    if key_age > 90:
        checks.append(ComplianceCheck(
            "IA-5", "Access key rotation",
            "FAIL", f"Key age {key_age}d exceeds 90d limit",
            "HIGH",
        ))
    else:
        checks.append(ComplianceCheck(
            "IA-5", "Access key rotation",
            "PASS", f"All keys within {key_age}d (limit 90d)",
            "HIGH",
        ))

    # ─── S3 encryption (stable) ───────────────────────────────────
    checks.append(ComplianceCheck(
        "SC-28", "S3 encryption at rest",
        "PASS", "All buckets encrypted",
        "HIGH",
    ))

    # ─── S3 public access (occasional drift) ──────────────────────
    public_drift = random.random() < 0.2  # 20% chance
    if public_drift:
        checks.append(ComplianceCheck(
            "AC-3", "S3 public access blocked",
            "FAIL", "marketing-uploads has public access enabled",
            "CRITICAL",
        ))
    else:
        checks.append(ComplianceCheck(
            "AC-3", "S3 public access blocked",
            "PASS", "All buckets block public access",
            "CRITICAL",
        ))

    # ─── CloudTrail (stable) ──────────────────────────────────────
    checks.append(ComplianceCheck(
        "AU-2", "CloudTrail logging",
        "PASS", "CloudTrail active in all regions",
        "CRITICAL",
    ))

    # ─── Root usage (rare but critical) ───────────────────────────
    root_used = random.random() < 0.1  # 10% chance
    if root_used:
        checks.append(ComplianceCheck(
            "AC-6", "Root account usage",
            "FAIL", "Root account login detected from 45.33.32.156",
            "CRITICAL",
        ))
    else:
        checks.append(ComplianceCheck(
            "AC-6", "Root account usage",
            "PASS", "No root activity detected",
            "CRITICAL",
        ))

    return checks


# ═══════════════════════════════════════════════════════════════════════
# MONITORING LOOP
# ═══════════════════════════════════════════════════════════════════════

# Global flag for graceful shutdown
running = True


def handle_shutdown(signum, frame):
    """
    Signal handler for graceful shutdown.

    signal.signal() registers a function to call when the OS sends
    a signal (like Ctrl+C → SIGINT). This lets us clean up properly
    instead of crashing mid-check.
    """
    global running
    running = False


def log_cycle_results(logger, cycle, checks):
    """Log the results of one monitoring cycle."""

    total = len(checks)
    passed = len([c for c in checks if c.is_passing()])
    failed = total - passed

    if failed == 0:
        logger.info(f"Cycle {cycle}: ALL CLEAR — {passed}/{total} checks passed")
    else:
        logger.warning(f"Cycle {cycle}: {failed} FAILURE(S) — {passed}/{total} passed")

        # Log each failure with appropriate level
        for check in checks:
            if not check.is_passing():
                if check.severity == "CRITICAL":
                    logger.critical(f"  [{check.control_id}] {check.description}: {check.evidence}")
                elif check.severity == "HIGH":
                    logger.error(f"  [{check.control_id}] {check.description}: {check.evidence}")
                else:
                    logger.warning(f"  [{check.control_id}] {check.description}: {check.evidence}")


def save_cycle_json(cycle, checks, filepath):
    """Append cycle results to a JSON Lines file (.jsonl)."""
    record = {
        "cycle": cycle,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total": len(checks),
        "passed": len([c for c in checks if c.is_passing()]),
        "failed": len([c for c in checks if not c.is_passing()]),
        "checks": [c.to_dict() for c in checks],
    }

    # "a" mode = append — each cycle adds one line
    with open(filepath, "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")


def monitor_loop(logger):
    """
    Main monitoring loop.

    time.sleep(seconds) pauses execution. Combined with a while loop,
    this creates a scheduled process that runs checks at regular intervals.

    The 'global running' flag lets us stop cleanly via Ctrl+C.
    """
    global running

    jsonl_path = os.path.join(SCRIPT_DIR, "monitor_history.jsonl")

    logger.info("=" * 55)
    logger.info("COMPLIANCE MONITOR STARTED")
    logger.info(f"  Interval: {CHECK_INTERVAL}s | Max cycles: {MAX_CYCLES or 'unlimited'}")
    logger.info(f"  Log level: {LOG_LEVEL} | Log file: {LOG_FILE}")
    logger.info(f"  AWS profile: {AWS_PROFILE}")
    logger.info(f"  History file: {jsonl_path}")
    logger.info("=" * 55)

    cycle = 0

    while running:
        cycle += 1

        # Check if we've hit the max
        if MAX_CYCLES > 0 and cycle > MAX_CYCLES:
            logger.info(f"Reached max cycles ({MAX_CYCLES}). Stopping.")
            break

        logger.info(f"─── Cycle {cycle} starting ───")

        # Run checks
        checks = run_checks(cycle)

        # Log results
        log_cycle_results(logger, cycle, checks)

        # Save to history
        save_cycle_json(cycle, checks, jsonl_path)

        # Wait for next cycle (unless this is the last one)
        if MAX_CYCLES > 0 and cycle >= MAX_CYCLES:
            break

        if running:
            logger.debug(f"Sleeping {CHECK_INTERVAL}s until next cycle...")
            # time.sleep() can be interrupted by Ctrl+C
            try:
                time.sleep(CHECK_INTERVAL)
            except KeyboardInterrupt:
                running = False

    # ─── Shutdown summary ─────────────────────────────────────────
    logger.info("=" * 55)
    logger.info(f"MONITOR STOPPED after {cycle} cycle(s)")
    logger.info(f"  History saved to: {jsonl_path}")
    logger.info(f"  Full log at: {LOG_FILE}")
    logger.info("=" * 55)


# ═══════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    # Register signal handlers for graceful shutdown
    # SIGINT = Ctrl+C, SIGTERM = kill command
    signal.signal(signal.SIGINT, handle_shutdown)
    try:
        signal.signal(signal.SIGTERM, handle_shutdown)
    except (OSError, AttributeError):
        pass  # SIGTERM not available on all platforms

    # Setup logging
    logger = setup_logging()

    # Print config summary
    print(f"\n  📡 Compliance Monitor")
    print(f"  {'─' * 40}")
    print(f"  Interval:    {CHECK_INTERVAL}s (set $env:GRC_INTERVAL to change)")
    print(f"  Max cycles:  {MAX_CYCLES} (set $env:GRC_MAX_CYCLES, 0=infinite)")
    print(f"  Log level:   {LOG_LEVEL} (set $env:GRC_LOG_LEVEL)")
    print(f"  Log file:    {LOG_FILE}")
    print(f"  Press Ctrl+C to stop\n")

    # Run the monitor
    monitor_loop(logger)
