"""
Lesson 3: Compliance Evidence Logger
=====================================
A GRC tool that records timestamped compliance evidence entries to a log file.

Python concepts covered:
  - File I/O: open(), write(), read(), append mode ("a")
  - datetime: timestamps, strftime() formatting
  - os.path: checking if files exist, getting file size
  - sys.argv: command-line arguments
  - String formatting and joining

GRC relevance:
  - NIST 800-53 AU-2 (Event Logging)
  - NIST 800-53 CA-7 (Continuous Monitoring)
  - Audit evidence collection and chain of custody
"""

import sys
import os
from datetime import datetime


# ─── CONFIGURATION ────────────────────────────────────────────────────
# The log file path. You can change this or pass it as an environment variable.
# os.path.join() builds file paths that work on any OS (Windows, Mac, Linux).

LOG_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(LOG_DIR, "evidence_log.txt")

# The delimiter between fields in each log entry.
# Using " | " makes the log easy to read AND easy to parse later (Lesson 4).
DELIMITER = " | "


# ─── CORE FUNCTIONS ──────────────────────────────────────────────────

def get_timestamp():
    """
    Return the current date and time as a formatted string.

    datetime.now() returns the current local date/time as a datetime object.
    .strftime() converts it to a string using format codes:
      %Y = 4-digit year     %m = 2-digit month    %d = 2-digit day
      %H = 24-hour hour     %M = minute            %S = second
    """
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def log_evidence(control_id, description, source):
    """
    Append a single evidence entry to the log file.

    open() with mode "a" means APPEND — it adds to the end of the file
    without erasing what's already there. If the file doesn't exist, it
    creates it automatically.

    Compare to mode "w" (write) which OVERWRITES the entire file — dangerous
    for a log! Always use "a" for logs.
    """
    timestamp = get_timestamp()

    # Build the log entry as a single line with delimiters
    entry = DELIMITER.join([timestamp, control_id, source, description])

    # open() returns a file object. "a" = append, encoding="utf-8" handles
    # special characters properly. The 'with' statement automatically closes
    # the file when we're done — even if an error occurs.
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(entry + "\n")

    # Also print to console so the user sees confirmation
    print(f"\n  ✅ Evidence logged successfully")
    print(f"  Time:        {timestamp}")
    print(f"  Control ID:  {control_id}")
    print(f"  Source:       {source}")
    print(f"  Description: {description}")
    print(f"  File:        {LOG_FILE}\n")


def read_evidence():
    """
    Read and display all entries from the log file.

    os.path.exists() checks if a file exists before we try to read it.
    This prevents a FileNotFoundError crash.

    open() with mode "r" means READ (this is the default mode).
    .readlines() returns a list where each item is one line of the file.
    .strip() removes the trailing newline character from each line.
    """
    if not os.path.exists(LOG_FILE):
        print(f"\n  No evidence log found at: {LOG_FILE}")
        print("  Run 'log' command first to create entries.\n")
        return

    # os.path.getsize() returns file size in bytes
    file_size = os.path.getsize(LOG_FILE)

    with open(LOG_FILE, "r", encoding="utf-8") as f:
        lines = f.readlines()

    if not lines:
        print("\n  Evidence log is empty.\n")
        return

    print("\n" + "=" * 70)
    print("  COMPLIANCE EVIDENCE LOG")
    print(f"  File: {LOG_FILE}")
    print(f"  Entries: {len(lines)}  |  Size: {file_size} bytes")
    print("=" * 70)

    # Print column headers
    print(f"\n  {'#':<4} {'Timestamp':<22} {'Control':<12} {'Source':<20} {'Description'}")
    print(f"  {'-'*4} {'-'*22} {'-'*12} {'-'*20} {'-'*30}")

    for i, line in enumerate(lines, start=1):
        # enumerate() gives us both the index AND the value
        # start=1 means we count from 1 instead of 0
        line = line.strip()
        if not line:
            continue

        # .split() with our delimiter breaks the line back into fields
        parts = line.split(DELIMITER)

        if len(parts) >= 4:
            timestamp, control_id, source, description = parts[0], parts[1], parts[2], parts[3]
            print(f"  {i:<4} {timestamp:<22} {control_id:<12} {source:<20} {description}")
        else:
            # Handle malformed lines gracefully
            print(f"  {i:<4} [malformed] {line}")

    print()


def show_usage():
    """Print help text explaining how to use this tool."""
    print("""
  📋 Compliance Evidence Logger
  ─────────────────────────────

  Usage:
    python evidence_logger.py log <control_id> <source> <description>
    python evidence_logger.py read
    python evidence_logger.py help

  Commands:
    log   - Record a new evidence entry
    read  - Display all logged entries
    help  - Show this help message

  Examples:
    python evidence_logger.py log AC-2 "IAM Console" "Reviewed user access list, 3 inactive users found"
    python evidence_logger.py log IA-5 "Password Audit" "Password policy meets 12-char minimum requirement"
    python evidence_logger.py log CM-6 "AWS Config" "All S3 buckets verified encrypted at rest"
    python evidence_logger.py read
    """)


# ─── MAIN ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    # sys.argv is a list of command-line arguments:
    #   sys.argv[0] = the script name itself
    #   sys.argv[1] = the first argument (the command)
    #   sys.argv[2], [3], [4] = additional arguments

    if len(sys.argv) < 2:
        show_usage()
        sys.exit(1)

    # .lower() normalizes the command so "LOG", "Log", and "log" all work
    command = sys.argv[1].lower()

    if command == "help":
        show_usage()

    elif command == "log":
        # We need exactly 3 more arguments: control_id, source, description
        if len(sys.argv) < 5:
            print("\n  Error: 'log' requires 3 arguments: <control_id> <source> <description>")
            print("  Example: python evidence_logger.py log AC-2 \"IAM Console\" \"Reviewed user list\"\n")
            sys.exit(1)

        control_id = sys.argv[2]
        source = sys.argv[3]
        description = sys.argv[4]
        log_evidence(control_id, description, source)

    elif command == "read":
        read_evidence()

    else:
        print(f"\n  Unknown command: '{command}'")
        show_usage()
        sys.exit(1)
