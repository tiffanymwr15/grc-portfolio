"""
GRC Automation Framework - Python Package Structure
====================================================

This is the capstone project for the GRC Python course.
It demonstrates professional Python package organization:
  - __init__.py for package/module initialization
  - __main__.py for CLI entry point (python -m grc_framework)
  - Shared configuration system
  - Organized submodules by function
  - Unit tests with pytest

Package Structure:
  grc_framework/
  ├── __init__.py          # Package version and exports
  ├── __main__.py          # CLI entry point
  ├── config.py            # Shared configuration
  ├── core/                # Core utilities
  │   ├── __init__.py
  │   └── utils.py         # Common functions
  ├── scanners/            # AWS/resource scanners
  │   ├── __init__.py
  │   └── aws_scanner.py   # S3, IAM, CloudTrail
  ├── reports/             # Report generation
  │   ├── __init__.py
  │   └── generator.py     # Markdown/JSON reports
  ├── risk/                # Risk management
  │   ├── __init__.py
  │   └── register.py      # SQLite risk operations
  └── tests/               # Unit tests
      ├── __init__.py
      └── test_*.py

Usage:
  python -m grc_framework --help
  python -m grc_framework audit
  python -m grc_framework scan s3
  python -m grc_framework report

This file exists to document the package. The actual implementation
is in the submodules and __main__.py.
"""

# Package version - single source of truth
__version__ = "1.0.0"
__author__ = "GRC Engineering Course"

# Expose key classes/functions at package level
# This allows: from grc_framework import GRCConfig, ComplianceScanner
from .config import GRCConfig
from .core.utils import setup_logging, format_timestamp

__all__ = [
    "__version__",
    "GRCConfig",
    "setup_logging",
    "format_timestamp",
]
