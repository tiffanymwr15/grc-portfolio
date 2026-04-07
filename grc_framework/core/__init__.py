"""
GRC Framework - Core Utilities
===============================
Common utilities used across the framework.

Demonstrates:
  - Logging setup with proper formatting
  - Timestamp utilities
  - File operations
  - JSON handling
"""

import os
import sys
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional


# Import config for paths
from ..config import get_config


def setup_logging(name: str = "grc_framework") -> logging.Logger:
    """
    Set up a properly configured logger.
    
    Demonstrates:
      - logging.getLogger() for hierarchical loggers
      - Multiple handlers (console + file)
      - Formatter with custom format strings
      - Level configuration
    """
    config = get_config()
    
    # Get or create logger
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, config.log_level))
    
    # Avoid duplicate handlers if called multiple times
    if logger.handlers:
        return logger
    
    # Console handler
    console = logging.StreamHandler(sys.stdout)
    console.setLevel(logging.INFO)
    console_fmt = logging.Formatter("%(levelname)s: %(message)s")
    console.setFormatter(console_fmt)
    logger.addHandler(console)
    
    # File handler
    log_path = Path(config.output_dir) / config.log_file
    file_handler = logging.FileHandler(log_path)
    file_handler.setLevel(logging.DEBUG)
    file_fmt = logging.Formatter(
        "%(asctime)s | %(name)s | %(levelname)s | %(message)s"
    )
    file_handler.setFormatter(file_fmt)
    logger.addHandler(file_handler)
    
    return logger


def format_timestamp(dt: Optional[datetime] = None) -> str:
    """Format datetime in ISO format."""
    if dt is None:
        dt = datetime.now()
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def load_json(filepath: str) -> Optional[Dict[str, Any]]:
    """Safely load JSON file."""
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return None


def save_json(data: Any, filepath: str) -> bool:
    """Save data to JSON file."""
    try:
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        return True
    except Exception:
        return False


def load_jsonl(filepath: str, limit: int = 100) -> List[Dict[str, Any]]:
    """
    Load JSON Lines file (last N entries).
    
    JSON Lines format: one JSON object per line
    Used for append-only logs like alert_history.jsonl
    """
    entries = []
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            lines = f.readlines()
            for line in lines[-limit:]:
                entries.append(json.loads(line.strip()))
    except FileNotFoundError:
        pass
    return entries


class ProgressTracker:
    """
    Track progress of long-running operations.
    
    Demonstrates:
      - Context manager protocol (__enter__, __exit__)
      - Progress reporting
      - Timing operations
    """
    
    def __init__(self, total: int, description: str = "Processing"):
        self.total = total
        self.current = 0
        self.description = description
        self.start_time: Optional[datetime] = None
        self.logger = setup_logging("progress")
    
    def __enter__(self):
        """Called when entering 'with' block."""
        self.start_time = datetime.now()
        self.logger.info(f"{self.description}: Starting {self.total} items...")
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Called when exiting 'with' block."""
        elapsed = datetime.now() - self.start_time
        if exc_type is None:
            self.logger.info(f"{self.description}: Complete ({elapsed.total_seconds():.1f}s)")
        else:
            self.logger.error(f"{self.description}: Failed after {elapsed.total_seconds():.1f}s")
        return False  # Don't suppress exceptions
    
    def update(self, increment: int = 1):
        """Update progress."""
        self.current += increment
        if self.current % max(1, self.total // 10) == 0:
            pct = (self.current / self.total) * 100
            self.logger.info(f"{self.description}: {pct:.0f}% ({self.current}/{self.total})")


def sanitize_filename(filename: str) -> str:
    """
    Sanitize a string for use as a filename.
    
    Removes/replaces characters that are invalid in filenames.
    """
    invalid_chars = '<>:"/\\|?*'
    for char in invalid_chars:
        filename = filename.replace(char, '_')
    return filename[:255]  # Max filename length


def ensure_file_exists(filepath: str, default_content: str = "") -> bool:
    """Create file with default content if it doesn't exist."""
    if not os.path.exists(filepath):
        try:
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(default_content)
            return True
        except Exception:
            return False
    return True
