"""
GRC Framework - Configuration Module
=====================================
Centralized configuration management for all GRC tools.

Demonstrates:
  - Singleton pattern for global config
  - Environment variable integration
  - Type hints and validation
  - YAML config file loading (optional)
"""

import os
from typing import Optional
from dataclasses import dataclass, field


@dataclass
class GRCConfig:
    """
    Global configuration for GRC Framework.
    
    This is a dataclass - Python automatically generates:
      - __init__ method
      - __repr__ for printing
      - __eq__ for comparison
      - Type hints enforced (with tools like mypy)
    
    Usage:
      config = GRCConfig.from_env()
      print(config.aws_profile)
    """
    
    # AWS Configuration
    aws_profile: str = "default"
    aws_region: str = "us-east-1"
    
    # Output paths
    output_dir: str = field(default_factory=lambda: os.path.expanduser("~/grc_reports"))
    log_file: str = "grc_framework.log"
    
    # Alerting (from Lesson 14)
    slack_webhook: Optional[str] = None
    email_from: str = "grc-alerts@company.com"
    email_to: str = "security-team@company.com"
    
    # Risk register DB path
    risk_db_path: str = "ai_risk_register.db"
    
    # Dashboard settings (from Lesson 15)
    dashboard_host: str = "127.0.0.1"
    dashboard_port: int = 5000
    
    # Logging
    log_level: str = "INFO"
    
    @classmethod
    def from_env(cls) -> "GRCConfig":
        """
        Create configuration from environment variables.
        
        This is a class method - it creates instances without
        needing an existing instance first.
        
        Environment variables mapped:
          GRC_AWS_PROFILE -> aws_profile
          GRC_AWS_REGION -> aws_region
          GRC_OUTPUT_DIR -> output_dir
          GRC_SLACK_WEBHOOK -> slack_webhook
          GRC_LOG_LEVEL -> log_level
        """
        return cls(
            aws_profile=os.environ.get("GRC_AWS_PROFILE", "default"),
            aws_region=os.environ.get("GRC_AWS_REGION", "us-east-1"),
            output_dir=os.environ.get("GRC_OUTPUT_DIR", os.path.expanduser("~/grc_reports")),
            slack_webhook=os.environ.get("GRC_SLACK_WEBHOOK"),
            log_level=os.environ.get("GRC_LOG_LEVEL", "INFO"),
        )
    
    def ensure_directories(self) -> None:
        """Ensure output directories exist."""
        os.makedirs(self.output_dir, exist_ok=True)


# Global config instance (singleton pattern)
# This is created once and reused throughout the application
_config: Optional[GRCConfig] = None


def get_config() -> GRCConfig:
    """
    Get the global configuration instance.
    
    If none exists, creates one from environment variables.
    This ensures all modules use the same config.
    """
    global _config
    if _config is None:
        _config = GRCConfig.from_env()
        _config.ensure_directories()
    return _config


def set_config(config: GRCConfig) -> None:
    """Set the global configuration (useful for testing)."""
    global _config
    _config = config
    _config.ensure_directories()
