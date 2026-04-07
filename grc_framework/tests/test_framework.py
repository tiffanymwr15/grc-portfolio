"""
GRC Framework - Test Suite
==========================
Unit tests using pytest.

Demonstrates:
  - pytest fixtures
  - Parameterized tests
  - Mocking
  - Test organization

Run tests:
  cd grc_framework
  pytest tests/ -v

Or:
  python -m pytest tests/ -v
"""

import sys
import json
from pathlib import Path
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import pytest
from unittest.mock import Mock, patch, MagicMock

# Import modules to test
from grc_framework import __version__, GRCConfig
from grc_framework.config import get_config, set_config
from grc_framework.core.utils import (
    format_timestamp, 
    load_json, 
    save_json,
    sanitize_filename,
    ProgressTracker
)
from grc_framework.scanners import Finding, S3Scanner, IAMScanner
from grc_framework.reports import ReportGenerator


# ═══════════════════════════════════════════════════════════════════════
# Fixtures
# ═══════════════════════════════════════════════════════════════════════

@pytest.fixture
def temp_config(tmp_path):
    """Create a temporary config for testing."""
    config = GRCConfig(
        output_dir=str(tmp_path),
        risk_db_path=str(tmp_path / "test_risks.db"),
        aws_profile="test"
    )
    set_config(config)
    return config


@pytest.fixture
def sample_findings():
    """Sample findings for testing."""
    return [
        {
            "resource_type": "S3",
            "resource_id": "bucket-1",
            "finding_type": "No Encryption",
            "severity": "HIGH",
            "description": "Bucket lacks encryption",
            "control": "SC-28",
            "remediation": "Enable encryption"
        },
        {
            "resource_type": "IAM",
            "resource_id": "user-1",
            "finding_type": "No MFA",
            "severity": "CRITICAL",
            "description": "User lacks MFA",
            "control": "IA-2",
            "remediation": "Enable MFA"
        },
        {
            "resource_type": "S3",
            "resource_id": "bucket-2",
            "finding_type": "Public Access",
            "severity": "CRITICAL",
            "description": "Bucket is public",
            "control": "AC-3",
            "remediation": "Block public access"
        }
    ]


# ═══════════════════════════════════════════════════════════════════════
# Config Tests
# ═══════════════════════════════════════════════════════════════════════

class TestConfig:
    """Test configuration module."""
    
    def test_version_exists(self):
        """Test that version is defined."""
        assert __version__ is not None
        assert isinstance(__version__, str)
        assert "." in __version__
    
    def test_config_from_env(self, monkeypatch):
        """Test loading config from environment."""
        monkeypatch.setenv("GRC_AWS_PROFILE", "test-profile")
        monkeypatch.setenv("GRC_AWS_REGION", "us-west-2")
        
        config = GRCConfig.from_env()
        assert config.aws_profile == "test-profile"
        assert config.aws_region == "us-west-2"
    
    def test_config_defaults(self):
        """Test config has sensible defaults."""
        config = GRCConfig()
        assert config.aws_region == "us-east-1"
        assert config.log_level == "INFO"


# ═══════════════════════════════════════════════════════════════════════
# Utils Tests
# ═══════════════════════════════════════════════════════════════════════

class TestUtils:
    """Test utility functions."""
    
    def test_format_timestamp(self):
        """Test timestamp formatting."""
        ts = format_timestamp()
        assert isinstance(ts, str)
        # Should contain date and time components
        assert "-" in ts  # Date separator
        assert ":" in ts  # Time separator
    
    def test_sanitize_filename(self):
        """Test filename sanitization."""
        assert sanitize_filename("test<file>.txt") == "test_file_.txt"
        assert sanitize_filename("normal.txt") == "normal.txt"
        assert len(sanitize_filename("a" * 300)) == 255  # Max length
    
    def test_load_save_json(self, tmp_path):
        """Test JSON load/save operations."""
        test_file = tmp_path / "test.json"
        test_data = {"key": "value", "number": 42}
        
        # Save
        assert save_json(test_data, str(test_file)) is True
        
        # Load
        loaded = load_json(str(test_file))
        assert loaded == test_data
        
        # Load non-existent file
        assert load_json(str(tmp_path / "nonexistent.json")) is None
    
    def test_progress_tracker(self, caplog):
        """Test progress tracker context manager."""
        import logging
        
        with ProgressTracker(total=10, description="Test") as tracker:
            for i in range(10):
                tracker.update(1)
        
        # Check that progress was logged
        assert "Test: Starting 10 items" in caplog.text
        assert "Test: Complete" in caplog.text


# ═══════════════════════════════════════════════════════════════════════
# Scanner Tests
# ═══════════════════════════════════════════════════════════════════════

class TestFinding:
    """Test Finding dataclass."""
    
    def test_finding_creation(self):
        """Test creating a finding."""
        finding = Finding(
            resource_type="S3",
            resource_id="bucket-1",
            finding_type="No Encryption",
            severity="HIGH",
            description="Test finding",
            control="SC-28",
            remediation="Enable encryption"
        )
        
        assert finding.resource_type == "S3"
        assert finding.severity == "HIGH"
        assert finding.timestamp is not None  # Auto-generated
    
    def test_finding_to_dict(self):
        """Test converting finding to dict."""
        finding = Finding(
            resource_type="S3",
            resource_id="bucket-1",
            finding_type="No Encryption",
            severity="HIGH",
            description="Test",
            control="SC-28",
            remediation="Fix it"
        )
        
        d = finding.to_dict()
        assert d["resource_type"] == "S3"
        assert d["severity"] == "HIGH"
        assert "timestamp" in d


class TestScanners:
    """Test AWS scanners (mock mode)."""
    
    def test_s3_scanner_mock_mode(self):
        """Test S3 scanner in mock mode."""
        scanner = S3Scanner(profile="test")
        findings = scanner.scan()
        
        assert len(findings) > 0
        assert all(isinstance(f, Finding) for f in findings)
    
    def test_iam_scanner_mock_mode(self):
        """Test IAM scanner in mock mode."""
        scanner = IAMScanner(profile="test")
        findings = scanner.scan()
        
        assert len(findings) > 0
        assert any(f.resource_type == "IAM" for f in findings)


# ═══════════════════════════════════════════════════════════════════════
# Report Tests
# ═══════════════════════════════════════════════════════════════════════

class TestReportGenerator:
    """Test report generation."""
    
    def test_report_generator_init(self):
        """Test report generator initialization."""
        gen = ReportGenerator()
        assert gen.findings == []
    
    def test_add_findings(self, sample_findings):
        """Test adding findings."""
        gen = ReportGenerator()
        gen.add_findings(sample_findings)
        
        assert len(gen.findings) == 3
    
    def test_generate_json(self, sample_findings, tmp_path):
        """Test JSON report generation."""
        gen = ReportGenerator(sample_findings)
        output_path = tmp_path / "report.json"
        
        result = gen.generate_json(str(output_path))
        
        assert Path(result).exists()
        
        # Verify content
        with open(result) as f:
            data = json.load(f)
        
        assert "metadata" in data
        assert "summary" in data
        assert "findings" in data
        assert data["summary"]["total"] == 3
    
    def test_generate_markdown(self, sample_findings, tmp_path):
        """Test Markdown report generation."""
        gen = ReportGenerator(sample_findings)
        output_path = tmp_path / "report.md"
        
        result = gen.generate_markdown(str(output_path))
        
        assert Path(result).exists()
        
        # Verify content
        with open(result) as f:
            content = f.read()
        
        assert "# Compliance Report" in content
        assert "CRITICAL" in content
    
    def test_executive_summary(self, sample_findings):
        """Test executive summary generation."""
        gen = ReportGenerator(sample_findings)
        summary = gen.generate_executive_summary()
        
        assert "Executive Summary" in summary
        assert "Status:" in summary
        assert "2" in summary  # Critical count


# ═══════════════════════════════════════════════════════════════════════
# Integration Tests
# ═══════════════════════════════════════════════════════════════════════

class TestIntegration:
    """Integration tests combining multiple modules."""
    
    def test_full_workflow(self, tmp_path):
        """Test complete workflow from scan to report."""
        # 1. Run mock scan
        scanner = S3Scanner()
        findings = scanner.scan()
        
        # 2. Convert to dicts
        findings_data = [f.to_dict() for f in findings]
        
        # 3. Generate report
        gen = ReportGenerator(findings_data)
        
        json_path = tmp_path / "workflow.json"
        md_path = tmp_path / "workflow.md"
        
        gen.generate_json(str(json_path))
        gen.generate_markdown(str(md_path))
        
        # 4. Verify outputs
        assert json_path.exists()
        assert md_path.exists()
        
        with open(json_path) as f:
            data = json.load(f)
        assert data["findings"]


# ═══════════════════════════════════════════════════════════════════════
# Main Entry Point
# ═══════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    # Run pytest if called directly
    pytest.main([__file__, "-v"])
