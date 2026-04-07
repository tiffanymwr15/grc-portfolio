"""
GRC Framework - CLI Entry Point
==================================
Main command-line interface for the GRC Framework.

Demonstrates:
  - __main__.py for python -m package execution
  - argparse subparsers for command hierarchies
  - Module organization and imports
  - CLI-driven workflow

Usage:
  python -m grc_framework --help
  python -m grc_framework version
  python -m grc_framework audit iam
  python -m grc_framework scan s3
  python -m grc_framework report compliance
  python -m grc_framework dashboard
"""

import sys
import argparse
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from grc_framework import __version__, GRCConfig
from grc_framework.config import get_config, set_config
from grc_framework.core.utils import setup_logging, format_timestamp


def cmd_version(args):
    """Display version information."""
    print(f"GRC Framework v{__version__}")
    print("Python GRC Engineering Course - Capstone Project")
    return 0


def cmd_config(args):
    """Display current configuration."""
    config = get_config()
    print("\nGRC Framework Configuration:")
    print("=" * 40)
    print(f"AWS Profile:     {config.aws_profile}")
    print(f"AWS Region:      {config.aws_region}")
    print(f"Output Dir:      {config.output_dir}")
    print(f"Log File:        {config.log_file}")
    print(f"Log Level:       {config.log_level}")
    print(f"Risk DB:         {config.risk_db_path}")
    print(f"Dashboard:       {config.dashboard_host}:{config.dashboard_port}")
    print(f"Slack Webhook:   {'Set' if config.slack_webhook else 'Not configured'}")
    return 0


def cmd_audit(args):
    """Run compliance audit."""
    logger = setup_logging()
    config = get_config()
    
    logger.info(f"Starting {args.target} audit...")
    
    # This would integrate with Lesson 6 (IAM), Lesson 7 (S3), etc.
    # For demonstration, we show the structure
    
    if args.target == "iam":
        logger.info("Auditing IAM users, MFA status, access keys...")
        # Would call: from grc_framework.scanners.aws_scanner import audit_iam
        print("  [MOCK] IAM audit complete - 3 users, 1 without MFA")
        
    elif args.target == "s3":
        logger.info("Auditing S3 buckets, encryption, public access...")
        print("  [MOCK] S3 audit complete - 5 buckets, 1 public")
        
    elif args.target == "all":
        logger.info("Running full compliance audit...")
        print("  [MOCK] Full audit complete")
    
    logger.info(f"Audit report saved to: {config.output_dir}/")
    return 0


def cmd_scan(args):
    """Run resource scanner."""
    logger = setup_logging()
    
    if args.resource == "s3":
        logger.info("Scanning S3 buckets...")
        print("  [MOCK] Found 5 buckets - 1 compliance issue")
        
    elif args.resource == "cloudtrail":
        logger.info("Analyzing CloudTrail logs...")
        print("  [MOCK] Analyzed 1000 events - 2 suspicious patterns")
        
    elif args.resource == "drift":
        logger.info("Checking for infrastructure drift...")
        print("  [MOCK] 3 resources changed from baseline")
    
    return 0


def cmd_report(args):
    """Generate compliance report."""
    logger = setup_logging()
    config = get_config()
    
    logger.info(f"Generating {args.type} report...")
    
    timestamp = format_timestamp().replace(" ", "_").replace(":", "-")
    report_file = Path(config.output_dir) / f"compliance_report_{timestamp}.json"
    
    # Mock report data
    report = {
        "generated_at": format_timestamp(),
        "type": args.type,
        "findings": {
            "critical": 2,
            "high": 5,
            "medium": 8,
            "low": 12
        },
        "compliance_score": 78
    }
    
    import json
    with open(report_file, "w") as f:
        json.dump(report, f, indent=2)
    
    logger.info(f"Report saved: {report_file}")
    
    if args.markdown:
        md_file = report_file.with_suffix(".md")
        with open(md_file, "w") as f:
            f.write(f"# Compliance Report\n\nScore: {report['compliance_score']}%\n")
        logger.info(f"Markdown report: {md_file}")
    
    return 0


def cmd_risk(args):
    """Risk register operations."""
    logger = setup_logging()
    
    if args.operation == "list":
        print("\nOpen Risks:")
        print("-" * 40)
        print("  [MOCK] AI-RISK-001: LLM Hallucination (Score: 30)")
        print("  [MOCK] AI-RISK-002: Data Poisoning (Score: 22)")
        
    elif args.operation == "add":
        logger.info(f"Adding new risk: {args.title}")
        print(f"  [MOCK] Risk added with ID: RISK-{format_timestamp()[:10]}")
        
    elif args.operation == "summary":
        print("\nRisk Summary:")
        print("  Total: 20 | Open: 8 | Critical: 3")
    
    return 0


def cmd_alert(args):
    """Send test alert."""
    logger = setup_logging()
    config = get_config()
    
    logger.info(f"Sending {args.severity} alert...")
    
    if config.slack_webhook:
        print("  [MOCK] Alert sent to Slack")
    else:
        print("  [MOCK] Slack not configured - would log locally")
    
    print(f"  Title: {args.title}")
    print(f"  Severity: {args.severity}")
    
    return 0


def cmd_dashboard(args):
    """Start the web dashboard."""
    logger = setup_logging()
    config = get_config()
    
    print(f"\nStarting GRC Dashboard...")
    print(f"URL: http://{config.dashboard_host}:{config.dashboard_port}/")
    print("Press Ctrl+C to stop\n")
    
    try:
        # This would import and run the Flask app from Lesson 15
        # For now, show the structure
        print("  [MOCK] Flask server would start here")
        print("  (In production: from grc_framework.dashboard import app; app.run())")
        
        # Keep running until interrupted
        import time
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\nDashboard stopped.")
    
    return 0


def main():
    """
    Main CLI entry point.
    
    Demonstrates sophisticated argparse usage:
      - Subparsers for command categories
      - Parent parsers for shared arguments
      - Type validation
      - Help generation
    """
    parser = argparse.ArgumentParser(
        prog="grc_framework",
        description="GRC Automation Framework - Unified CLI for compliance tools",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s version                    Show version info
  %(prog)s config                     Display configuration
  %(prog)s audit iam                  Audit IAM compliance
  %(prog)s scan s3                    Scan S3 buckets
  %(prog)s report compliance          Generate report
  %(prog)s risk list                  List open risks
  %(prog)s alert --title "Test"       Send test alert
  %(prog)s dashboard                  Start web dashboard
        """
    )
    
    parser.add_argument(
        "--version", 
        action="version", 
        version=f"%(prog)s {__version__}"
    )
    
    # Create subparsers for commands
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # version command
    version_parser = subparsers.add_parser("version", help="Show version")
    version_parser.set_defaults(func=cmd_version)
    
    # config command
    config_parser = subparsers.add_parser("config", help="Show configuration")
    config_parser.set_defaults(func=cmd_config)
    
    # audit command
    audit_parser = subparsers.add_parser("audit", help="Run compliance audit")
    audit_parser.add_argument(
        "target", 
        choices=["iam", "s3", "cloudtrail", "all"],
        help="What to audit"
    )
    audit_parser.set_defaults(func=cmd_audit)
    
    # scan command
    scan_parser = subparsers.add_parser("scan", help="Scan resources")
    scan_parser.add_argument(
        "resource",
        choices=["s3", "cloudtrail", "drift", "cfn"],
        help="Resource type to scan"
    )
    scan_parser.set_defaults(func=cmd_scan)
    
    # report command
    report_parser = subparsers.add_parser("report", help="Generate report")
    report_parser.add_argument(
        "type",
        choices=["compliance", "risk", "executive"],
        default="compliance",
        nargs="?",
        help="Report type"
    )
    report_parser.add_argument(
        "--markdown", "-m",
        action="store_true",
        help="Also generate Markdown version"
    )
    report_parser.set_defaults(func=cmd_report)
    
    # risk command
    risk_parser = subparsers.add_parser("risk", help="Risk register operations")
    risk_parser.add_argument(
        "operation",
        choices=["list", "add", "update", "delete", "summary"],
        help="Operation to perform"
    )
    risk_parser.add_argument(
        "--title",
        help="Risk title (for add operation)"
    )
    risk_parser.set_defaults(func=cmd_risk)
    
    # alert command
    alert_parser = subparsers.add_parser("alert", help="Send alert")
    alert_parser.add_argument(
        "--title",
        default="Test Alert",
        help="Alert title"
    )
    alert_parser.add_argument(
        "--severity",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
        default="HIGH",
        help="Alert severity"
    )
    alert_parser.set_defaults(func=cmd_alert)
    
    # dashboard command
    dashboard_parser = subparsers.add_parser("dashboard", help="Start web dashboard")
    dashboard_parser.set_defaults(func=cmd_dashboard)
    
    # Parse arguments
    args = parser.parse_args()
    
    # If no command given, show help
    if not hasattr(args, "func"):
        parser.print_help()
        return 1
    
    # Execute command
    try:
        return args.func(args)
    except Exception as e:
        logger = setup_logging()
        logger.error(f"Command failed: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
