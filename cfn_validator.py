"""
Lesson 11: CloudFormation Template Validator
=============================================
A GRC tool that reads CloudFormation YAML templates, validates them
against a configurable rules file, and reports security violations.

Python concepts covered:
  - YAML parsing with pyyaml
  - argparse for CLI argument handling
  - Schema/rule-based validation
  - Navigating nested dicts with dot-path strings

GRC relevance:
  - NIST 800-53 SA-11 (Developer Security Testing)
  - NIST 800-53 CM-6 (Configuration Settings)
  - "Shift-left" security — catch issues before deployment
  - CIS Benchmark alignment for S3, EC2, RDS, IAM
"""

import sys
import os
import json
import argparse
from datetime import datetime

# ─── DEPENDENCY CHECK ─────────────────────────────────────────────────
# pyyaml is not in the standard library — it must be installed.
# We check early and give a helpful message if missing.
try:
    import yaml
except ImportError:
    print("\n  ❌ pyyaml is required. Install it with:")
    print('     pip install pyyaml\n')
    sys.exit(1)


# ─── CloudFormation Intrinsic Function Handlers ──────────────────────
# yaml.safe_load() doesn't recognize CloudFormation tags like !Ref, !Sub,
# !GetAtt. We register custom constructors so they're parsed as plain
# strings or dicts instead of raising errors.

def _cfn_tag(loader, tag_suffix, node):
    """Handle any CloudFormation intrinsic function tag."""
    if isinstance(node, yaml.ScalarNode):
        return loader.construct_scalar(node)
    elif isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node)
    elif isinstance(node, yaml.MappingNode):
        return loader.construct_mapping(node)

# Register all common CloudFormation intrinsic functions
for tag in ["!Ref", "!Sub", "!GetAtt", "!Join", "!Select", "!Split",
            "!If", "!Not", "!Equals", "!And", "!Or", "!FindInMap",
            "!Base64", "!Cidr", "!ImportValue", "!GetAZs",
            "!Condition", "!Transform"]:
    yaml.SafeLoader.add_constructor(tag, lambda loader, node, t=tag: _cfn_tag(loader, t, node))


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


# ═══════════════════════════════════════════════════════════════════════
# ARGPARSE — Command-Line Interface
# ═══════════════════════════════════════════════════════════════════════
#
# argparse is Python's standard module for building CLI tools.
# Instead of manually parsing sys.argv, argparse:
#   1. Defines flags (--template, --rules, --format)
#   2. Validates inputs automatically
#   3. Generates --help text for free
#   4. Returns a clean namespace object with all arguments
#
# This is how professional CLI tools are built.

def build_parser():
    """
    Build and return the argument parser.

    argparse.ArgumentParser() creates the parser.
    .add_argument() defines each flag:
      - positional args (no --)  → required
      - optional flags (--flag)  → optional with defaults
      - type=           → auto-convert (str, int, float)
      - default=        → value if flag not provided
      - choices=        → limit to specific values
      - help=           → description for --help output
    """
    parser = argparse.ArgumentParser(
        description="Validate CloudFormation templates against GRC security rules",
        # epilog shows after --help
        epilog="Example: cfn_validator.py --template stack.yaml --rules cfn_rules.yaml",
    )

    parser.add_argument(
        "--template", "-t",
        default=os.path.join(SCRIPT_DIR, "sample_template.yaml"),
        help="Path to the CloudFormation YAML template (default: sample_template.yaml)",
    )

    parser.add_argument(
        "--rules", "-r",
        default=os.path.join(SCRIPT_DIR, "cfn_rules.yaml"),
        help="Path to the validation rules YAML file (default: cfn_rules.yaml)",
    )

    parser.add_argument(
        "--format", "-f",
        choices=["text", "json", "markdown"],
        default="text",
        help="Output format: text, json, or markdown (default: text)",
    )

    parser.add_argument(
        "--output", "-o",
        default=None,
        help="Save report to file (optional)",
    )

    parser.add_argument(
        "--severity",
        choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
        default="LOW",
        help="Minimum severity to report (default: LOW = show everything)",
    )

    return parser


# ═══════════════════════════════════════════════════════════════════════
# YAML PARSING
# ═══════════════════════════════════════════════════════════════════════
#
# YAML is like JSON but more readable — CloudFormation uses it heavily.
# pyyaml's yaml.safe_load() converts YAML text into Python dicts/lists.
#
# yaml.safe_load() vs yaml.load():
#   - safe_load() only creates basic Python types (safe!)
#   - load() can execute arbitrary Python code (dangerous!)
#   ALWAYS use safe_load() for untrusted input.

def load_yaml(filepath):
    """Load and parse a YAML file, returning a Python dict."""
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        return data
    except FileNotFoundError:
        print(f"\n  ❌ File not found: {filepath}")
        sys.exit(1)
    except yaml.YAMLError as e:
        print(f"\n  ❌ YAML parsing error in {filepath}:\n  {e}")
        sys.exit(1)


# ═══════════════════════════════════════════════════════════════════════
# DOT-PATH NAVIGATION
# ═══════════════════════════════════════════════════════════════════════
#
# Rules reference nested properties like "Properties.BucketEncryption".
# We need a function that can walk into nested dicts using a dot-separated path.

def get_nested(data, path):
    """
    Navigate into a nested dict using a dot-separated path.

    get_nested({"a": {"b": {"c": 42}}}, "a.b.c") → 42
    get_nested({"a": {"b": 1}}, "a.x") → None

    .split(".") breaks "Properties.BucketEncryption" into ["Properties", "BucketEncryption"]
    Then we walk through each key with a for loop.
    """
    keys = path.split(".")
    current = data

    for key in keys:
        if isinstance(current, dict) and key in current:
            current = current[key]
        else:
            return None  # Path doesn't exist

    return current


# ═══════════════════════════════════════════════════════════════════════
# VALIDATION ENGINE
# ═══════════════════════════════════════════════════════════════════════

class Finding:
    """Represents a single validation finding (pass or fail)."""

    def __init__(self, rule_id, rule_name, resource_name, resource_type,
                 status, detail, severity, standard):
        self.rule_id = rule_id
        self.rule_name = rule_name
        self.resource_name = resource_name
        self.resource_type = resource_type
        self.status = status      # "PASS" or "FAIL"
        self.detail = detail
        self.severity = severity
        self.standard = standard

    def to_dict(self):
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "resource": self.resource_name,
            "resource_type": self.resource_type,
            "status": self.status,
            "detail": self.detail,
            "severity": self.severity,
            "standard": self.standard,
        }


def check_property_exists(resource, resource_name, rule):
    """Check that a property path exists in the resource."""
    value = get_nested(resource, rule["property_path"])

    if value is not None:
        return Finding(
            rule["id"], rule["name"], resource_name, rule["resource_type"],
            "PASS", f"{rule['property_path']} is configured",
            rule["severity"], rule.get("standard", ""),
        )
    else:
        return Finding(
            rule["id"], rule["name"], resource_name, rule["resource_type"],
            "FAIL", f"Missing {rule['property_path']}",
            rule["severity"], rule.get("standard", ""),
        )


def check_property_equals(resource, resource_name, rule):
    """Check that a property has a specific expected value."""
    value = get_nested(resource, rule["property_path"])
    expected = rule["expected_value"]

    if value == expected:
        return Finding(
            rule["id"], rule["name"], resource_name, rule["resource_type"],
            "PASS", f"{rule['property_path']} = {value}",
            rule["severity"], rule.get("standard", ""),
        )
    else:
        return Finding(
            rule["id"], rule["name"], resource_name, rule["resource_type"],
            "FAIL", f"{rule['property_path']} = {value} (expected {expected})",
            rule["severity"], rule.get("standard", ""),
        )


def check_property_not_in(resource, resource_name, rule):
    """Check that a property value is NOT in a list of forbidden values."""
    value = get_nested(resource, rule["property_path"])
    forbidden = rule.get("forbidden_values", [])

    if value is None or value not in forbidden:
        return Finding(
            rule["id"], rule["name"], resource_name, rule["resource_type"],
            "PASS", f"{rule['property_path']} is acceptable (value: {value})",
            rule["severity"], rule.get("standard", ""),
        )
    else:
        return Finding(
            rule["id"], rule["name"], resource_name, rule["resource_type"],
            "FAIL", f"{rule['property_path']} = '{value}' (forbidden)",
            rule["severity"], rule.get("standard", ""),
        )


def check_property_not_plaintext(resource, resource_name, rule):
    """Check that a property is not a hardcoded plaintext string (should use !Ref or similar)."""
    value = get_nested(resource, rule["property_path"])

    # In YAML, !Ref and !Sub are parsed as special objects, not plain strings
    # A plain string means it's hardcoded
    if value is None:
        return Finding(
            rule["id"], rule["name"], resource_name, rule["resource_type"],
            "PASS", f"{rule['property_path']} not set",
            rule["severity"], rule.get("standard", ""),
        )
    elif isinstance(value, str):
        # Plain string = hardcoded = BAD
        masked = value[:3] + "***" if len(value) > 3 else "***"
        return Finding(
            rule["id"], rule["name"], resource_name, rule["resource_type"],
            "FAIL", f"{rule['property_path']} is a hardcoded string ('{masked}')",
            rule["severity"], rule.get("standard", ""),
        )
    else:
        # Not a string — likely a !Ref or !Sub intrinsic function
        return Finding(
            rule["id"], rule["name"], resource_name, rule["resource_type"],
            "PASS", f"{rule['property_path']} uses a dynamic reference",
            rule["severity"], rule.get("standard", ""),
        )


def check_no_open_port(resource, resource_name, rule):
    """Check that a security group doesn't allow a specific port from 0.0.0.0/0."""
    port = rule["port"]
    ingress = get_nested(resource, "Properties.SecurityGroupIngress")

    if not ingress or not isinstance(ingress, list):
        return Finding(
            rule["id"], rule["name"], resource_name, rule["resource_type"],
            "PASS", f"No ingress rules defined",
            rule["severity"], rule.get("standard", ""),
        )

    # Check each ingress rule for the forbidden port + open CIDR
    for ingress_rule in ingress:
        from_port = ingress_rule.get("FromPort", 0)
        to_port = ingress_rule.get("ToPort", 0)
        cidr = ingress_rule.get("CidrIp", "")

        if from_port <= port <= to_port and cidr in ["0.0.0.0/0", "::/0"]:
            return Finding(
                rule["id"], rule["name"], resource_name, rule["resource_type"],
                "FAIL", f"Port {port} open to {cidr}",
                rule["severity"], rule.get("standard", ""),
            )

    return Finding(
        rule["id"], rule["name"], resource_name, rule["resource_type"],
        "PASS", f"Port {port} not open to the world",
        rule["severity"], rule.get("standard", ""),
    )


def check_no_wildcard_policy(resource, resource_name, rule):
    """Check that IAM policies don't grant Action * on Resource *."""
    policies = get_nested(resource, "Properties.Policies")

    if not policies:
        return Finding(
            rule["id"], rule["name"], resource_name, rule["resource_type"],
            "PASS", "No inline policies defined",
            rule["severity"], rule.get("standard", ""),
        )

    for policy in policies:
        statements = get_nested(policy, "PolicyDocument.Statement") or []
        for stmt in statements:
            action = stmt.get("Action", "")
            resource_val = stmt.get("Resource", "")
            if action == "*" and resource_val == "*":
                return Finding(
                    rule["id"], rule["name"], resource_name, rule["resource_type"],
                    "FAIL", f"Policy '{policy.get('PolicyName', '?')}' grants Action:* Resource:*",
                    rule["severity"], rule.get("standard", ""),
                )

    return Finding(
        rule["id"], rule["name"], resource_name, rule["resource_type"],
        "PASS", "No wildcard policies found",
        rule["severity"], rule.get("standard", ""),
    )


# Map rule check types to functions
CHECK_FUNCTIONS = {
    "property_exists": check_property_exists,
    "property_equals": check_property_equals,
    "property_not_in": check_property_not_in,
    "property_not_plaintext": check_property_not_plaintext,
    "no_open_port": check_no_open_port,
    "no_wildcard_policy": check_no_wildcard_policy,
}


def validate_template(template, rules):
    """
    Run all rules against all matching resources in the template.

    This is the core engine:
    1. Loop through each rule
    2. Find resources that match the rule's resource_type
    3. Run the appropriate check function
    4. Collect all findings
    """
    findings = []
    resources = template.get("Resources", {})

    for rule in rules:
        check_type = rule.get("check")
        check_fn = CHECK_FUNCTIONS.get(check_type)

        if not check_fn:
            print(f"  ⚠️  Unknown check type: {check_type} (rule {rule['id']})")
            continue

        # Find resources matching this rule's type
        matching = {
            name: res for name, res in resources.items()
            if res.get("Type") == rule["resource_type"]
        }

        for resource_name, resource in matching.items():
            finding = check_fn(resource, resource_name, rule)
            findings.append(finding)

    return findings


# ═══════════════════════════════════════════════════════════════════════
# REPORT FORMATTERS
# ═══════════════════════════════════════════════════════════════════════

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
SEVERITY_ICONS = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}


def filter_findings(findings, min_severity):
    """Filter findings to only show at or above the minimum severity."""
    min_level = SEVERITY_ORDER.get(min_severity, 3)
    return [f for f in findings if SEVERITY_ORDER.get(f.severity, 3) <= min_level]


def format_text(findings, template_path):
    """Format findings as human-readable text."""
    lines = []
    lines.append("")
    lines.append("=" * 70)
    lines.append("  CLOUDFORMATION TEMPLATE VALIDATION REPORT")
    lines.append(f"  Template: {os.path.basename(template_path)}")
    lines.append(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("=" * 70)

    passed = [f for f in findings if f.status == "PASS"]
    failed = [f for f in findings if f.status == "FAIL"]

    lines.append(f"\n  Results: {len(passed)} passed, {len(failed)} failed out of {len(findings)} checks\n")

    # Group failures by resource
    if failed:
        lines.append("  ⚠️  FAILURES:")
        lines.append("  " + "─" * 55)

        # Sort by severity
        failed.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 99))

        for f in failed:
            icon = SEVERITY_ICONS.get(f.severity, "⚪")
            lines.append(f"  {icon} [{f.severity}] {f.rule_id}: {f.rule_name}")
            lines.append(f"     Resource: {f.resource_name} ({f.resource_type})")
            lines.append(f"     Finding:  {f.detail}")
            lines.append(f"     Standard: {f.standard}")
            lines.append("")

    # Pass summary
    if passed:
        lines.append("  ✅ PASSED CHECKS:")
        lines.append("  " + "─" * 55)
        for f in passed:
            lines.append(f"    [+] {f.rule_id}: {f.resource_name} — {f.rule_name}")

    lines.append("\n" + "=" * 70)
    return "\n".join(lines)


def format_json(findings, template_path):
    """Format findings as JSON."""
    output = {
        "template": os.path.basename(template_path),
        "generated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total": len(findings),
        "passed": len([f for f in findings if f.status == "PASS"]),
        "failed": len([f for f in findings if f.status == "FAIL"]),
        "findings": [f.to_dict() for f in findings],
    }
    return json.dumps(output, indent=2, ensure_ascii=False)


def format_markdown(findings, template_path):
    """Format findings as a Markdown report."""
    lines = []
    passed = [f for f in findings if f.status == "PASS"]
    failed = [f for f in findings if f.status == "FAIL"]

    lines.append("# CloudFormation Validation Report")
    lines.append("")
    lines.append(f"**Template:** `{os.path.basename(template_path)}`  ")
    lines.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  ")
    lines.append(f"**Result:** {len(passed)} passed, {len(failed)} failed  ")
    lines.append("")

    if failed:
        lines.append("## Failures")
        lines.append("")
        lines.append("| Severity | Rule | Resource | Finding | Standard |")
        lines.append("|----------|------|----------|---------|----------|")
        failed.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 99))
        for f in failed:
            icon = SEVERITY_ICONS.get(f.severity, "⚪")
            lines.append(f"| {icon} {f.severity} | {f.rule_id} | {f.resource_name} | {f.detail} | {f.standard} |")
        lines.append("")

    if passed:
        lines.append("## Passed")
        lines.append("")
        lines.append("| Rule | Resource | Detail |")
        lines.append("|------|----------|--------|")
        for f in passed:
            lines.append(f"| {f.rule_id} | {f.resource_name} | {f.detail} |")
        lines.append("")

    lines.append("---")
    lines.append("*Generated by cfn_validator.py (Lesson 11)*")
    return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    # Parse CLI arguments
    parser = build_parser()
    args = parser.parse_args()

    print(f"\n  🔍 CloudFormation Template Validator")
    print(f"  {'─' * 40}")

    # Load template
    print(f"  [INFO] Loading template: {args.template}")
    template = load_yaml(args.template)

    # Load rules
    print(f"  [INFO] Loading rules: {args.rules}")
    rules_data = load_yaml(args.rules)
    rules = rules_data.get("rules", [])
    print(f"  [INFO] Loaded {len(rules)} validation rules.")

    # Count resources
    resources = template.get("Resources", {})
    print(f"  [INFO] Template has {len(resources)} resources.\n")

    # Validate
    findings = validate_template(template, rules)

    # Filter by severity
    findings = filter_findings(findings, args.severity)

    # Format output
    formatters = {
        "text": format_text,
        "json": format_json,
        "markdown": format_markdown,
    }
    report = formatters[args.format](findings, args.template)

    # Print to console
    print(report)

    # Save to file if requested
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(report)
        print(f"\n  📄 Report saved to: {args.output}\n")
    else:
        # Auto-save JSON to script dir
        json_path = os.path.join(SCRIPT_DIR, "cfn_validation_report.json")
        json_report = format_json(findings, args.template)
        with open(json_path, "w", encoding="utf-8") as f:
            f.write(json_report)
        print(f"\n  📄 JSON report saved to: {json_path}\n")

    # Exit code based on failures
    failed = len([f for f in findings if f.status == "FAIL"])
    sys.exit(0 if failed == 0 else 1)
