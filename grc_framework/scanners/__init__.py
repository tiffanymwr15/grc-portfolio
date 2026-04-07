"""
GRC Framework - AWS Scanner Module
===================================
AWS resource scanning and compliance checking.

Demonstrates:
  - boto3 integration patterns
  - Error handling for AWS API calls
  - Result aggregation
  - Reusable scanner base class
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict
from datetime import datetime, timezone


try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
    HAS_BOTO3 = True
except ImportError:
    HAS_BOTO3 = False


@dataclass
class Finding:
    """Represents a compliance finding."""
    resource_type: str
    resource_id: str
    finding_type: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    description: str
    control: str  # NIST/CIS control reference
    remediation: str
    timestamp: str = ""
    
    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)


class AWSScanner:
    """
    Base class for AWS resource scanners.
    
    Demonstrates:
      - Abstract base class pattern
      - Template method pattern
      - Context manager support
    """
    
    def __init__(self, profile: str = "default", region: str = "us-east-1"):
        self.profile = profile
        self.region = region
        self.session = None
        self.findings: List[Finding] = []
        
        if HAS_BOTO3:
            try:
                self.session = boto3.Session(profile_name=profile, region_name=region)
            except NoCredentialsError:
                self.session = None
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        return False
    
    def scan(self) -> List[Finding]:
        """
        Perform the scan. Override in subclasses.
        
        This is the Template Method pattern - defines the skeleton
        of an algorithm, letting subclasses override specific steps.
        """
        raise NotImplementedError("Subclasses must implement scan()")
    
    def add_finding(self, finding: Finding) -> None:
        """Add a finding to the results."""
        self.findings.append(finding)
    
    def get_findings_by_severity(self, severity: str) -> List[Finding]:
        """Filter findings by severity."""
        return [f for f in self.findings if f.severity == severity]


class S3Scanner(AWSScanner):
    """Scanner for S3 bucket compliance."""
    
    def scan(self) -> List[Finding]:
        """Scan S3 buckets for compliance issues."""
        self.findings = []
        
        if not HAS_BOTO3 or not self.session:
            # Mock mode for demonstration
            self._mock_scan()
            return self.findings
        
        try:
            s3 = self.session.client("s3")
            response = s3.list_buckets()
            
            for bucket in response.get("Buckets", []):
                bucket_name = bucket["Name"]
                self._check_bucket(s3, bucket_name)
                
        except ClientError as e:
            print(f"AWS API error: {e}")
        
        return self.findings
    
    def _check_bucket(self, s3_client, bucket_name: str) -> None:
        """Check a single bucket for compliance."""
        # Check encryption
        try:
            s3_client.get_bucket_encryption(Bucket=bucket_name)
        except ClientError:
            self.add_finding(Finding(
                resource_type="S3",
                resource_id=bucket_name,
                finding_type="Encryption Not Enabled",
                severity="HIGH",
                description=f"Bucket {bucket_name} does not have default encryption",
                control="SC-28",
                remediation="Enable S3 default encryption with KMS"
            ))
        
        # Check public access block
        try:
            public_access = s3_client.get_public_access_block(Bucket=bucket_name)
            config = public_access.get("PublicAccessBlockConfiguration", {})
            if not all(config.values()):
                self.add_finding(Finding(
                    resource_type="S3",
                    resource_id=bucket_name,
                    finding_type="Public Access Not Fully Blocked",
                    severity="CRITICAL",
                    description=f"Bucket {bucket_name} has partial public access configuration",
                    control="AC-3",
                    remediation="Enable all public access block settings"
                ))
        except ClientError:
            self.add_finding(Finding(
                resource_type="S3",
                resource_id=bucket_name,
                finding_type="Public Access Block Not Configured",
                severity="CRITICAL",
                description=f"Bucket {bucket_name} has no public access block",
                control="AC-3",
                remediation="Enable S3 Block Public Access"
            ))
    
    def _mock_scan(self) -> None:
        """Generate mock findings for demonstration."""
        self.add_finding(Finding(
            resource_type="S3",
            resource_id="company-data-prod",
            finding_type="Encryption Not Enabled",
            severity="HIGH",
            description="Production data bucket lacks encryption",
            control="SC-28",
            remediation="Enable S3 default encryption"
        ))


class IAMScanner(AWSScanner):
    """Scanner for IAM compliance."""
    
    def scan(self) -> List[Finding]:
        """Scan IAM for compliance issues."""
        self.findings = []
        
        if not HAS_BOTO3 or not self.session:
            self._mock_scan()
            return self.findings
        
        try:
            iam = self.session.client("iam")
            self._check_users(iam)
            self._check_password_policy(iam)
        except ClientError as e:
            print(f"AWS API error: {e}")
        
        return self.findings
    
    def _check_users(self, iam) -> None:
        """Check IAM users for compliance."""
        users = iam.list_users()
        
        for user in users.get("Users", []):
            username = user["UserName"]
            
            # Check MFA
            mfa_devices = iam.list_mfa_devices(UserName=username)
            if not mfa_devices.get("MFADevices"):
                self.add_finding(Finding(
                    resource_type="IAM",
                    resource_id=username,
                    finding_type="MFA Not Enabled",
                    severity="HIGH",
                    description=f"User {username} does not have MFA enabled",
                    control="IA-2",
                    remediation="Enable virtual or hardware MFA"
                ))
            
            # Check access key age
            access_keys = iam.list_access_keys(UserName=username)
            for key in access_keys.get("AccessKeyMetadata", []):
                key_age = (datetime.now(timezone.utc) - key["CreateDate"]).days
                if key_age > 90:
                    self.add_finding(Finding(
                        resource_type="IAM",
                        resource_id=f"{username}/{key['AccessKeyId'][-4:]}",
                        finding_type="Access Key Too Old",
                        severity="MEDIUM",
                        description=f"Access key is {key_age} days old",
                        control="IA-5",
                        remediation="Rotate access keys every 90 days"
                    ))
    
    def _check_password_policy(self, iam) -> None:
        """Check account password policy."""
        try:
            policy = iam.get_account_password_policy()
            p = policy.get("PasswordPolicy", {})
            
            if p.get("MinimumPasswordLength", 0) < 12:
                self.add_finding(Finding(
                    resource_type="IAM",
                    resource_id="account",
                    finding_type="Weak Password Policy",
                    severity="MEDIUM",
                    description=f"Minimum password length is {p.get('MinimumPasswordLength')}",
                    control="IA-5",
                    remediation="Set minimum password length to 12+"
                ))
        except ClientError:
            self.add_finding(Finding(
                resource_type="IAM",
                resource_id="account",
                finding_type="No Password Policy",
                severity="HIGH",
                description="Account has no custom password policy",
                control="IA-5",
                remediation="Configure IAM password policy"
            ))
    
    def _mock_scan(self) -> None:
        """Generate mock findings."""
        self.add_finding(Finding(
            resource_type="IAM",
            resource_id="admin-user",
            finding_type="MFA Not Enabled",
            severity="HIGH",
            description="Admin user lacks MFA",
            control="IA-2",
            remediation="Enable MFA for admin user"
        ))


def run_compliance_scan(profile: str = "default", services: List[str] = None) -> Dict[str, Any]:
    """
    Run a complete compliance scan across multiple services.
    
    Returns aggregated results from all scanners.
    """
    services = services or ["s3", "iam"]
    all_findings = []
    
    scanners = {
        "s3": S3Scanner,
        "iam": IAMScanner,
    }
    
    for service in services:
        if service in scanners:
            with scanners[service](profile) as scanner:
                findings = scanner.scan()
                all_findings.extend(findings)
    
    # Calculate summary
    by_severity = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in all_findings:
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
    
    return {
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "profile": profile,
        "services_scanned": services,
        "total_findings": len(all_findings),
        "by_severity": by_severity,
        "findings": [f.to_dict() for f in all_findings]
    }
