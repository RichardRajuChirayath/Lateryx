#!/usr/bin/env python3
"""
Lateryx Auto-Remediation Engine
================================
Automatically generates fix suggestions and can create PRs with fixes applied.
This is the "Auto-Pilot" feature that removes friction from security fixes.
"""

import re
import json
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class RemediationPatch:
    """Represents a code patch to fix a security issue."""
    file_path: str
    original_content: str
    patched_content: str
    description: str
    confidence: float  # 0.0 to 1.0 - how confident we are in this fix


@dataclass
class RemediationSuggestion:
    """Complete remediation suggestion with multiple options."""
    finding_id: str
    severity: str
    description: str
    patches: List[RemediationPatch] = field(default_factory=list)
    manual_steps: List[str] = field(default_factory=list)
    documentation_links: List[str] = field(default_factory=list)


class AutoRemediator:
    """
    The Auto-Remediation Engine.
    Analyzes security findings and generates automatic fixes.
    """
    
    # Terraform patterns and their fixes
    REMEDIATION_PATTERNS = {
        # S3 Public Access
        "aws_s3_bucket_public_access": {
            "pattern": r'resource\s+"aws_s3_bucket"\s+"(\w+)"',
            "fix_template": '''
resource "aws_s3_bucket_public_access_block" "{bucket_name}_public_access_block" {{
  bucket = aws_s3_bucket.{bucket_name}.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}}
''',
            "description": "Add S3 public access block to prevent accidental public exposure",
            "confidence": 0.95
        },
        
        # RDS Public Access
        "aws_rds_public": {
            "pattern": r'publicly_accessible\s*=\s*true',
            "replacement": "publicly_accessible = false",
            "description": "Disable public accessibility for RDS instance",
            "confidence": 0.98
        },
        
        # Security Group 0.0.0.0/0
        "aws_security_group_open": {
            "pattern": r'cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0/0"\s*\]',
            "replacement": 'cidr_blocks = ["10.0.0.0/8"]  # TODO: Replace with your VPC CIDR',
            "description": "Restrict security group to VPC CIDR instead of open internet",
            "confidence": 0.7  # Lower confidence - needs manual review
        },
        
        # IAM Admin Policy
        "aws_iam_admin_policy": {
            "pattern": r'"arn:aws:iam::aws:policy/AdministratorAccess"',
            "replacement": '"arn:aws:iam::aws:policy/PowerUserAccess"  # TODO: Use least privilege',
            "description": "Replace AdministratorAccess with more restrictive policy",
            "confidence": 0.6
        },
        
        # Azure Storage Public Access
        "azure_storage_public": {
            "pattern": r'allow_blob_public_access\s*=\s*true',
            "replacement": "allow_blob_public_access = false",
            "description": "Disable public blob access for Azure Storage",
            "confidence": 0.95
        },
        
        # Azure SQL Public Access
        "azure_sql_public": {
            "pattern": r'public_network_access_enabled\s*=\s*true',
            "replacement": "public_network_access_enabled = false",
            "description": "Disable public network access for Azure SQL",
            "confidence": 0.95
        },
        
        # GCP Storage allUsers
        "gcp_storage_public": {
            "pattern": r'"allUsers"',
            "replacement": '"allAuthenticatedUsers"  # TODO: Replace with specific service account',
            "description": "Remove public access from GCP Storage bucket",
            "confidence": 0.85
        },
        
        # GCP SQL Public IP
        "gcp_sql_public": {
            "pattern": r'ipv4_enabled\s*=\s*true',
            "replacement": "ipv4_enabled = false  # Use private IP only",
            "description": "Disable public IP for Cloud SQL instance",
            "confidence": 0.9
        },
    }
    
    # Compliance-specific remediations
    COMPLIANCE_REMEDIATIONS = {
        "SOC2 CC6.1": [
            "Implement network segmentation",
            "Enable encryption at rest",
            "Configure access logging",
        ],
        "HIPAA §164.312": [
            "Enable audit logging",
            "Implement encryption in transit (TLS)",
            "Configure automatic session timeout",
        ],
        "PCI DSS Req 1": [
            "Implement firewall rules",
            "Document all network connections",
            "Regular firewall rule review",
        ],
        "GDPR Art. 32": [
            "Implement data encryption",
            "Enable access logging",
            "Document data processing activities",
        ],
    }
    
    def analyze_file(self, file_path: str, content: str) -> List[RemediationPatch]:
        """
        Analyze a Terraform file and generate remediation patches.
        """
        patches = []
        
        for pattern_name, pattern_config in self.REMEDIATION_PATTERNS.items():
            pattern = pattern_config["pattern"]
            matches = list(re.finditer(pattern, content, re.MULTILINE | re.IGNORECASE))
            
            if matches:
                patched_content = content
                
                if "replacement" in pattern_config:
                    # Simple replacement
                    patched_content = re.sub(
                        pattern, 
                        pattern_config["replacement"], 
                        content,
                        flags=re.MULTILINE | re.IGNORECASE
                    )
                elif "fix_template" in pattern_config:
                    # Template-based fix (append)
                    for match in matches:
                        if match.groups():
                            resource_name = match.group(1)
                            fix_code = pattern_config["fix_template"].format(
                                bucket_name=resource_name
                            )
                            # Append after the resource block
                            patched_content += "\n" + fix_code
                
                if patched_content != content:
                    patches.append(RemediationPatch(
                        file_path=file_path,
                        original_content=content,
                        patched_content=patched_content,
                        description=pattern_config["description"],
                        confidence=pattern_config["confidence"]
                    ))
        
        return patches
    
    def generate_fix_for_finding(self, finding: Dict, 
                                  terraform_dir: str) -> RemediationSuggestion:
        """
        Generate a complete remediation suggestion for a security finding.
        """
        suggestion = RemediationSuggestion(
            finding_id=finding.get("id", "unknown"),
            severity=finding.get("severity", "HIGH"),
            description=finding.get("description", "Security issue detected"),
            patches=[],
            manual_steps=[],
            documentation_links=[]
        )
        
        # Scan all .tf files in the directory
        tf_dir = Path(terraform_dir)
        if tf_dir.exists():
            for tf_file in tf_dir.glob("**/*.tf"):
                try:
                    content = tf_file.read_text()
                    patches = self.analyze_file(str(tf_file), content)
                    suggestion.patches.extend(patches)
                except Exception as e:
                    pass
        
        # Add compliance-specific manual steps
        compliance_violations = finding.get("compliance_violations", [])
        for violation in compliance_violations:
            for framework, steps in self.COMPLIANCE_REMEDIATIONS.items():
                if framework in violation:
                    suggestion.manual_steps.extend(steps)
        
        # Remove duplicates
        suggestion.manual_steps = list(set(suggestion.manual_steps))
        
        # Add documentation links
        if "S3" in finding.get("description", ""):
            suggestion.documentation_links.append(
                "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html"
            )
        if "RDS" in finding.get("description", ""):
            suggestion.documentation_links.append(
                "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_VPC.WorkingWithRDSInstanceinaVPC.html"
            )
        
        return suggestion
    
    def apply_patches(self, patches: List[RemediationPatch], 
                      dry_run: bool = True) -> Dict[str, str]:
        """
        Apply remediation patches to files.
        
        Args:
            patches: List of patches to apply
            dry_run: If True, don't actually write files
            
        Returns:
            Dict mapping file paths to their patched content
        """
        results = {}
        
        for patch in patches:
            if patch.confidence >= 0.8:  # Only auto-apply high-confidence fixes
                results[patch.file_path] = patch.patched_content
                
                if not dry_run:
                    Path(patch.file_path).write_text(patch.patched_content)
        
        return results
    
    def generate_pr_description(self, suggestions: List[RemediationSuggestion]) -> str:
        """
        Generate a GitHub PR description for auto-remediation.
        """
        md = "# 🛡️ Lateryx Auto-Remediation\n\n"
        md += "This PR was automatically generated by Lateryx to fix security issues.\n\n"
        md += "## 🔧 Changes Made\n\n"
        
        for suggestion in suggestions:
            md += f"### [{suggestion.severity}] {suggestion.description}\n\n"
            
            if suggestion.patches:
                md += "**Automatic Fixes Applied:**\n"
                for patch in suggestion.patches:
                    confidence_emoji = "✅" if patch.confidence >= 0.9 else "⚠️"
                    md += f"- {confidence_emoji} {patch.description} ({patch.file_path})\n"
                md += "\n"
            
            if suggestion.manual_steps:
                md += "**Manual Steps Recommended:**\n"
                for step in suggestion.manual_steps:
                    md += f"- [ ] {step}\n"
                md += "\n"
            
            if suggestion.documentation_links:
                md += "**Documentation:**\n"
                for link in suggestion.documentation_links:
                    md += f"- {link}\n"
                md += "\n"
            
            md += "---\n\n"
        
        md += "> ⚠️ Please review all changes carefully before merging.\n"
        md += "> Auto-generated by [Lateryx](https://github.com/RichardRajuChirayath/Lateryx)\n"
        
        return md


def get_auto_remediator() -> AutoRemediator:
    """Get a configured auto-remediator instance."""
    return AutoRemediator()
