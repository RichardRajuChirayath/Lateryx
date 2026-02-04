#!/usr/bin/env python3
"""
Lateryx Intelligence Layer
==========================
Translates complex graph breaches into:
1. Plain English Human Impact
2. Specific Compliance Violations (SOC2, HIPAA, ISO27001)
3. Legal Risk Assessment
"""

from typing import Dict, List, Optional
from dataclasses import dataclass

@dataclass
class BusinessImpact:
    risk_level: str
    impact_summary: str
    compliance_violations: List[str]
    legal_exposure: str
    remediation_for_humans: str

class RiskIntelligence:
    """The brain that makes Lateryx understandable for non-security people."""

    COMPLIANCE_MAP = {
        "S3_PUBLIC": ["SOC2 CC6.1 (Access Control)", "HIPAA §164.312 (Technical Safeguards)"],
        "IAM_ADMIN": ["ISO 27001 A.9 (Access Control)", "PCI DSS Req 7"],
        "DATABASE_EXPOSED": ["GDPR Art. 32 (Security of Processing)", "SOC2 CC7.1 (System Operations)"],
        "OPEN_NETWORK": ["SOC2 CC6.6 (Network Security)", "PCI DSS Req 1"]
    }

    IMPACT_TEMPLATES = {
        "S3": "Your company files (S3) are now visible to anyone with a browser. This often leads to public data leaks.",
        "RDS": "Your primary database is now reachable from the open internet. This is a high-risk vector for ransomware.",
        "IAM": "A service has been given 'Admin' rights. If this service is hacked, the attacker controls your entire AWS account.",
        "NETWORK": "A firewall (Security Group) was opened too wide. It's like leaving the front door of your office unlocked."
    }

    REMEDIATION_TEMPLATES = {
        "S3": "Remove the `public-read` ACL or the wildcard `Principal: *` from your S3 bucket policy. Use CloudFront with OAI for public assets.",
        "RDS": "Change `publicly_accessible = true` to `false` in your Terraform. Ensure the DB is in a private subnet with no 0.0.0.0/0 ingress.",
        "IAM": "Apply the Principle of Least Privilege. Replace `AdministratorAccess` with specific actions (e.g., `s3:PutObject`) only for needed resources.",
        "NETWORK": "Tighten your Security Group rules. Replace `0.0.0.0/0` with your VPC CIDR or specific IP ranges using a bastion host or VPN."
    }

    def translate_breach(self, breach_type: str, resource_type: str, affected_resource: str) -> BusinessImpact:
        """Translates a technical breach into business-friendly risk language and remediation steps."""
        
        impact = self.IMPACT_TEMPLATES.get(resource_type.upper(), "Architectural shift detected that bypasses existing security guardrails.")
        violations = self.COMPLIANCE_MAP.get(f"{resource_type.upper()}_EXPOSED", ["Internal Security Policy Violation"])
        remediation = self.REMEDIATION_TEMPLATES.get(resource_type.upper(), f"Restrict access to '{affected_resource}' to the minimum required VPC or IAM scope.")
        
        # Determine Legal Exposure
        legal = "LOW"
        if "data" in affected_resource.lower() or resource_type.upper() in ["S3", "RDS"]:
            legal = "CRITICAL: Potential GDPR/CCPA notification requirement if breached."
        elif "admin" in affected_resource.lower():
            legal = "HIGH: Total infrastructure liability."

        return BusinessImpact(
            risk_level="CRITICAL" if "data" in affected_resource.lower() else "HIGH",
            impact_summary=impact,
            compliance_violations=violations,
            legal_exposure=legal,
            remediation_for_humans=remediation
        )

def get_intelligence():
    return RiskIntelligence()
