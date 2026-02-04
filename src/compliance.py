#!/usr/bin/env python3
"""
Lateryx Compliance Frameworks
==============================
Extended compliance mapping for enterprise requirements.
Covers: SOC2, HIPAA, ISO27001, PCI DSS, NIST 800-53, CIS Benchmarks, FedRAMP.
"""

from typing import Dict, List, Set
from dataclasses import dataclass


@dataclass
class ComplianceControl:
    """Represents a compliance control/requirement."""
    framework: str
    control_id: str
    title: str
    description: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW


@dataclass
class ComplianceMapping:
    """Maps a security finding to compliance controls."""
    finding_type: str
    controls: List[ComplianceControl]


class ComplianceFrameworks:
    """
    Comprehensive compliance framework mappings.
    Maps security issues to specific compliance control violations.
    """
    
    # SOC 2 Trust Service Criteria
    SOC2_CONTROLS = {
        "CC6.1": ComplianceControl(
            framework="SOC2",
            control_id="CC6.1",
            title="Access Control",
            description="The entity implements logical access security measures to protect against unauthorized access.",
            severity="HIGH"
        ),
        "CC6.6": ComplianceControl(
            framework="SOC2",
            control_id="CC6.6",
            title="Network Security",
            description="The entity implements network security measures to protect against unauthorized access.",
            severity="HIGH"
        ),
        "CC6.7": ComplianceControl(
            framework="SOC2",
            control_id="CC6.7",
            title="Encryption",
            description="The entity restricts the transmission, movement, and removal of information.",
            severity="MEDIUM"
        ),
        "CC7.1": ComplianceControl(
            framework="SOC2",
            control_id="CC7.1",
            title="System Operations",
            description="The entity detects and monitors security events.",
            severity="MEDIUM"
        ),
        "CC7.2": ComplianceControl(
            framework="SOC2",
            control_id="CC7.2",
            title="Incident Response",
            description="The entity monitors and evaluates security events.",
            severity="HIGH"
        ),
    }
    
    # HIPAA Security Rule
    HIPAA_CONTROLS = {
        "164.312(a)(1)": ComplianceControl(
            framework="HIPAA",
            control_id="§164.312(a)(1)",
            title="Access Control",
            description="Implement technical policies and procedures for electronic information systems.",
            severity="CRITICAL"
        ),
        "164.312(b)": ComplianceControl(
            framework="HIPAA",
            control_id="§164.312(b)",
            title="Audit Controls",
            description="Implement hardware, software, and procedural mechanisms to record access.",
            severity="HIGH"
        ),
        "164.312(c)(1)": ComplianceControl(
            framework="HIPAA",
            control_id="§164.312(c)(1)",
            title="Integrity",
            description="Implement policies to protect ePHI from improper alteration or destruction.",
            severity="HIGH"
        ),
        "164.312(d)": ComplianceControl(
            framework="HIPAA",
            control_id="§164.312(d)",
            title="Person/Entity Authentication",
            description="Implement procedures to verify identity of persons seeking access.",
            severity="HIGH"
        ),
        "164.312(e)(1)": ComplianceControl(
            framework="HIPAA",
            control_id="§164.312(e)(1)",
            title="Transmission Security",
            description="Implement measures to guard against unauthorized access during transmission.",
            severity="CRITICAL"
        ),
    }
    
    # PCI DSS v4.0
    PCI_DSS_CONTROLS = {
        "1.3.1": ComplianceControl(
            framework="PCI-DSS",
            control_id="Req 1.3.1",
            title="Firewall Configuration",
            description="Restrict inbound traffic to only necessary services and ports.",
            severity="HIGH"
        ),
        "1.3.2": ComplianceControl(
            framework="PCI-DSS",
            control_id="Req 1.3.2",
            title="DMZ Implementation",
            description="Limit inbound traffic to IP addresses within the DMZ.",
            severity="HIGH"
        ),
        "2.2.1": ComplianceControl(
            framework="PCI-DSS",
            control_id="Req 2.2.1",
            title="System Hardening",
            description="Implement only one primary function per server.",
            severity="MEDIUM"
        ),
        "3.4": ComplianceControl(
            framework="PCI-DSS",
            control_id="Req 3.4",
            title="PAN Protection",
            description="Render PAN unreadable using strong cryptography.",
            severity="CRITICAL"
        ),
        "7.1": ComplianceControl(
            framework="PCI-DSS",
            control_id="Req 7.1",
            title="Access Limitation",
            description="Limit access to system components to only those required.",
            severity="HIGH"
        ),
        "8.3": ComplianceControl(
            framework="PCI-DSS",
            control_id="Req 8.3",
            title="Strong Authentication",
            description="Secure all individual administrative access with MFA.",
            severity="HIGH"
        ),
        "10.1": ComplianceControl(
            framework="PCI-DSS",
            control_id="Req 10.1",
            title="Audit Trail",
            description="Implement audit trails to link access to individual users.",
            severity="HIGH"
        ),
    }
    
    # NIST 800-53 Rev 5
    NIST_CONTROLS = {
        "AC-2": ComplianceControl(
            framework="NIST 800-53",
            control_id="AC-2",
            title="Account Management",
            description="Manage system accounts including creation, enabling, modification, and removal.",
            severity="HIGH"
        ),
        "AC-3": ComplianceControl(
            framework="NIST 800-53",
            control_id="AC-3",
            title="Access Enforcement",
            description="Enforce approved authorizations for logical access.",
            severity="HIGH"
        ),
        "AC-4": ComplianceControl(
            framework="NIST 800-53",
            control_id="AC-4",
            title="Information Flow Enforcement",
            description="Enforce approved authorizations for information flow.",
            severity="HIGH"
        ),
        "AC-6": ComplianceControl(
            framework="NIST 800-53",
            control_id="AC-6",
            title="Least Privilege",
            description="Employ the principle of least privilege.",
            severity="HIGH"
        ),
        "AU-2": ComplianceControl(
            framework="NIST 800-53",
            control_id="AU-2",
            title="Event Logging",
            description="Identify events that require logging.",
            severity="MEDIUM"
        ),
        "CA-7": ComplianceControl(
            framework="NIST 800-53",
            control_id="CA-7",
            title="Continuous Monitoring",
            description="Develop a continuous monitoring strategy.",
            severity="MEDIUM"
        ),
        "CM-7": ComplianceControl(
            framework="NIST 800-53",
            control_id="CM-7",
            title="Least Functionality",
            description="Configure systems to provide only essential capabilities.",
            severity="MEDIUM"
        ),
        "IA-2": ComplianceControl(
            framework="NIST 800-53",
            control_id="IA-2",
            title="Identification and Authentication",
            description="Uniquely identify and authenticate organizational users.",
            severity="HIGH"
        ),
        "SC-7": ComplianceControl(
            framework="NIST 800-53",
            control_id="SC-7",
            title="Boundary Protection",
            description="Monitor and control communications at system boundaries.",
            severity="HIGH"
        ),
        "SC-8": ComplianceControl(
            framework="NIST 800-53",
            control_id="SC-8",
            title="Transmission Confidentiality",
            description="Protect the confidentiality of transmitted information.",
            severity="HIGH"
        ),
    }
    
    # CIS Benchmarks (AWS-focused)
    CIS_CONTROLS = {
        "1.4": ComplianceControl(
            framework="CIS AWS",
            control_id="1.4",
            title="Root Account MFA",
            description="Ensure MFA is enabled for the root account.",
            severity="CRITICAL"
        ),
        "1.16": ComplianceControl(
            framework="CIS AWS",
            control_id="1.16",
            title="IAM Policies",
            description="Ensure IAM policies are attached only to groups or roles.",
            severity="MEDIUM"
        ),
        "2.1.1": ComplianceControl(
            framework="CIS AWS",
            control_id="2.1.1",
            title="S3 Public Access",
            description="Ensure S3 Bucket Policy does not have public access.",
            severity="HIGH"
        ),
        "2.1.2": ComplianceControl(
            framework="CIS AWS",
            control_id="2.1.2",
            title="S3 Encryption",
            description="Ensure S3 Bucket has server-side encryption enabled.",
            severity="MEDIUM"
        ),
        "2.3.1": ComplianceControl(
            framework="CIS AWS",
            control_id="2.3.1",
            title="RDS Encryption",
            description="Ensure RDS instances have encryption enabled.",
            severity="HIGH"
        ),
        "4.1": ComplianceControl(
            framework="CIS AWS",
            control_id="4.1",
            title="Security Groups",
            description="Ensure no security groups allow ingress from 0.0.0.0/0.",
            severity="HIGH"
        ),
        "5.1": ComplianceControl(
            framework="CIS AWS",
            control_id="5.1",
            title="VPC Flow Logs",
            description="Ensure VPC Flow Logs are enabled in all VPCs.",
            severity="MEDIUM"
        ),
    }
    
    # GDPR
    GDPR_CONTROLS = {
        "Art.25": ComplianceControl(
            framework="GDPR",
            control_id="Art. 25",
            title="Data Protection by Design",
            description="Implement appropriate technical measures to ensure data protection.",
            severity="HIGH"
        ),
        "Art.32": ComplianceControl(
            framework="GDPR",
            control_id="Art. 32",
            title="Security of Processing",
            description="Implement measures to ensure a level of security appropriate to the risk.",
            severity="HIGH"
        ),
        "Art.33": ComplianceControl(
            framework="GDPR",
            control_id="Art. 33",
            title="Breach Notification",
            description="Notify supervisory authority within 72 hours of awareness of breach.",
            severity="CRITICAL"
        ),
    }
    
    # Mapping: Security Issue Type -> Applicable Controls
    ISSUE_MAPPINGS = {
        "PUBLIC_S3": [
            "SOC2.CC6.1", "HIPAA.164.312(a)(1)", "PCI-DSS.2.1.1", 
            "NIST.AC-3", "CIS.2.1.1", "GDPR.Art.32"
        ],
        "PUBLIC_DATABASE": [
            "SOC2.CC6.1", "SOC2.CC6.6", "HIPAA.164.312(a)(1)", 
            "PCI-DSS.1.3.1", "NIST.SC-7", "CIS.2.3.1", "GDPR.Art.32"
        ],
        "ADMIN_ACCESS": [
            "SOC2.CC6.1", "HIPAA.164.312(d)", "PCI-DSS.7.1",
            "NIST.AC-6", "CIS.1.16"
        ],
        "OPEN_SECURITY_GROUP": [
            "SOC2.CC6.6", "PCI-DSS.1.3.1", "NIST.SC-7", "CIS.4.1"
        ],
        "MISSING_ENCRYPTION": [
            "SOC2.CC6.7", "HIPAA.164.312(e)(1)", "PCI-DSS.3.4",
            "NIST.SC-8", "CIS.2.1.2", "GDPR.Art.32"
        ],
        "MISSING_LOGGING": [
            "SOC2.CC7.1", "HIPAA.164.312(b)", "PCI-DSS.10.1",
            "NIST.AU-2", "CIS.5.1"
        ],
        "MISSING_MFA": [
            "HIPAA.164.312(d)", "PCI-DSS.8.3", "NIST.IA-2", "CIS.1.4"
        ],
    }
    
    def get_controls_for_issue(self, issue_type: str) -> List[ComplianceControl]:
        """
        Get all applicable compliance controls for a security issue type.
        """
        controls = []
        control_refs = self.ISSUE_MAPPINGS.get(issue_type, [])
        
        for ref in control_refs:
            framework, control_id = ref.split(".", 1)
            
            if framework == "SOC2":
                control = self.SOC2_CONTROLS.get(control_id)
            elif framework == "HIPAA":
                control = self.HIPAA_CONTROLS.get(control_id)
            elif framework == "PCI-DSS":
                control = self.PCI_DSS_CONTROLS.get(control_id)
            elif framework == "NIST":
                control = self.NIST_CONTROLS.get(control_id)
            elif framework == "CIS":
                control = self.CIS_CONTROLS.get(control_id)
            elif framework == "GDPR":
                control = self.GDPR_CONTROLS.get(control_id)
            else:
                control = None
            
            if control:
                controls.append(control)
        
        return controls
    
    def detect_issue_type(self, resource_type: str, finding_description: str) -> str:
        """
        Detect the issue type from resource and description.
        """
        desc_lower = finding_description.lower()
        
        if "s3" in desc_lower and "public" in desc_lower:
            return "PUBLIC_S3"
        if "database" in desc_lower or "rds" in desc_lower or "sql" in desc_lower:
            if "public" in desc_lower:
                return "PUBLIC_DATABASE"
        if "admin" in desc_lower or "administrator" in desc_lower:
            return "ADMIN_ACCESS"
        if "security group" in desc_lower or "0.0.0.0" in desc_lower:
            return "OPEN_SECURITY_GROUP"
        if "encrypt" in desc_lower:
            return "MISSING_ENCRYPTION"
        if "log" in desc_lower or "audit" in desc_lower:
            return "MISSING_LOGGING"
        if "mfa" in desc_lower or "multi-factor" in desc_lower:
            return "MISSING_MFA"
        
        return "GENERAL"
    
    def get_full_compliance_report(self, findings: List[Dict]) -> Dict:
        """
        Generate a full compliance report for all findings.
        """
        report = {
            "frameworks_affected": set(),
            "controls_violated": [],
            "by_framework": {},
            "by_severity": {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": []},
            "summary": ""
        }
        
        for finding in findings:
            issue_type = self.detect_issue_type(
                finding.get("resource_type", ""),
                finding.get("description", "")
            )
            controls = self.get_controls_for_issue(issue_type)
            
            for control in controls:
                report["frameworks_affected"].add(control.framework)
                report["controls_violated"].append({
                    "finding": finding.get("description", ""),
                    "control": control
                })
                
                if control.framework not in report["by_framework"]:
                    report["by_framework"][control.framework] = []
                report["by_framework"][control.framework].append(control)
                
                report["by_severity"][control.severity].append(control)
        
        report["frameworks_affected"] = list(report["frameworks_affected"])
        
        # Generate summary
        critical_count = len(report["by_severity"]["CRITICAL"])
        high_count = len(report["by_severity"]["HIGH"])
        
        if critical_count > 0:
            report["summary"] = f"⚠️ CRITICAL: {critical_count} critical compliance violations detected"
        elif high_count > 0:
            report["summary"] = f"⚠️ HIGH: {high_count} high-severity compliance violations detected"
        else:
            report["summary"] = "✅ No critical or high-severity compliance violations detected"
        
        return report


def get_compliance_frameworks() -> ComplianceFrameworks:
    """Get a configured compliance frameworks instance."""
    return ComplianceFrameworks()
