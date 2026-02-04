#!/usr/bin/env python3
"""
Lateryx CLI - Local Security Scanner
=====================================
Run Lateryx from your terminal to scan infrastructure before pushing.

Usage:
    python -m lateryx scan ./infrastructure
    python -m lateryx scan ./infrastructure --format json
    python -m lateryx scan ./infrastructure --fail-on-breach
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Optional

# Rich console output (graceful fallback if not installed)
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.markdown import Markdown
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

from .scanner import TerraformScanner
from .main import LaterxyAnalyzer, InfrastructureGraph
from .intelligence import get_intelligence


def print_banner():
    """Print the Lateryx banner."""
    banner = """
    ╔═══════════════════════════════════════════════════════════╗
    ║  🛡️  LATERYX - Cloud Safety & Compliance on Autopilot    ║
    ║      Local Security Scanner                               ║
    ╚═══════════════════════════════════════════════════════════╝
    """
    print(banner)


def scan_directory(terraform_dir: str, output_format: str = "rich", 
                   fail_on_breach: bool = False, severity_threshold: str = "HIGH") -> int:
    """
    Scan a Terraform directory for security issues.
    
    Args:
        terraform_dir: Path to Terraform files
        output_format: Output format (rich, json, markdown)
        fail_on_breach: Exit with code 1 if breaches found
        severity_threshold: Minimum severity to fail on
        
    Returns:
        Exit code (0 = safe, 1 = breaches found)
    """
    print_banner()
    
    terraform_path = Path(terraform_dir)
    if not terraform_path.exists():
        print(f"❌ Error: Directory not found: {terraform_dir}")
        return 1
    
    print(f"📂 Scanning: {terraform_path.absolute()}")
    print("─" * 60)
    
    # Initialize scanner
    scanner = TerraformScanner()
    intel = get_intelligence()
    
    # Scan the directory
    try:
        graph = scanner.scan_directory(str(terraform_path))
    except Exception as e:
        print(f"❌ Scan failed: {e}")
        return 1
    
    # Get all attack paths in the current state
    attack_paths = graph.find_all_attack_paths()
    
    # Build results
    results = {
        "is_safe": len(attack_paths) == 0,
        "total_resources": graph.graph.number_of_nodes() - 2,  # Exclude Internet and ProtectedData
        "total_permissions": graph.graph.number_of_edges(),
        "attack_paths_count": len(attack_paths),
        "findings": []
    }
    
    # Analyze each path
    for path in attack_paths:
        # Find the sensitive resource
        sensitive_node = next(
            (n for n in path.path if graph.graph.nodes[n].get('contains_sensitive_data')), 
            path.path[-1]
        )
        res_type = graph.graph.nodes[sensitive_node].get('type', 'unknown')
        
        # Get business intelligence
        impact = intel.translate_breach("ATTACK_PATH", res_type, sensitive_node)
        
        results["findings"].append({
            "severity": "CRITICAL" if path.risk_score > 0.7 else "HIGH" if path.risk_score > 0.4 else "MEDIUM",
            "path": " → ".join(path.path),
            "risk_score": round(path.risk_score, 2),
            "impact": impact.impact_summary,
            "compliance": impact.compliance_violations,
            "legal_exposure": impact.legal_exposure,
            "remediation": impact.remediation_for_humans
        })
    
    # Output results
    if output_format == "json":
        print(json.dumps(results, indent=2))
    elif output_format == "markdown":
        print_markdown_report(results)
    else:
        print_rich_report(results)
    
    # Determine exit code
    if fail_on_breach and not results["is_safe"]:
        severity_order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        threshold_idx = severity_order.index(severity_threshold)
        
        for finding in results["findings"]:
            finding_idx = severity_order.index(finding["severity"])
            if finding_idx >= threshold_idx:
                print(f"\n❌ Failing due to {finding['severity']} severity finding (threshold: {severity_threshold})")
                return 1
    
    return 0 if results["is_safe"] else 0


def print_rich_report(results: dict):
    """Print a beautiful terminal report."""
    print()
    
    if results["is_safe"]:
        print("╔════════════════════════════════════════════════════════════╗")
        print("║  ✅ SAFE TO COMMIT                                         ║")
        print("║  No attack paths detected. Your infrastructure is secure.  ║")
        print("╚════════════════════════════════════════════════════════════╝")
    else:
        print("╔════════════════════════════════════════════════════════════╗")
        print("║  ⚠️  SECURITY ISSUES DETECTED                              ║")
        print("║  Review the findings below before committing.              ║")
        print("╚════════════════════════════════════════════════════════════╝")
    
    print()
    print(f"📊 Resources Scanned: {results['total_resources']}")
    print(f"🔗 Permissions Mapped: {results['total_permissions']}")
    print(f"🚨 Attack Paths Found: {results['attack_paths_count']}")
    print()
    
    if results["findings"]:
        print("─" * 60)
        print("🔍 FINDINGS:")
        print("─" * 60)
        
        for i, finding in enumerate(results["findings"], 1):
            severity_icon = "🔴" if finding["severity"] == "CRITICAL" else "🟠" if finding["severity"] == "HIGH" else "🟡"
            
            print(f"\n{severity_icon} [{finding['severity']}] Finding #{i}")
            print(f"   Path: {finding['path']}")
            print(f"   Risk Score: {finding['risk_score']}")
            print()
            print(f"   📢 Impact: {finding['impact']}")
            print()
            print(f"   📜 Compliance Violations:")
            for violation in finding["compliance"]:
                print(f"      - {violation}")
            print()
            print(f"   ⚖️  Legal: {finding['legal_exposure']}")
            print()
            print(f"   🛠️  How to Fix:")
            print(f"      {finding['remediation']}")
            print()
            print("─" * 60)
    
    print()
    print("💡 Run 'lateryx scan <dir> --format markdown' for a shareable report.")
    print()


def print_markdown_report(results: dict):
    """Print a Markdown report."""
    status = "✅ SAFE" if results["is_safe"] else "⚠️ ISSUES DETECTED"
    
    print(f"# 🛡️ Lateryx Local Scan Report")
    print()
    print(f"**Status:** {status}")
    print()
    print(f"| Metric | Value |")
    print(f"|--------|-------|")
    print(f"| Resources Scanned | {results['total_resources']} |")
    print(f"| Permissions Mapped | {results['total_permissions']} |")
    print(f"| Attack Paths | {results['attack_paths_count']} |")
    print()
    
    if results["findings"]:
        print("## 🚨 Findings")
        print()
        for i, finding in enumerate(results["findings"], 1):
            print(f"### [{finding['severity']}] Finding #{i}")
            print()
            print(f"**Path:** `{finding['path']}`")
            print()
            print(f"**Impact:** {finding['impact']}")
            print()
            print("**Compliance Violations:**")
            for v in finding["compliance"]:
                print(f"- {v}")
            print()
            print(f"**Legal Exposure:** {finding['legal_exposure']}")
            print()
            print(f"**🛠️ How to Fix:**")
            print(f"> {finding['remediation']}")
            print()
            print("---")
            print()


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="lateryx",
        description="Lateryx - Cloud Safety & Compliance on Autopilot",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  lateryx scan ./infrastructure
  lateryx scan ./terraform --format json
  lateryx scan . --fail-on-breach --severity HIGH
        """
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Scan a directory for security issues")
    scan_parser.add_argument(
        "directory",
        help="Path to Terraform/infrastructure directory"
    )
    scan_parser.add_argument(
        "--format", "-f",
        choices=["rich", "json", "markdown"],
        default="rich",
        help="Output format (default: rich)"
    )
    scan_parser.add_argument(
        "--fail-on-breach",
        action="store_true",
        help="Exit with code 1 if security issues are found"
    )
    scan_parser.add_argument(
        "--severity", "-s",
        choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
        default="HIGH",
        help="Minimum severity to fail on (default: HIGH)"
    )
    
    # Version command
    parser.add_argument(
        "--version", "-v",
        action="version",
        version="Lateryx 1.2.0"
    )
    
    args = parser.parse_args()
    
    if args.command == "scan":
        exit_code = scan_directory(
            args.directory,
            output_format=args.format,
            fail_on_breach=args.fail_on_breach,
            severity_threshold=args.severity
        )
        sys.exit(exit_code)
    else:
        parser.print_help()
        sys.exit(0)


if __name__ == "__main__":
    main()
