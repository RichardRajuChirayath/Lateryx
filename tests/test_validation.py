#!/usr/bin/env python3
"""
Lateryx Validation Test
=======================
Proves that Lateryx can distinguish between safe and hacked infrastructure.
"""

import json
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.main import (
    InfrastructureGraph,
    LaterxyAnalyzer,
    RiskLevel,
)


def create_safe_graph() -> InfrastructureGraph:
    """Create a graph representing the SAFE infrastructure."""
    graph = InfrastructureGraph(name="safe-infrastructure")
    
    # Private VPC components (not connected to Internet)
    graph.add_resource("vpc.main", "vpc", is_public=False)
    graph.add_resource("subnet.private", "subnet", is_public=False)
    
    # Security group with restrictive rules
    graph.add_resource("sg.db_sg", "security_group", 
                       properties={"allows_internal_only": True})
    
    # IAM role with conditions
    graph.add_resource("iam.app_role", "iam_role",
                       properties={"has_conditions": True})
    
    # Private S3 bucket with encryption
    graph.add_resource("s3.data_bucket", "s3",
                       is_public=False, 
                       contains_sensitive_data=True)
    
    # Private RDS with encryption
    graph.add_resource("rds.main", "rds",
                       is_public=False,
                       contains_sensitive_data=True)
    
    # KMS key
    graph.add_resource("kms.data_key", "kms")
    
    # Permissions: Internal connections only
    graph.add_permission("subnet.private", "rds.main", "network_access",
                         conditions={"vpc_only": True})
    graph.add_permission("iam.app_role", "s3.data_bucket", "read",
                         conditions={"vpc_endpoint": True})
    graph.add_permission("kms.data_key", "s3.data_bucket", "encrypt")
    graph.add_permission("kms.data_key", "rds.main", "encrypt")
    
    # NO path from Internet to ProtectedData!
    
    return graph


def create_hacked_graph() -> InfrastructureGraph:
    """Create a graph representing the HACKED infrastructure."""
    graph = InfrastructureGraph(name="hacked-infrastructure")
    
    # Public VPC components
    graph.add_resource("vpc.main", "vpc", is_public=False)
    graph.add_resource("subnet.public", "subnet", 
                       is_public=True,  # Public subnet!
                       properties={"map_public_ip": True})
    
    # Internet Gateway (path to Internet)
    graph.add_resource("igw.main", "internet_gateway", is_public=True)
    
    # VULNERABLE: Open security group
    graph.add_resource("sg.open_sg", "security_group",
                       is_public=True,
                       properties={"allows_0.0.0.0/0": True})
    
    # VULNERABLE: Admin IAM role with wildcard
    graph.add_resource("iam.admin_role", "iam_role",
                       properties={"wildcard_principal": True})
    
    # VULNERABLE: Public S3 bucket
    graph.add_resource("s3.public_data", "s3",
                       is_public=True,  # PUBLIC!
                       contains_sensitive_data=True)
    
    # VULNERABLE: Public RDS
    graph.add_resource("rds.public_db", "rds",
                       is_public=True,  # PUBLIC!
                       contains_sensitive_data=True)
    
    # VULNERABLE: Public Lambda with admin role
    graph.add_resource("lambda.public_api", "lambda",
                       is_public=True)
    
    # VULNERABLE: Public API Gateway
    graph.add_resource("apigw.public_api", "api_gateway",
                       is_public=True)
    
    # Attack path 1: Internet -> S3 -> ProtectedData
    # (Already connected via is_public=True and contains_sensitive_data=True)
    
    # Attack path 2: Internet -> API Gateway -> Lambda -> IAM -> RDS
    graph.add_permission("apigw.public_api", "lambda.public_api", "invoke")
    graph.add_permission("lambda.public_api", "iam.admin_role", "assume_role")
    graph.add_permission("iam.admin_role", "rds.public_db", "admin")
    
    # Attack path 3: Internet -> Open SG -> RDS
    graph.add_permission("sg.open_sg", "rds.public_db", "network_access")
    
    return graph


def test_safe_infrastructure():
    """Test that safe infrastructure is correctly identified."""
    print("=" * 60)
    print("TEST 1: Safe Infrastructure Analysis")
    print("=" * 60)
    
    # Create before (empty) and after (safe) graphs
    before = InfrastructureGraph(name="baseline")
    after = create_safe_graph()
    
    # Run analysis
    analyzer = LaterxyAnalyzer()
    result = analyzer.analyze(before, after)
    
    print(f"\n{result.summary}")
    print(f"\nAttack paths found: {result.after_paths_count}")
    print(f"Breaches detected: {len(result.breaches)}")
    
    # Safe infrastructure should have NO paths to ProtectedData
    if result.after_paths_count == 0:
        print("\n[PASS] No attack paths to protected data")
        return True
    else:
        print(f"\n[FAIL] Found {result.after_paths_count} attack paths")
        return False


def test_hacked_infrastructure():
    """Test that hacked infrastructure is correctly flagged."""
    print("\n" + "=" * 60)
    print("TEST 2: Hacked Infrastructure Analysis")
    print("=" * 60)
    
    # Create before (safe) and after (hacked) graphs
    before = create_safe_graph()
    after = create_hacked_graph()
    
    # Run analysis
    analyzer = LaterxyAnalyzer()
    result = analyzer.analyze(before, after)
    
    print(f"\n{result.summary}")
    print(f"\nBefore paths: {result.before_paths_count}")
    print(f"After paths: {result.after_paths_count}")
    print(f"New paths: {result.new_paths_count}")
    print(f"Breaches: {len(result.breaches)}")
    
    # Hacked infrastructure should have breaches
    if not result.is_safe and len(result.breaches) > 0:
        print("\n[PASS] Causality breaches correctly detected!")
        
        # Print breach details
        print("\nDetected Breaches:")
        for i, breach in enumerate(result.breaches, 1):
            print(f"\n  [{i}] {breach.severity.value}: {breach.breach_type}")
            print(f"      Path: {' -> '.join(breach.after_path.path)}")
            print(f"      {breach.description}")
        
        return True
    else:
        print("\n[FAIL] Should have detected breaches!")
        return False


def test_comparison():
    """Compare safe vs hacked to prove differentiation."""
    print("\n" + "=" * 60)
    print("TEST 3: Safe -> Hacked Transition")
    print("=" * 60)
    
    before = create_safe_graph()
    after = create_hacked_graph()
    
    analyzer = LaterxyAnalyzer()
    result = analyzer.analyze(before, after)
    
    # Check for HIGH or CRITICAL severity
    high_severity = [b for b in result.breaches 
                     if b.severity in (RiskLevel.HIGH, RiskLevel.CRITICAL)]
    
    print(f"\nTotal breaches: {len(result.breaches)}")
    print(f"High/Critical: {len(high_severity)}")
    
    if len(high_severity) > 0:
        print("\n[PASS] High severity breaches detected!")
        return True
    else:
        print("\n[FAIL] Should detect high severity breaches")
        return False


def main():
    """Run all validation tests."""
    print("\n" + "=" * 60)
    print("  LATERYX SECURITY ENGINE - VALIDATION SUITE  ")
    print("=" * 60)
    
    results = []
    
    # Run tests
    results.append(("Safe Infrastructure", test_safe_infrastructure()))
    results.append(("Hacked Infrastructure", test_hacked_infrastructure()))
    results.append(("Safe-to-Hacked Transition", test_comparison()))
    
    # Summary
    print("\n" + "=" * 60)
    print("VALIDATION SUMMARY")
    print("=" * 60)
    
    passed = sum(1 for _, r in results if r)
    total = len(results)
    
    for name, result in results:
        status = "[PASS]" if result else "[FAIL]"
        print(f"  {status}: {name}")
    
    print(f"\nTotal: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n*** ALL VALIDATIONS PASSED! ***")
        print("Lateryx can correctly distinguish safe from hacked infrastructure.")
        return 0
    else:
        print("\n*** SOME VALIDATIONS FAILED ***")
        return 1


if __name__ == "__main__":
    exit(main())
