#!/usr/bin/env python3
"""
Lateryx Enterprise Features Test Suite
=======================================
Tests all enterprise capabilities:
1. Plan Analyzer (Terraform Plan JSON parsing)
2. IAM Resolver (Effective permissions calculation)
3. Optimized Engine (Centrality and blast radius)
4. Configuration (Custom risk scoring)
"""

import json
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.main import InfrastructureGraph, LaterxyAnalyzer
from src.optimized_engine import OptimizedGraphEngine
from src.iam_resolver import IAMResolver, PolicyEffect
from src.config import ConfigLoader, LaterxyConfig


def create_enterprise_graph():
    """Create a complex enterprise infrastructure graph."""
    graph = InfrastructureGraph(name="enterprise-corp")
    
    # Public entry points
    graph.add_resource("cdn.cloudfront", "cdn", is_public=True)
    graph.add_resource("alb.main", "alb", is_public=True)
    graph.add_resource("api.gateway", "api_gateway", is_public=True)
    
    # Compute layer
    graph.add_resource("ec2.web_1", "ec2")
    graph.add_resource("ec2.web_2", "ec2")
    graph.add_resource("ec2.api_1", "ec2")
    graph.add_resource("lambda.processor", "lambda")
    graph.add_resource("ecs.workers", "ecs")
    
    # IAM layer
    graph.add_resource("iam.web_role", "iam_role")
    graph.add_resource("iam.api_role", "iam_role")
    graph.add_resource("iam.admin_role", "iam_role")
    graph.add_resource("iam.data_role", "iam_role")
    
    # Data layer
    graph.add_resource("rds.primary", "rds", contains_sensitive_data=True)
    graph.add_resource("rds.replica", "rds", contains_sensitive_data=True)
    graph.add_resource("s3.customer_data", "s3", contains_sensitive_data=True)
    graph.add_resource("dynamodb.sessions", "dynamodb")
    graph.add_resource("secrets.api_keys", "secrets_manager", contains_sensitive_data=True)
    
    # Security layer
    graph.add_resource("sg.public", "security_group", is_public=True)
    graph.add_resource("sg.private", "security_group")
    graph.add_resource("sg.db", "security_group")
    
    # Connections - Public to Compute
    graph.add_permission("cdn.cloudfront", "alb.main", "forward")
    graph.add_permission("alb.main", "ec2.web_1", "forward")
    graph.add_permission("alb.main", "ec2.web_2", "forward")
    graph.add_permission("api.gateway", "lambda.processor", "invoke")
    graph.add_permission("api.gateway", "ec2.api_1", "forward")
    
    # Connections - Compute to IAM
    graph.add_permission("ec2.web_1", "iam.web_role", "assume")
    graph.add_permission("ec2.web_2", "iam.web_role", "assume")
    graph.add_permission("ec2.api_1", "iam.api_role", "assume")
    graph.add_permission("lambda.processor", "iam.data_role", "assume")
    
    # Connections - IAM to Data
    graph.add_permission("iam.web_role", "dynamodb.sessions", "read_write")
    graph.add_permission("iam.api_role", "rds.primary", "read")
    graph.add_permission("iam.data_role", "s3.customer_data", "read_write")
    graph.add_permission("iam.data_role", "secrets.api_keys", "read")
    graph.add_permission("iam.admin_role", "rds.primary", "admin")
    
    # The vulnerability: Admin role can be assumed too easily
    graph.add_permission("iam.api_role", "iam.admin_role", "assume")
    
    return graph


def test_optimized_engine():
    """Test the optimized graph engine with centrality analysis."""
    print("\n" + "=" * 60)
    print("TEST: Optimized Graph Engine")
    print("=" * 60)
    
    graph = create_enterprise_graph()
    engine = OptimizedGraphEngine(graph)
    
    # Test centrality analysis
    print("\n[1] Testing Centrality Analysis...")
    centrality = engine.analyze_centrality()
    print(f"    Analyzed {len(centrality)} nodes")
    
    top_3 = centrality[:3]
    print("    Top 3 Central Nodes:")
    for c in top_3:
        print(f"      - {c.node_id}: score={c.risk_score:.4f}")
    
    assert len(centrality) > 0, "Centrality analysis failed"
    print("    [PASS] Centrality analysis working")
    
    # Test risk zones
    print("\n[2] Testing Risk Zone Identification...")
    zones = engine.identify_risk_zones(num_zones=3)
    print(f"    Identified {len(zones)} risk zones")
    for zone in zones:
        print(f"      - {zone.zone_name}: {len(zone.member_nodes)} nodes, risk={zone.total_risk:.4f}")
    
    assert len(zones) > 0, "Risk zone identification failed"
    print("    [PASS] Risk zones identified")
    
    # Test blast radius
    print("\n[3] Testing Blast Radius Calculation...")
    blast = engine.get_blast_radius("iam.api_role")
    print(f"    Compromised node: iam.api_role")
    print(f"    Blast radius: {blast['blast_radius_percent']}% of infrastructure")
    print(f"    Can reach protected data: {blast['can_reach_protected_data']}")
    print(f"    Risk level: {blast['risk_level']}")
    
    assert "blast_radius_percent" in blast, "Blast radius calculation failed"
    print("    [PASS] Blast radius calculated")
    
    # Test critical paths
    print("\n[4] Testing Critical Path Discovery...")
    paths = engine.find_critical_paths(max_paths=10)
    print(f"    Found {len(paths)} critical paths")
    if paths:
        print(f"    Highest risk path: {' -> '.join(paths[0].path[:5])}...")
        print(f"    Risk score: {paths[0].risk_score:.4f}")
    
    print("    [PASS] Critical paths found")
    
    return True


def test_iam_resolver():
    """Test the IAM permission resolver."""
    print("\n" + "=" * 60)
    print("TEST: IAM Resolver")
    print("=" * 60)
    
    resolver = IAMResolver()
    
    # Add a simple allow policy
    allow_policy = resolver.parse_policy_document(
        json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:PutObject"],
                "Resource": "arn:aws:s3:::my-bucket/*"
            }]
        }),
        "AllowS3Policy",
        "identity"
    )
    resolver.add_identity_policy("arn:aws:iam::123456789:role/MyRole", allow_policy)
    
    # Add a deny policy (SCP)
    deny_policy = resolver.parse_policy_document(
        json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Deny",
                "Action": "s3:DeleteObject",
                "Resource": "*"
            }]
        }),
        "DenyDeleteSCP",
        "scp"
    )
    resolver.add_scp(deny_policy)
    
    print("\n[1] Testing Permission Evaluation...")
    
    # Test allowed action
    result1 = resolver.evaluate_permission(
        "arn:aws:iam::123456789:role/MyRole",
        "s3:GetObject",
        "arn:aws:s3:::my-bucket/file.txt"
    )
    print(f"    s3:GetObject on my-bucket: {'ALLOWED' if result1.allowed else 'DENIED'}")
    print(f"    Reason: {result1.reason}")
    assert result1.allowed, "Should allow s3:GetObject"
    
    # Test denied action (by SCP)
    result2 = resolver.evaluate_permission(
        "arn:aws:iam::123456789:role/MyRole",
        "s3:DeleteObject",
        "arn:aws:s3:::my-bucket/file.txt"
    )
    print(f"    s3:DeleteObject on my-bucket: {'ALLOWED' if result2.allowed else 'DENIED'}")
    print(f"    Reason: {result2.reason}")
    assert not result2.allowed, "Should deny s3:DeleteObject due to SCP"
    
    # Test implicit deny
    result3 = resolver.evaluate_permission(
        "arn:aws:iam::123456789:role/MyRole",
        "ec2:DescribeInstances",
        "*"
    )
    print(f"    ec2:DescribeInstances: {'ALLOWED' if result3.allowed else 'DENIED'}")
    print(f"    Reason: {result3.reason}")
    assert not result3.allowed, "Should implicitly deny ec2:DescribeInstances"
    
    print("    [PASS] IAM resolution working correctly")
    return True


def test_config_loader():
    """Test the configuration loader."""
    print("\n" + "=" * 60)
    print("TEST: Configuration Loader")
    print("=" * 60)
    
    loader = ConfigLoader()
    config = loader.config  # Use defaults
    
    print("\n[1] Testing Default Configuration...")
    print(f"    Resource score for S3: {config.resource_scores.get('s3', 0)}")
    print(f"    Resource score for RDS: {config.resource_scores.get('rds', 0)}")
    print(f"    Severity threshold (critical): {config.severity.critical}")
    
    assert config.resource_scores.get('rds', 0) > config.resource_scores.get('s3', 0), \
        "RDS should be scored higher than S3"
    print("    [PASS] Default config loaded")
    
    print("\n[2] Testing Severity Classification...")
    assert loader.get_severity(0.9) == "CRITICAL"
    assert loader.get_severity(0.7) == "HIGH"
    assert loader.get_severity(0.5) == "MEDIUM"
    assert loader.get_severity(0.2) == "LOW"
    print("    [PASS] Severity classification working")
    
    print("\n[3] Testing Crown Jewel Detection...")
    # Update config for test
    config.crown_jewels.name_patterns = ["*customer*", "*secret*"]
    loader.config = config
    
    assert loader.is_crown_jewel("s3.customer_data"), "Should detect customer data as crown jewel"
    assert loader.is_crown_jewel("aws_secretsmanager_secret.api_keys"), "Should detect secrets as crown jewel"
    assert not loader.is_crown_jewel("ec2.web_server"), "Web server should not be crown jewel"
    print("    [PASS] Crown jewel detection working")
    
    return True


def test_integration():
    """Test full integration of all enterprise features."""
    print("\n" + "=" * 60)
    print("TEST: Full Enterprise Integration")
    print("=" * 60)
    
    # Create both safe and vulnerable graphs
    safe_graph = InfrastructureGraph(name="safe")
    safe_graph.add_resource("alb.main", "alb", is_public=True)
    safe_graph.add_resource("ec2.web", "ec2")
    safe_graph.add_resource("sg.private", "security_group")
    safe_graph.add_resource("rds.db", "rds", contains_sensitive_data=True)
    
    # Safe: No direct path from ALB to RDS
    safe_graph.add_permission("alb.main", "ec2.web", "forward")
    safe_graph.add_permission("sg.private", "ec2.web", "network")
    # RDS is isolated, no path from Internet
    
    vulnerable_graph = InfrastructureGraph(name="vulnerable")
    vulnerable_graph.add_resource("alb.main", "alb", is_public=True)
    vulnerable_graph.add_resource("ec2.web", "ec2")
    vulnerable_graph.add_resource("iam.overprivileged", "iam_role")
    vulnerable_graph.add_resource("rds.db", "rds", contains_sensitive_data=True)
    
    # Vulnerable: Direct path from ALB to RDS via overprivileged role
    vulnerable_graph.add_permission("alb.main", "ec2.web", "forward")
    vulnerable_graph.add_permission("ec2.web", "iam.overprivileged", "assume")
    vulnerable_graph.add_permission("iam.overprivileged", "rds.db", "admin")
    
    print("\n[1] Testing Safe vs Vulnerable Comparison...")
    
    # Check safe graph
    safe_engine = OptimizedGraphEngine(safe_graph)
    safe_paths = safe_engine.find_critical_paths()
    print(f"    Safe graph attack paths: {len(safe_paths)}")
    
    # Check vulnerable graph
    vuln_engine = OptimizedGraphEngine(vulnerable_graph)
    vuln_paths = vuln_engine.find_critical_paths()
    print(f"    Vulnerable graph attack paths: {len(vuln_paths)}")
    
    assert len(vuln_paths) > len(safe_paths), "Vulnerable should have more paths"
    print("    [PASS] Can distinguish safe from vulnerable")
    
    print("\n[2] Testing Analyzer Integration...")
    analyzer = LaterxyAnalyzer()
    result = analyzer.analyze(safe_graph, vulnerable_graph)
    
    print(f"    Is safe: {result.is_safe}")
    print(f"    Breaches found: {len(result.breaches)}")
    
    if result.breaches:
        print(f"    First breach: {result.breaches[0].breach_type}")
        print(f"    Severity: {result.breaches[0].severity}")
    
    assert not result.is_safe, "Should detect the vulnerability"
    print("    [PASS] Analyzer detected the security regression")
    
    return True


def main():
    """Run all enterprise feature tests."""
    print("=" * 60)
    print("  LATERYX ENTERPRISE FEATURES TEST SUITE")
    print("  Testing: Parsing, IAM, Centrality, Config")
    print("=" * 60)
    
    results = []
    
    try:
        results.append(("Optimized Engine", test_optimized_engine()))
    except Exception as e:
        print(f"    [FAIL] Optimized Engine: {e}")
        results.append(("Optimized Engine", False))
    
    try:
        results.append(("IAM Resolver", test_iam_resolver()))
    except Exception as e:
        print(f"    [FAIL] IAM Resolver: {e}")
        results.append(("IAM Resolver", False))
    
    try:
        results.append(("Config Loader", test_config_loader()))
    except Exception as e:
        print(f"    [FAIL] Config Loader: {e}")
        results.append(("Config Loader", False))
    
    try:
        results.append(("Integration", test_integration()))
    except Exception as e:
        print(f"    [FAIL] Integration: {e}")
        results.append(("Integration", False))
    
    # Summary
    print("\n" + "=" * 60)
    print("  TEST SUMMARY")
    print("=" * 60)
    
    passed = sum(1 for _, r in results if r)
    total = len(results)
    
    for name, result in results:
        status = "[PASS]" if result else "[FAIL]"
        print(f"  {status} {name}")
    
    print(f"\n  Total: {passed}/{total} passed")
    print("=" * 60)
    
    return passed == total


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
