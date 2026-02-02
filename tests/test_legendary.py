#!/usr/bin/env python3
"""
Lateryx Legendary Features Demonstration
========================================
Proves the three Legendary features:
1. Shadow Path Discovery (War-Gaming Simulation)
2. Zero-Knowledge "Private" Analysis (Tokenization)
3. Immune System Loop (Observability Prioritization)
"""

import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.main import InfrastructureGraph

def create_complex_infrastructure():
    graph = InfrastructureGraph(name="enterprise-hq")
    
    # Entrance
    graph.add_resource("alb.public", "alb", is_public=True)
    
    # App Layer
    graph.add_resource("ec2.web_server", "ec2")
    graph.add_resource("ec2.api_gateway", "ec2")
    
    # Internal Services
    graph.add_resource("lambda.auth_processor", "lambda")
    graph.add_resource("iam.data_accessor_role", "iam_role")
    
    # Data Layer
    graph.add_resource("rds.customer_db", "rds", contains_sensitive_data=True)
    graph.add_resource("s3.legacy_backups", "s3", contains_sensitive_data=True)

    # Connections
    graph.add_permission("alb.public", "ec2.web_server", "forward")
    graph.add_permission("ec2.web_server", "ec2.api_gateway", "api_call")
    graph.add_permission("ec2.api_gateway", "lambda.auth_processor", "invoke")
    graph.add_permission("lambda.auth_processor", "iam.data_accessor_role", "assume")
    graph.add_permission("iam.data_accessor_role", "rds.customer_db", "read")
    
    # Alternative path (The hidden vulnerability)
    graph.add_permission("ec2.web_server", "iam.data_accessor_role", "direct_access") # OUCH!
    
    return graph

def demo_legendary_features():
    print("=" * 70)
    print("  LATERYX LEGENDARY FEATURES DEMONSTRATION")
    print("=" * 70)
    
    graph = create_complex_infrastructure()
    
    # --- Feature 1: Shadow Path Discovery ---
    print("\n[1] LEGENDARY: Shadow Path Discovery (War-Gaming)")
    print("Scenario: 'If our Web Server is compromised, what can they hit?'")
    
    war_room_report = graph.simulate_compromise("ec2.web_server")
    
    if war_room_report:
        print(f"!!! ALERT: Revealed {len(war_room_report)} paths to ProtectedData from ec2.web_server")
        for i, path in enumerate(war_room_report, 1):
            print(f"  Path {i}: {' -> '.join(path.path)}")
            print(f"  Risk Score: {path.risk_score:.2f}")
    else:
        print("PASS: No paths found from this node.")

    # --- Feature 2: Zero-Knowledge Analysis ---
    print("\n[2] LEGENDARY: Zero-Knowledge 'Private' Analysis")
    print("Tokenizing graph for third-party audit...")
    
    anon_graph, mapping = graph.tokenize_graph()
    
    print(f"Original Node: ec2.web_server -> Anon ID: {[k for k, v in mapping.items() if v == 'ec2.web_server'][0]}")
    
    # Prove analysis still works on tokenized graph
    anon_paths = anon_graph.find_all_attack_paths()
    print(f"Audit Result: Successfully found {len(anon_paths)} attack paths on anonymized data.")
    print(f"Example Anon Path: {' -> '.join(anon_paths[0].path)}")

    # --- Feature 3: Immune System Loop ---
    print("\n[3] LEGENDARY: Immune System Loop")
    print("Identifying Choke Points for GuardDuty/CloudTrail monitoring...")
    
    choke_points = graph.get_critical_observability_nodes()
    
    print("Targeted Monitoring Manifest:")
    for cp in choke_points[:3]: # Top 3
        print(f"  - [{cp['observability_priority']}] Node: {cp['node_id']} (Involved in {cp['path_involvement_count']} paths)")
        print(f"    Action: Attach GuardDuty honeypot or high-fidelity CloudTrail logging.")

def main():
    demo_legendary_features()
    print("\n" + "=" * 70)
    print("CONCLUSION: Lateryx is now an Architectural War-Gaming Engine.")
    print("=" * 70)

if __name__ == "__main__":
    main()
