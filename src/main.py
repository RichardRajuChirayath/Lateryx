#!/usr/bin/env python3
"""
Lateryx Security Engine - Main Module
======================================
Analyzes infrastructure changes to predict new attack paths using graph theory.
Identifies "Causality Breaches" by comparing before/after infrastructure graphs.

Core Logic:
1. Graph Construction: Map infrastructure components as nodes, permissions as edges
2. Pathfinding: Find paths from 'Internet' to 'ProtectedData'
3. Change Analysis: Compare "Before" and "After" graphs
4. Scoring: Flag new or shortened paths as HIGH RISK
"""

import hashlib
import json
import sys
import uuid
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import networkx as nx


class RiskLevel(Enum):
    """Risk classification for infrastructure changes."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class AttackPath:
    """Represents a potential attack path through infrastructure."""
    source: str
    target: str
    path: list[str]
    length: int
    risk_score: float = 0.0
    
    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "target": self.target,
            "path": self.path,
            "length": self.length,
            "risk_score": self.risk_score
        }


@dataclass
class CausalityBreach:
    """Represents a detected security breach in infrastructure changes."""
    breach_type: str  # "NEW_PATH" | "SHORTENED_PATH" | "WIDENED_ACCESS"
    severity: RiskLevel
    before_path: Optional[AttackPath]
    after_path: AttackPath
    description: str
    remediation: str
    
    def to_dict(self) -> dict:
        return {
            "breach_type": self.breach_type,
            "severity": self.severity.value,
            "before_path": self.before_path.to_dict() if self.before_path else None,
            "after_path": self.after_path.to_dict(),
            "description": self.description,
            "remediation": self.remediation
        }


@dataclass
class AnalysisResult:
    """Complete analysis result for infrastructure comparison."""
    is_safe: bool
    breaches: list[CausalityBreach] = field(default_factory=list)
    before_paths_count: int = 0
    after_paths_count: int = 0
    new_paths_count: int = 0
    shortened_paths_count: int = 0
    summary: str = ""
    
    def to_dict(self) -> dict:
        return {
            "is_safe": self.is_safe,
            "breaches": [b.to_dict() for b in self.breaches],
            "before_paths_count": self.before_paths_count,
            "after_paths_count": self.after_paths_count,
            "new_paths_count": self.new_paths_count,
            "shortened_paths_count": self.shortened_paths_count,
            "summary": self.summary
        }


class InfrastructureGraph:
    """
    Graph representation of cloud infrastructure.
    
    Nodes represent infrastructure components (S3, EC2, IAM, etc.)
    Edges represent permissions and access relationships.
    """
    
    # Special node identifiers
    INTERNET = "Internet"
    PROTECTED_DATA = "ProtectedData"
    
    # Node type weights for risk calculation
    NODE_WEIGHTS = {
        "internet": 0.0,      # Entry point
        "alb": 0.1,           # Load balancer
        "api_gateway": 0.1,   # API Gateway
        "lambda": 0.2,        # Lambda function
        "ec2": 0.3,           # EC2 instance
        "ecs": 0.3,           # ECS container
        "iam_role": 0.4,      # IAM role
        "iam_user": 0.5,      # IAM user
        "s3": 0.6,            # S3 bucket
        "rds": 0.8,           # RDS database
        "dynamodb": 0.7,      # DynamoDB table
        "secrets_manager": 0.9,  # Secrets
        "kms": 0.9,           # KMS keys
        "protected_data": 1.0    # Target
    }
    
    def __init__(self, name: str = "infrastructure"):
        self.name = name
        self.graph = nx.DiGraph()
        self._add_sentinel_nodes()
    
    def _add_sentinel_nodes(self):
        """Add Internet and ProtectedData sentinel nodes."""
        self.graph.add_node(self.INTERNET, type="internet", weight=0.0)
        self.graph.add_node(self.PROTECTED_DATA, type="protected_data", weight=1.0)
    
    def add_resource(self, resource_id: str, resource_type: str, 
                     properties: dict = None, is_public: bool = False,
                     contains_sensitive_data: bool = False):
        """
        Add an infrastructure resource as a node.
        
        Args:
            resource_id: Unique identifier for the resource
            resource_type: Type of resource (s3, ec2, iam_role, etc.)
            properties: Additional properties of the resource
            is_public: Whether the resource is publicly accessible
            contains_sensitive_data: Whether the resource contains protected data
        """
        weight = self.NODE_WEIGHTS.get(resource_type.lower(), 0.5)
        
        self.graph.add_node(
            resource_id,
            type=resource_type,
            weight=weight,
            properties=properties or {},
            is_public=is_public,
            contains_sensitive_data=contains_sensitive_data
        )
        
        # If public, connect from Internet
        if is_public:
            self.graph.add_edge(
                self.INTERNET, 
                resource_id,
                permission="public_access",
                risk_weight=0.8
            )
        
        # If contains sensitive data, connect to ProtectedData
        if contains_sensitive_data:
            self.graph.add_edge(
                resource_id,
                self.PROTECTED_DATA,
                permission="data_access",
                risk_weight=1.0
            )
    
    def add_permission(self, source: str, target: str, 
                       permission_type: str, conditions: dict = None):
        """
        Add a permission relationship as an edge.
        
        Args:
            source: Source resource ID
            target: Target resource ID
            permission_type: Type of permission (read, write, assume_role, etc.)
            conditions: IAM conditions or restrictions
        """
        # Calculate risk weight based on permission type
        risk_weights = {
            "read": 0.3,
            "write": 0.6,
            "delete": 0.8,
            "admin": 1.0,
            "assume_role": 0.7,
            "invoke": 0.5,
            "execute": 0.6,
            "public_access": 0.9,
            "data_access": 1.0
        }
        
        risk_weight = risk_weights.get(permission_type.lower(), 0.5)
        
        # Reduce risk if conditions are present (more restrictive)
        if conditions:
            risk_weight *= 0.7
        
        self.graph.add_edge(
            source,
            target,
            permission=permission_type,
            conditions=conditions or {},
            risk_weight=risk_weight
        )
    
    def find_all_attack_paths(self) -> list[AttackPath]:
        """
        Find all possible paths from Internet to ProtectedData.
        
        Uses NetworkX's all_simple_paths algorithm to enumerate
        all potential attack vectors through the infrastructure.
        
        Returns:
            List of AttackPath objects representing potential attack vectors
        """
        attack_paths = []
        
        try:
            # Find all simple paths (no cycles) from Internet to ProtectedData
            all_paths = nx.all_simple_paths(
                self.graph,
                source=self.INTERNET,
                target=self.PROTECTED_DATA,
                cutoff=15  # Limit path length to prevent explosion
            )
            
            for path in all_paths:
                risk_score = self._calculate_path_risk(path)
                attack_paths.append(AttackPath(
                    source=self.INTERNET,
                    target=self.PROTECTED_DATA,
                    path=path,
                    length=len(path) - 1,  # Number of edges
                    risk_score=risk_score
                ))
        except nx.NetworkXNoPath:
            # No path exists - infrastructure is isolated
            pass
        except nx.NodeNotFound:
            # Sentinel nodes missing - shouldn't happen
            pass
        
        # Sort by risk score (highest first)
        attack_paths.sort(key=lambda p: p.risk_score, reverse=True)
        
        return attack_paths
    
    def _calculate_path_risk(self, path: list[str]) -> float:
        """
        Calculate the risk score for a given attack path.
        
        Risk is calculated based on:
        - Path length (shorter = higher risk)
        - Edge weights (permission risk)
        - Node types along the path
        
        Returns:
            Float between 0.0 and 1.0 representing risk
        """
        if len(path) < 2:
            return 0.0
        
        # Base risk inversely proportional to path length
        # Shorter paths = higher risk (easier to exploit)
        length_factor = 1.0 / len(path)
        
        # Accumulate edge risks
        edge_risk = 0.0
        for i in range(len(path) - 1):
            edge_data = self.graph.get_edge_data(path[i], path[i + 1], default={})
            edge_risk += edge_data.get("risk_weight", 0.5)
        
        # Normalize edge risk
        edge_factor = edge_risk / (len(path) - 1)
        
        # Combine factors
        # Weight: 40% path length, 60% edge risk
        risk_score = (0.4 * length_factor) + (0.6 * edge_factor)
        
        return min(1.0, risk_score)
    
    def get_shortest_path_length(self) -> Optional[int]:
        """Get the length of the shortest path from Internet to ProtectedData."""
        try:
            return nx.shortest_path_length(
                self.graph,
                source=self.INTERNET,
                target=self.PROTECTED_DATA
            )
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return None

    def simulate_compromise(self, node_id: str) -> List[AttackPath]:
        """
        LEGENDARY: Shadow Path Discovery (War-Gaming).
        Simulates what an attacker can reach if this specific node is compromised.
        
        Returns:
            List of paths from the compromised node to ProtectedData.
        """
        if node_id not in self.graph:
            return []
            
        paths = []
        try:
            all_paths = nx.all_simple_paths(
                self.graph,
                source=node_id,
                target=self.PROTECTED_DATA,
                cutoff=10
            )
            for path in all_paths:
                risk_score = self._calculate_path_risk(path)
                paths.append(AttackPath(
                    source=node_id,
                    target=self.PROTECTED_DATA,
                    path=path,
                    length=len(path) - 1,
                    risk_score=risk_score
                ))
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            pass
            
        return sorted(paths, key=lambda p: p.risk_score, reverse=True)

    def tokenize_graph(self) -> Tuple['InfrastructureGraph', Dict[str, str]]:
        """
        LEGENDARY: Zero-Knowledge "Private" Analysis.
        Anonymizes all node names using salt+hash to protect sensitive naming conventions.
        
        Returns:
            Tuple of (Anonymized Graph, Mapping Dictionary)
        """
        tokenized = InfrastructureGraph(name=f"anon-{self.name}")
        tokenized.graph.clear()
        
        mapping = {}
        salt = str(uuid.uuid4())
        
        def get_anon_id(original: str) -> str:
            if original in mapping:
                return mapping[original]
            if original in [self.INTERNET, self.PROTECTED_DATA]:
                mapping[original] = original
                return original
            
            # Create a deterministic but opaque ID
            hasher = hashlib.sha256()
            hasher.update(f"{salt}{original}".encode())
            anon_id = f"node-{hasher.hexdigest()[:12]}"
            mapping[original] = anon_id
            return anon_id

        # Copy nodes with anonymized IDs
        for node, data in self.graph.nodes(data=True):
            anon_id = get_anon_id(node)
            tokenized.graph.add_node(anon_id, **data)
            
        # Copy edges
        for u, v, data in self.graph.edges(data=True):
            tokenized.graph.add_edge(get_anon_id(u), get_anon_id(v), **data)
            
        return tokenized, {v: k for k, v in mapping.items()}

    def get_critical_observability_nodes(self) -> List[Dict]:
        """
        LEGENDARY: Immune System Loop.
        Identifies nodes that appear in multiple attack paths.
        These are "Choke Points" that should be monitored via CloudTrail/GuardDuty.
        """
        all_paths = self.find_all_attack_paths()
        node_frequency = {}
        
        for p in all_paths:
            # Skip Internet and ProtectedData
            for node in p.path[1:-1]:
                node_frequency[node] = node_frequency.get(node, 0) + 1
        
        # Sort by frequency (highest impact first)
        critical_nodes = []
        for node, freq in sorted(node_frequency.items(), key=lambda x: x[1], reverse=True):
            node_data = self.graph.nodes[node]
            critical_nodes.append({
                "node_id": node,
                "type": node_data.get("type"),
                "path_involvement_count": freq,
                "observability_priority": "CRITICAL" if freq > (len(all_paths) * 0.5) else "HIGH"
            })
            
        return critical_nodes
    
    def has_path_to_protected_data(self) -> bool:
        """Check if any path exists from Internet to ProtectedData."""
        return nx.has_path(self.graph, self.INTERNET, self.PROTECTED_DATA)
    
    def to_dict(self) -> dict:
        """Serialize graph to dictionary for JSON export."""
        return {
            "name": self.name,
            "nodes": [
                {"id": n, **self.graph.nodes[n]}
                for n in self.graph.nodes
            ],
            "edges": [
                {"source": u, "target": v, **d}
                for u, v, d in self.graph.edges(data=True)
            ]
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> "InfrastructureGraph":
        """Deserialize graph from dictionary."""
        graph = cls(name=data.get("name", "infrastructure"))
        
        # Clear default nodes (will be added from data)
        graph.graph.clear()
        
        for node in data.get("nodes", []):
            node_id = node.pop("id")
            graph.graph.add_node(node_id, **node)
        
        for edge in data.get("edges", []):
            source = edge.pop("source")
            target = edge.pop("target")
            graph.graph.add_edge(source, target, **edge)
        
        return graph


class LaterxyAnalyzer:
    """
    Main analyzer for detecting Causality Breaches.
    
    Compares before and after infrastructure states to identify:
    - New attack paths created
    - Existing paths that were shortened
    - Widened access patterns
    """
    
    def __init__(self):
        self.before_graph: Optional[InfrastructureGraph] = None
        self.after_graph: Optional[InfrastructureGraph] = None
    
    def analyze(self, before: InfrastructureGraph, 
                after: InfrastructureGraph) -> AnalysisResult:
        """
        Perform full analysis comparing before and after infrastructure states.
        
        This implements the core Lateryx logic:
        1. Find all attack paths in both graphs
        2. Identify new paths (paths that didn't exist before)
        3. Identify shortened paths (same destination, fewer hops)
        4. Score and classify each breach
        
        Args:
            before: Infrastructure graph before the change
            after: Infrastructure graph after the change
            
        Returns:
            AnalysisResult with all detected breaches
        """
        self.before_graph = before
        self.after_graph = after
        
        # Find all attack paths
        before_paths = before.find_all_attack_paths()
        after_paths = after.find_all_attack_paths()
        
        breaches = []
        
        # Detect new paths
        new_paths = self._find_new_paths(before_paths, after_paths)
        for path in new_paths:
            breach = CausalityBreach(
                breach_type="NEW_PATH",
                severity=self._classify_severity(path, is_new=True),
                before_path=None,
                after_path=path,
                description=f"New attack path created: {' → '.join(path.path)}",
                remediation=self._generate_remediation(path, "NEW_PATH")
            )
            breaches.append(breach)
        
        # Detect shortened paths
        shortened = self._find_shortened_paths(before_paths, after_paths)
        for before_path, after_path in shortened:
            breach = CausalityBreach(
                breach_type="SHORTENED_PATH",
                severity=self._classify_severity(after_path, is_shortened=True),
                before_path=before_path,
                after_path=after_path,
                description=(
                    f"Attack path shortened from {before_path.length} to "
                    f"{after_path.length} hops: {' → '.join(after_path.path)}"
                ),
                remediation=self._generate_remediation(after_path, "SHORTENED_PATH")
            )
            breaches.append(breach)
        
        # Determine if infrastructure is safe
        is_safe = len(breaches) == 0
        
        # Generate summary
        summary = self._generate_summary(
            before_paths, after_paths, 
            len(new_paths), len(shortened)
        )
        
        return AnalysisResult(
            is_safe=is_safe,
            breaches=breaches,
            before_paths_count=len(before_paths),
            after_paths_count=len(after_paths),
            new_paths_count=len(new_paths),
            shortened_paths_count=len(shortened),
            summary=summary
        )
    
    def _find_new_paths(self, before: list[AttackPath], 
                        after: list[AttackPath]) -> list[AttackPath]:
        """Find paths that exist in 'after' but not in 'before'."""
        before_path_sets = {tuple(p.path) for p in before}
        
        new_paths = []
        for path in after:
            if tuple(path.path) not in before_path_sets:
                # Check if this is truly new or just a variation
                if not self._is_path_variation(path, before):
                    new_paths.append(path)
        
        return new_paths
    
    def _find_shortened_paths(self, before: list[AttackPath], 
                               after: list[AttackPath]) -> list[tuple[AttackPath, AttackPath]]:
        """Find paths that were shortened (same endpoints via intermediate nodes)."""
        shortened = []
        
        # Group by critical intermediate nodes
        for after_path in after:
            for before_path in before:
                # Check if after_path is a shorter version of before_path
                if (after_path.length < before_path.length and 
                    self._paths_share_critical_nodes(before_path, after_path)):
                    shortened.append((before_path, after_path))
                    break
        
        return shortened
    
    def _is_path_variation(self, path: AttackPath, 
                           existing_paths: list[AttackPath]) -> bool:
        """Check if a path is just a minor variation of existing paths."""
        for existing in existing_paths:
            # If paths share 80%+ of nodes, consider it a variation
            common_nodes = set(path.path) & set(existing.path)
            similarity = len(common_nodes) / max(len(path.path), len(existing.path))
            if similarity > 0.8:
                return True
        return False
    
    def _paths_share_critical_nodes(self, path1: AttackPath, 
                                     path2: AttackPath) -> bool:
        """Check if two paths share critical intermediate nodes."""
        # Exclude Internet and ProtectedData for comparison
        critical1 = set(path1.path[1:-1])
        critical2 = set(path2.path[1:-1])
        
        if not critical1 or not critical2:
            return False
        
        # Check if the shorter path's nodes are a subset
        return len(critical2 & critical1) > 0
    
    def _classify_severity(self, path: AttackPath, 
                           is_new: bool = False, 
                           is_shortened: bool = False) -> RiskLevel:
        """Classify the severity of a breach based on path characteristics."""
        # Very short paths are critical
        if path.length <= 2:
            return RiskLevel.CRITICAL
        
        # High risk score indicates dangerous path
        if path.risk_score > 0.7:
            return RiskLevel.HIGH
        
        # New paths are generally higher risk
        if is_new and path.length <= 4:
            return RiskLevel.HIGH
        
        # Shortened paths depend on reduction
        if is_shortened and path.length <= 3:
            return RiskLevel.HIGH
        
        if path.risk_score > 0.4:
            return RiskLevel.MEDIUM
        
        return RiskLevel.LOW
    
    def _generate_remediation(self, path: AttackPath, 
                               breach_type: str) -> str:
        """Generate remediation advice for a specific breach."""
        if breach_type == "NEW_PATH":
            # Find the weakest link in the path
            if len(path.path) > 2:
                weak_node = path.path[1]  # First node after Internet
                return (
                    f"Review the permissions and public access settings of "
                    f"'{weak_node}'. Consider adding IAM conditions, "
                    f"VPC restrictions, or removing public access."
                )
            return (
                "This is a direct path to protected data. "
                "Immediately review and restrict public access."
            )
        
        elif breach_type == "SHORTENED_PATH":
            return (
                "The change reduced the security layers between Internet "
                "and protected data. Review the removed restrictions and "
                "consider adding compensating controls."
            )
        
        return "Review the infrastructure change and assess the security impact."
    
    def _generate_summary(self, before_paths: list[AttackPath],
                          after_paths: list[AttackPath],
                          new_count: int, shortened_count: int) -> str:
        """Generate a human-readable summary of the analysis."""
        if new_count == 0 and shortened_count == 0:
            if len(after_paths) == 0:
                return "✅ SAFE: No attack paths detected. Infrastructure is properly isolated."
            return "✅ SAFE: No new or shortened attack paths detected."
        
        parts = []
        parts.append("⚠️ CAUSALITY BREACH DETECTED")
        
        if new_count > 0:
            parts.append(f"  • {new_count} new attack path(s) created")
        
        if shortened_count > 0:
            parts.append(f"  • {shortened_count} attack path(s) shortened")
        
        parts.append(f"\nBefore: {len(before_paths)} paths | After: {len(after_paths)} paths")
        
        return "\n".join(parts)


def analyze_terraform_change(before_json: str, after_json: str) -> AnalysisResult:
    """
    Main entry point for analyzing Terraform infrastructure changes.
    
    Args:
        before_json: Path to JSON file representing before state
        after_json: Path to JSON file representing after state
        
    Returns:
        AnalysisResult with all detected breaches
    """
    # Load graphs from JSON
    with open(before_json, 'r') as f:
        before_data = json.load(f)
    
    with open(after_json, 'r') as f:
        after_data = json.load(f)
    
    before_graph = InfrastructureGraph.from_dict(before_data)
    after_graph = InfrastructureGraph.from_dict(after_data)
    
    # Run analysis
    analyzer = LaterxyAnalyzer()
    return analyzer.analyze(before_graph, after_graph)


def main():
    """CLI entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Lateryx Security Engine - Infrastructure Attack Path Analyzer"
    )
    parser.add_argument(
        "--before", "-b",
        required=True,
        help="Path to JSON file representing infrastructure before change"
    )
    parser.add_argument(
        "--after", "-a",
        required=True,
        help="Path to JSON file representing infrastructure after change"
    )
    parser.add_argument(
        "--output", "-o",
        default=None,
        help="Path to output JSON file (optional, defaults to stdout)"
    )
    parser.add_argument(
        "--fail-on-breach",
        action="store_true",
        help="Exit with code 1 if any breach is detected"
    )
    
    args = parser.parse_args()
    
    # Run analysis
    result = analyze_terraform_change(args.before, args.after)
    
    # Output results
    output_json = json.dumps(result.to_dict(), indent=2)
    
    if args.output:
        with open(args.output, 'w') as f:
            f.write(output_json)
        print(f"Results written to {args.output}")
    else:
        print(output_json)
    
    # Print summary to stderr
    print(f"\n{result.summary}", file=sys.stderr)
    
    # Exit with error code if breaches detected and --fail-on-breach is set
    if args.fail_on_breach and not result.is_safe:
        sys.exit(1)


if __name__ == "__main__":
    main()
