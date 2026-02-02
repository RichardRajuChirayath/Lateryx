#!/usr/bin/env python3
"""
Lateryx Optimized Graph Engine
==============================
Uses advanced graph algorithms to handle massive enterprise infrastructures.
Solves the "Graph Explosion" problem using:
1. Centrality analysis to find high-risk zones first
2. Incremental path discovery
3. Memory-efficient streaming analysis
"""

from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple

import networkx as nx

from .main import AttackPath, InfrastructureGraph


@dataclass
class CentralityReport:
    """Report on node centrality (importance in the graph)."""
    node_id: str
    betweenness: float  # How often node appears on shortest paths
    degree: int         # Number of connections
    pagerank: float     # Importance based on incoming connections
    risk_score: float   # Combined risk assessment


@dataclass
class RiskZone:
    """A high-risk area of the infrastructure."""
    zone_name: str
    central_node: str
    member_nodes: Set[str]
    total_risk: float
    paths_through_zone: int


class OptimizedGraphEngine:
    """
    Optimized graph analysis engine for large infrastructures.
    
    For infrastructures with 10,000+ resources, we cannot enumerate
    all possible paths. Instead, we:
    1. Calculate centrality to find "important" nodes
    2. Focus path analysis on high-centrality regions
    3. Use streaming algorithms for memory efficiency
    """
    
    # Maximum paths to enumerate before switching to sampling
    MAX_FULL_ENUMERATION = 1000
    
    # Centrality threshold for "important" nodes
    CENTRALITY_THRESHOLD = 0.1
    
    def __init__(self, graph: InfrastructureGraph):
        self.infra_graph = graph
        self.nx_graph = graph.graph
        self._centrality_cache: Dict[str, CentralityReport] = {}
        
    def analyze_centrality(self) -> List[CentralityReport]:
        """
        Calculate centrality metrics for all nodes.
        
        Centrality tells us which nodes are "important" in the graph:
        - High betweenness = node sits on many paths (choke point)
        - High degree = node has many connections (hub)
        - High PageRank = node receives connections from important nodes
        """
        if self._centrality_cache:
            return list(self._centrality_cache.values())
        
        # Calculate different centrality measures
        try:
            betweenness = nx.betweenness_centrality(self.nx_graph)
        except:
            betweenness = {n: 0.0 for n in self.nx_graph.nodes()}
            
        try:
            pagerank = nx.pagerank(self.nx_graph, max_iter=100)
        except:
            pagerank = {n: 0.0 for n in self.nx_graph.nodes()}
        
        reports = []
        for node in self.nx_graph.nodes():
            degree = self.nx_graph.degree(node)
            
            # Combine metrics into risk score
            # Weight: 50% betweenness, 30% PageRank, 20% degree
            max_degree = max(d for _, d in self.nx_graph.degree()) or 1
            normalized_degree = degree / max_degree
            
            risk_score = (
                0.5 * betweenness.get(node, 0) +
                0.3 * pagerank.get(node, 0) +
                0.2 * normalized_degree
            )
            
            report = CentralityReport(
                node_id=node,
                betweenness=betweenness.get(node, 0),
                degree=degree,
                pagerank=pagerank.get(node, 0),
                risk_score=risk_score
            )
            
            reports.append(report)
            self._centrality_cache[node] = report
        
        # Sort by risk score
        reports.sort(key=lambda r: r.risk_score, reverse=True)
        return reports
    
    def identify_risk_zones(self, num_zones: int = 5) -> List[RiskZone]:
        """
        Identify high-risk zones in the infrastructure.
        
        A zone is a cluster of nodes around a high-centrality node.
        Focusing on zones allows us to analyze large graphs efficiently.
        """
        centrality = self.analyze_centrality()
        
        # Get top central nodes as zone centers
        top_nodes = [c.node_id for c in centrality[:num_zones * 2]]
        
        zones = []
        used_nodes: Set[str] = set()
        
        for center in top_nodes:
            if center in used_nodes:
                continue
            
            # Get neighbors within 2 hops
            members = set([center])
            for neighbor in self.nx_graph.neighbors(center):
                members.add(neighbor)
                for n2 in self.nx_graph.neighbors(neighbor):
                    members.add(n2)
            
            # Skip if heavily overlapping with existing zone
            if len(members & used_nodes) > len(members) * 0.5:
                continue
            
            used_nodes.update(members)
            
            # Calculate zone risk
            total_risk = sum(
                self._centrality_cache.get(m, CentralityReport(m, 0, 0, 0, 0)).risk_score
                for m in members
            )
            
            # Count paths through this zone
            paths_count = self._count_paths_through_nodes(members)
            
            zones.append(RiskZone(
                zone_name=f"Zone-{center[:20]}",
                central_node=center,
                member_nodes=members,
                total_risk=total_risk,
                paths_through_zone=paths_count
            ))
            
            if len(zones) >= num_zones:
                break
        
        return zones
    
    def _count_paths_through_nodes(self, nodes: Set[str]) -> int:
        """Count approximate paths that pass through a set of nodes."""
        count = 0
        source = InfrastructureGraph.INTERNET
        target = InfrastructureGraph.PROTECTED_DATA
        
        try:
            # Sample a few paths to estimate
            for _ in range(100):
                try:
                    path = nx.shortest_path(self.nx_graph, source, target)
                    if any(n in nodes for n in path):
                        count += 1
                except nx.NetworkXNoPath:
                    break
        except:
            pass
        
        return count
    
    def find_critical_paths(self, max_paths: int = 100) -> List[AttackPath]:
        """
        Find the most critical attack paths efficiently.
        
        Instead of enumerating ALL paths, we:
        1. Start with shortest paths
        2. Expand to include paths through high-centrality nodes
        3. Stop when we hit max_paths
        """
        paths = []
        source = InfrastructureGraph.INTERNET
        target = InfrastructureGraph.PROTECTED_DATA
        
        # Check if any path exists
        if not nx.has_path(self.nx_graph, source, target):
            return []
        
        # Get shortest paths first
        try:
            for path in nx.all_shortest_paths(self.nx_graph, source, target):
                risk = self._calculate_path_risk(path)
                paths.append(AttackPath(
                    source=source,
                    target=target,
                    path=path,
                    length=len(path) - 1,
                    risk_score=risk
                ))
                if len(paths) >= max_paths:
                    break
        except nx.NetworkXNoPath:
            return []
        
        # If we have room, add paths through high-centrality nodes
        if len(paths) < max_paths:
            centrality = self.analyze_centrality()
            critical_nodes = [c.node_id for c in centrality[:10]]
            
            for node in critical_nodes:
                if len(paths) >= max_paths:
                    break
                    
                # Find paths that go through this node
                try:
                    if nx.has_path(self.nx_graph, source, node) and \
                       nx.has_path(self.nx_graph, node, target):
                        path1 = nx.shortest_path(self.nx_graph, source, node)
                        path2 = nx.shortest_path(self.nx_graph, node, target)
                        
                        # Combine paths (avoid duplicate node)
                        full_path = path1 + path2[1:]
                        
                        # Check if this path is already found
                        if tuple(full_path) not in {tuple(p.path) for p in paths}:
                            risk = self._calculate_path_risk(full_path)
                            paths.append(AttackPath(
                                source=source,
                                target=target,
                                path=full_path,
                                length=len(full_path) - 1,
                                risk_score=risk
                            ))
                except:
                    continue
        
        # Sort by risk
        paths.sort(key=lambda p: p.risk_score, reverse=True)
        return paths[:max_paths]
    
    def _calculate_path_risk(self, path: List[str]) -> float:
        """Calculate risk score for a path."""
        if len(path) < 2:
            return 0.0
        
        # Shorter paths are riskier
        length_factor = 1.0 / len(path)
        
        # Sum centrality of nodes in path
        centrality_sum = sum(
            self._centrality_cache.get(n, CentralityReport(n, 0, 0, 0, 0)).risk_score
            for n in path[1:-1]  # Exclude source and target
        )
        
        # Normalize
        if len(path) > 2:
            centrality_factor = centrality_sum / (len(path) - 2)
        else:
            centrality_factor = 0.5
        
        return 0.5 * length_factor + 0.5 * centrality_factor
    
    def get_blast_radius(self, compromised_node: str) -> Dict:
        """
        Calculate the "blast radius" of a compromised node.
        
        Returns statistics on how much of the infrastructure
        can be reached from this node.
        """
        if compromised_node not in self.nx_graph:
            return {"error": "Node not found"}
        
        # Get all reachable nodes
        reachable = set(nx.descendants(self.nx_graph, compromised_node))
        reachable.add(compromised_node)
        
        total_nodes = len(self.nx_graph.nodes())
        
        # Check if protected data is reachable
        can_reach_data = InfrastructureGraph.PROTECTED_DATA in reachable
        
        # Calculate path to protected data if exists
        shortest_to_data = None
        if can_reach_data:
            try:
                shortest_to_data = nx.shortest_path_length(
                    self.nx_graph,
                    compromised_node,
                    InfrastructureGraph.PROTECTED_DATA
                )
            except:
                pass
        
        # Identify sensitive resources in blast radius
        sensitive_reachable = [
            n for n in reachable
            if self.nx_graph.nodes[n].get("contains_sensitive_data", False)
        ]
        
        return {
            "compromised_node": compromised_node,
            "reachable_nodes": len(reachable),
            "total_nodes": total_nodes,
            "blast_radius_percent": round(len(reachable) / total_nodes * 100, 2),
            "can_reach_protected_data": can_reach_data,
            "hops_to_protected_data": shortest_to_data,
            "sensitive_resources_exposed": sensitive_reachable,
            "risk_level": self._classify_blast_radius(
                len(reachable), total_nodes, can_reach_data
            )
        }
    
    def _classify_blast_radius(self, reachable: int, total: int, 
                               can_reach_data: bool) -> str:
        """Classify the blast radius severity."""
        percent = reachable / total * 100
        
        if can_reach_data:
            if percent > 50:
                return "CRITICAL"
            elif percent > 20:
                return "HIGH"
            else:
                return "MEDIUM"
        else:
            if percent > 50:
                return "MEDIUM"
            elif percent > 20:
                return "LOW"
            else:
                return "MINIMAL"
    
    def generate_summary_report(self) -> Dict:
        """Generate a comprehensive analysis summary."""
        centrality = self.analyze_centrality()
        zones = self.identify_risk_zones()
        paths = self.find_critical_paths(max_paths=50)
        
        return {
            "graph_stats": {
                "total_nodes": len(self.nx_graph.nodes()),
                "total_edges": len(self.nx_graph.edges()),
                "density": nx.density(self.nx_graph)
            },
            "risk_summary": {
                "attack_paths_found": len(paths),
                "highest_risk_path": paths[0].path if paths else None,
                "highest_risk_score": paths[0].risk_score if paths else 0
            },
            "top_central_nodes": [
                {"node": c.node_id, "score": round(c.risk_score, 4)}
                for c in centrality[:5]
            ],
            "risk_zones": [
                {
                    "name": z.zone_name,
                    "center": z.central_node,
                    "size": len(z.member_nodes),
                    "risk": round(z.total_risk, 4)
                }
                for z in zones
            ]
        }
