#!/usr/bin/env python3
"""
Lateryx Plan Analyzer
=====================
Parses `terraform plan -json` output for accurate resource analysis.
This solves the "Parsing Fidelity" gap by analyzing the ACTUAL planned
infrastructure, not just the raw HCL code.

Usage:
    terraform plan -out=tfplan
    terraform show -json tfplan > tfplan.json
    python -m src.plan_analyzer tfplan.json
"""

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from .main import InfrastructureGraph


@dataclass
class PlannedResource:
    """Represents a resource from terraform plan."""
    address: str
    type: str
    name: str
    provider: str
    mode: str  # "managed" or "data"
    values: Dict
    sensitive_values: Dict
    depends_on: List[str] = field(default_factory=list)
    

@dataclass
class ResourceChange:
    """Represents a change to a resource."""
    address: str
    type: str
    change_type: str  # "create", "update", "delete", "no-op"
    before: Optional[Dict]
    after: Optional[Dict]
    after_unknown: Dict = field(default_factory=dict)


class TerraformPlanAnalyzer:
    """
    Analyzes terraform plan JSON output for accurate graph construction.
    
    This is superior to HCL parsing because:
    1. All variables, locals, and modules are already resolved
    2. count/for_each expansions are already applied
    3. We see the ACTUAL values, not expressions
    """
    
    # Map terraform resource types to Lateryx node types
    RESOURCE_TYPE_MAP = {
        # AWS Compute
        "aws_instance": "ec2",
        "aws_launch_template": "ec2",
        "aws_autoscaling_group": "ec2",
        "aws_ecs_service": "ecs",
        "aws_ecs_cluster": "ecs",
        "aws_ecs_task_definition": "ecs",
        "aws_lambda_function": "lambda",
        "aws_lambda_function_url": "lambda",
        
        # AWS Networking
        "aws_lb": "alb",
        "aws_alb": "alb",
        "aws_elb": "alb",
        "aws_api_gateway_rest_api": "api_gateway",
        "aws_apigatewayv2_api": "api_gateway",
        "aws_cloudfront_distribution": "cdn",
        "aws_vpc": "vpc",
        "aws_subnet": "subnet",
        "aws_security_group": "security_group",
        "aws_internet_gateway": "internet_gateway",
        "aws_nat_gateway": "nat_gateway",
        
        # AWS IAM
        "aws_iam_role": "iam_role",
        "aws_iam_user": "iam_user",
        "aws_iam_policy": "iam_policy",
        "aws_iam_role_policy": "iam_policy",
        "aws_iam_role_policy_attachment": "iam_attachment",
        "aws_iam_instance_profile": "instance_profile",
        
        # AWS Storage
        "aws_s3_bucket": "s3",
        "aws_s3_bucket_policy": "s3_policy",
        "aws_s3_bucket_public_access_block": "s3_access_block",
        
        # AWS Database
        "aws_db_instance": "rds",
        "aws_rds_cluster": "rds",
        "aws_dynamodb_table": "dynamodb",
        "aws_elasticache_cluster": "elasticache",
        
        # AWS Secrets
        "aws_secretsmanager_secret": "secrets_manager",
        "aws_ssm_parameter": "ssm_parameter",
        "aws_kms_key": "kms",
        
        # Azure
        "azurerm_virtual_machine": "azure_vm",
        "azurerm_storage_account": "azure_storage",
        "azurerm_sql_database": "azure_sql",
        "azurerm_key_vault": "azure_keyvault",
        
        # GCP
        "google_compute_instance": "gcp_vm",
        "google_storage_bucket": "gcp_storage",
        "google_sql_database_instance": "gcp_sql",
        
        # Kubernetes
        "kubernetes_deployment": "k8s_deployment",
        "kubernetes_service": "k8s_service",
        "kubernetes_ingress": "k8s_ingress",
        "kubernetes_secret": "k8s_secret",
    }
    
    # Patterns that indicate public access
    PUBLIC_INDICATORS = {
        "publicly_accessible": True,
        "map_public_ip_on_launch": True,
        "associate_public_ip_address": True,
    }
    
    # Patterns that indicate sensitive data
    SENSITIVE_INDICATORS = [
        "secret", "password", "key", "token", "credential",
        "customer", "user", "pii", "ssn", "credit"
    ]
    
    def __init__(self):
        self.resources: Dict[str, PlannedResource] = {}
        self.changes: List[ResourceChange] = []
        self.outputs: Dict = {}
        
    def parse_plan_file(self, plan_path: str) -> Tuple[InfrastructureGraph, List[ResourceChange]]:
        """
        Parse a terraform plan JSON file and build the infrastructure graph.
        
        Args:
            plan_path: Path to the tfplan.json file
            
        Returns:
            Tuple of (InfrastructureGraph, List of ResourceChanges)
        """
        with open(plan_path, 'r') as f:
            plan_data = json.load(f)
            
        return self.parse_plan_data(plan_data)
    
    def parse_plan_data(self, plan_data: Dict) -> Tuple[InfrastructureGraph, List[ResourceChange]]:
        """Parse plan data from dictionary."""
        
        # Extract planned values (the "after" state)
        planned_values = plan_data.get("planned_values", {})
        root_module = planned_values.get("root_module", {})
        
        # Parse all resources recursively (handles modules)
        self._parse_module_resources(root_module)
        
        # Parse resource changes
        resource_changes = plan_data.get("resource_changes", [])
        for change in resource_changes:
            self._parse_resource_change(change)
        
        # Build the infrastructure graph
        graph = self._build_graph()
        
        return graph, self.changes
    
    def _parse_module_resources(self, module: Dict, prefix: str = ""):
        """Recursively parse resources from a module."""
        
        # Parse direct resources
        for resource in module.get("resources", []):
            address = resource.get("address", "")
            
            self.resources[address] = PlannedResource(
                address=address,
                type=resource.get("type", ""),
                name=resource.get("name", ""),
                provider=resource.get("provider_name", ""),
                mode=resource.get("mode", "managed"),
                values=resource.get("values", {}),
                sensitive_values=resource.get("sensitive_values", {}),
                depends_on=resource.get("depends_on", [])
            )
        
        # Recursively parse child modules
        for child in module.get("child_modules", []):
            child_prefix = child.get("address", "")
            self._parse_module_resources(child, child_prefix)
    
    def _parse_resource_change(self, change: Dict):
        """Parse a resource change entry."""
        actions = change.get("change", {}).get("actions", [])
        
        # Determine change type
        if actions == ["create"]:
            change_type = "create"
        elif actions == ["delete"]:
            change_type = "delete"
        elif actions == ["update"] or actions == ["delete", "create"]:
            change_type = "update"
        else:
            change_type = "no-op"
        
        self.changes.append(ResourceChange(
            address=change.get("address", ""),
            type=change.get("type", ""),
            change_type=change_type,
            before=change.get("change", {}).get("before"),
            after=change.get("change", {}).get("after"),
            after_unknown=change.get("change", {}).get("after_unknown", {})
        ))
    
    def _build_graph(self) -> InfrastructureGraph:
        """Build InfrastructureGraph from parsed resources."""
        graph = InfrastructureGraph(name="terraform-plan")
        
        # First pass: Add all resources as nodes
        for address, resource in self.resources.items():
            node_type = self.RESOURCE_TYPE_MAP.get(resource.type, "unknown")
            
            # Check if public
            is_public = self._is_resource_public(resource)
            
            # Check if contains sensitive data
            contains_sensitive = self._contains_sensitive_data(resource)
            
            graph.add_resource(
                resource_id=address,
                resource_type=node_type,
                properties=resource.values,
                is_public=is_public,
                contains_sensitive_data=contains_sensitive
            )
        
        # Second pass: Add edges based on relationships
        self._add_relationship_edges(graph)
        
        return graph
    
    def _is_resource_public(self, resource: PlannedResource) -> bool:
        """Determine if a resource is publicly accessible."""
        values = resource.values
        
        # Check explicit public indicators
        for key, expected in self.PUBLIC_INDICATORS.items():
            if values.get(key) == expected:
                return True
        
        # Check security group rules for 0.0.0.0/0
        ingress_rules = values.get("ingress", [])
        if isinstance(ingress_rules, list):
            for rule in ingress_rules:
                if isinstance(rule, dict):
                    cidr_blocks = rule.get("cidr_blocks", [])
                    if "0.0.0.0/0" in cidr_blocks or "::/0" in cidr_blocks:
                        return True
        
        # Check for public bucket policies
        if resource.type == "aws_s3_bucket_policy":
            policy = values.get("policy", "")
            if isinstance(policy, str) and '"Principal": "*"' in policy:
                return True
        
        return False
    
    def _contains_sensitive_data(self, resource: PlannedResource) -> bool:
        """Determine if a resource likely contains sensitive data."""
        
        # Check resource type
        sensitive_types = {"rds", "dynamodb", "secrets_manager", "kms", "s3"}
        node_type = self.RESOURCE_TYPE_MAP.get(resource.type, "")
        if node_type in sensitive_types:
            return True
        
        # Check tags for sensitivity indicators
        tags = resource.values.get("tags", {}) or {}
        for key, value in tags.items():
            combined = f"{key} {value}".lower()
            if any(ind in combined for ind in self.SENSITIVE_INDICATORS):
                return True
        
        # Check resource name
        name_lower = resource.name.lower()
        if any(ind in name_lower for ind in self.SENSITIVE_INDICATORS):
            return True
        
        return False
    
    def _add_relationship_edges(self, graph: InfrastructureGraph):
        """Add edges based on resource relationships."""
        
        for address, resource in self.resources.items():
            values = resource.values
            
            # Handle explicit depends_on
            for dep in resource.depends_on:
                if dep in self.resources:
                    graph.add_permission(dep, address, "depends_on")
            
            # Handle IAM role attachments
            if resource.type == "aws_iam_role_policy_attachment":
                role = values.get("role", "")
                # Find the role resource
                role_address = self._find_resource_by_name("aws_iam_role", role)
                if role_address:
                    graph.add_permission(role_address, address, "policy_attached")
            
            # Handle instance profiles
            if resource.type == "aws_iam_instance_profile":
                role = values.get("role", "")
                role_address = self._find_resource_by_name("aws_iam_role", role)
                if role_address:
                    graph.add_permission(role_address, address, "instance_profile")
            
            # Handle security group associations
            if "vpc_security_group_ids" in values:
                for sg_id in values.get("vpc_security_group_ids", []):
                    sg_address = self._find_resource_by_id(sg_id)
                    if sg_address:
                        graph.add_permission(sg_address, address, "network_access")
            
            # Handle Lambda function roles
            if resource.type == "aws_lambda_function":
                role_arn = values.get("role", "")
                role_address = self._find_resource_by_arn(role_arn)
                if role_address:
                    graph.add_permission(role_address, address, "execution_role")
            
            # Handle EC2 instance profiles
            if resource.type == "aws_instance":
                profile = values.get("iam_instance_profile", "")
                if profile:
                    profile_address = self._find_resource_by_name(
                        "aws_iam_instance_profile", profile
                    )
                    if profile_address:
                        graph.add_permission(profile_address, address, "instance_profile")
    
    def _find_resource_by_name(self, resource_type: str, name: str) -> Optional[str]:
        """Find a resource address by type and name."""
        for address, resource in self.resources.items():
            if resource.type == resource_type and resource.name == name:
                return address
        return None
    
    def _find_resource_by_id(self, resource_id: str) -> Optional[str]:
        """Find a resource address by its ID (in values)."""
        for address, resource in self.resources.items():
            if resource.values.get("id") == resource_id:
                return address
        return None
    
    def _find_resource_by_arn(self, arn: str) -> Optional[str]:
        """Find a resource address by ARN reference."""
        # ARN references often contain the resource address
        for address, resource in self.resources.items():
            if address in arn or resource.values.get("arn") == arn:
                return address
        return None


def analyze_plan(plan_path: str) -> Tuple[InfrastructureGraph, List[ResourceChange]]:
    """
    Main entry point for analyzing a terraform plan.
    
    Args:
        plan_path: Path to tfplan.json file
        
    Returns:
        Tuple of (InfrastructureGraph, List of changes)
    """
    analyzer = TerraformPlanAnalyzer()
    return analyzer.parse_plan_file(plan_path)


def main():
    """CLI entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Lateryx Plan Analyzer - Parse terraform plan JSON"
    )
    parser.add_argument("plan_file", help="Path to tfplan.json")
    parser.add_argument("--output", "-o", help="Output graph JSON file")
    
    args = parser.parse_args()
    
    graph, changes = analyze_plan(args.plan_file)
    
    print(f"Parsed {len(graph.graph.nodes)} resources")
    print(f"Found {len(changes)} changes:")
    for change in changes:
        print(f"  [{change.change_type.upper()}] {change.address}")
    
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(graph.to_dict(), f, indent=2)
        print(f"\nGraph saved to {args.output}")


if __name__ == "__main__":
    main()
