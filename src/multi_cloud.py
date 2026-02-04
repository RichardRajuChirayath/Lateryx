#!/usr/bin/env python3
"""
Lateryx Multi-Cloud Parser
===========================
Extends Lateryx to support Azure and GCP infrastructure.
Parses Terraform resources for all major cloud providers.
"""

from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from .main import InfrastructureGraph


@dataclass
class CloudResource:
    """Unified cloud resource representation."""
    provider: str  # aws, azure, gcp
    resource_type: str
    resource_id: str
    is_public: bool = False
    contains_sensitive_data: bool = False
    properties: Dict = None


class AzureParser:
    """Parse Azure Terraform resources into the infrastructure graph."""
    
    # Azure resource type to graph node type mapping
    RESOURCE_TYPES = {
        "azurerm_storage_account": "storage",
        "azurerm_storage_blob": "storage",
        "azurerm_storage_container": "storage",
        "azurerm_sql_server": "database",
        "azurerm_sql_database": "database",
        "azurerm_cosmosdb_account": "database",
        "azurerm_key_vault": "secrets",
        "azurerm_key_vault_secret": "secrets",
        "azurerm_virtual_machine": "compute",
        "azurerm_linux_virtual_machine": "compute",
        "azurerm_windows_virtual_machine": "compute",
        "azurerm_kubernetes_cluster": "kubernetes",
        "azurerm_function_app": "serverless",
        "azurerm_app_service": "compute",
        "azurerm_network_security_group": "firewall",
        "azurerm_public_ip": "network",
        "azurerm_role_assignment": "iam",
        "azurerm_user_assigned_identity": "iam",
    }
    
    # Patterns that indicate public access
    PUBLIC_PATTERNS = {
        "azurerm_storage_account": ["public_network_access_enabled", "allow_blob_public_access"],
        "azurerm_sql_server": ["public_network_access_enabled"],
        "azurerm_cosmosdb_account": ["public_network_access_enabled", "is_virtual_network_filter_enabled"],
    }
    
    # Patterns that indicate sensitive data
    SENSITIVE_PATTERNS = {
        "azurerm_sql_database": True,
        "azurerm_cosmosdb_account": True,
        "azurerm_key_vault": True,
        "azurerm_key_vault_secret": True,
    }
    
    def parse_resource(self, resource_type: str, resource_name: str, 
                       config: Dict) -> Optional[CloudResource]:
        """Parse an Azure resource into a CloudResource object."""
        
        if resource_type not in self.RESOURCE_TYPES:
            return None
        
        node_type = self.RESOURCE_TYPES[resource_type]
        resource_id = f"azure.{resource_type}.{resource_name}"
        
        # Check for public access
        is_public = False
        if resource_type in self.PUBLIC_PATTERNS:
            for pattern in self.PUBLIC_PATTERNS[resource_type]:
                if config.get(pattern, False) in [True, "true", "Enabled"]:
                    is_public = True
                    break
        
        # Check for sensitive data
        contains_sensitive = self.SENSITIVE_PATTERNS.get(resource_type, False)
        
        return CloudResource(
            provider="azure",
            resource_type=node_type,
            resource_id=resource_id,
            is_public=is_public,
            contains_sensitive_data=contains_sensitive,
            properties=config
        )
    
    def extract_permissions(self, resource_type: str, resource_name: str,
                           config: Dict) -> List[Tuple[str, str, str]]:
        """Extract permission edges from Azure resources."""
        permissions = []
        
        if resource_type == "azurerm_role_assignment":
            principal = config.get("principal_id", "unknown_principal")
            scope = config.get("scope", "unknown_scope")
            role = config.get("role_definition_name", "Reader")
            
            # Map Azure roles to permission levels
            role_map = {
                "Owner": "admin",
                "Contributor": "write",
                "Reader": "read",
                "Storage Blob Data Owner": "admin",
                "Storage Blob Data Contributor": "write",
                "Storage Blob Data Reader": "read",
            }
            
            perm_type = role_map.get(role, "read")
            permissions.append((f"azure.principal.{principal}", scope, perm_type))
        
        return permissions


class GCPParser:
    """Parse GCP Terraform resources into the infrastructure graph."""
    
    RESOURCE_TYPES = {
        "google_storage_bucket": "storage",
        "google_storage_bucket_object": "storage",
        "google_sql_database_instance": "database",
        "google_sql_database": "database",
        "google_bigquery_dataset": "database",
        "google_bigquery_table": "database",
        "google_secret_manager_secret": "secrets",
        "google_kms_key_ring": "secrets",
        "google_kms_crypto_key": "secrets",
        "google_compute_instance": "compute",
        "google_compute_instance_template": "compute",
        "google_container_cluster": "kubernetes",
        "google_cloudfunctions_function": "serverless",
        "google_cloud_run_service": "serverless",
        "google_compute_firewall": "firewall",
        "google_compute_network": "network",
        "google_project_iam_binding": "iam",
        "google_project_iam_member": "iam",
        "google_service_account": "iam",
    }
    
    PUBLIC_PATTERNS = {
        "google_storage_bucket": ["uniform_bucket_level_access"],
        "google_sql_database_instance": ["settings.ip_configuration.ipv4_enabled"],
        "google_bigquery_dataset": ["access"],
    }
    
    SENSITIVE_PATTERNS = {
        "google_sql_database": True,
        "google_bigquery_dataset": True,
        "google_bigquery_table": True,
        "google_secret_manager_secret": True,
    }
    
    def parse_resource(self, resource_type: str, resource_name: str,
                       config: Dict) -> Optional[CloudResource]:
        """Parse a GCP resource into a CloudResource object."""
        
        if resource_type not in self.RESOURCE_TYPES:
            return None
        
        node_type = self.RESOURCE_TYPES[resource_type]
        resource_id = f"gcp.{resource_type}.{resource_name}"
        
        # Check for public access
        is_public = False
        if resource_type == "google_storage_bucket":
            # Check for allUsers or allAuthenticatedUsers in ACL
            acl = config.get("acl", [])
            if any("allUsers" in str(a) or "allAuthenticatedUsers" in str(a) for a in acl):
                is_public = True
        
        if resource_type == "google_sql_database_instance":
            # Check if public IP is enabled
            settings = config.get("settings", {})
            ip_config = settings.get("ip_configuration", {})
            if ip_config.get("ipv4_enabled", False):
                authorized_networks = ip_config.get("authorized_networks", [])
                if any(net.get("value") == "0.0.0.0/0" for net in authorized_networks):
                    is_public = True
        
        contains_sensitive = self.SENSITIVE_PATTERNS.get(resource_type, False)
        
        return CloudResource(
            provider="gcp",
            resource_type=node_type,
            resource_id=resource_id,
            is_public=is_public,
            contains_sensitive_data=contains_sensitive,
            properties=config
        )
    
    def extract_permissions(self, resource_type: str, resource_name: str,
                           config: Dict) -> List[Tuple[str, str, str]]:
        """Extract permission edges from GCP resources."""
        permissions = []
        
        if resource_type in ["google_project_iam_binding", "google_project_iam_member"]:
            role = config.get("role", "roles/viewer")
            members = config.get("members", [config.get("member", "")])
            
            # Map GCP roles to permission levels
            if "admin" in role.lower() or "owner" in role.lower():
                perm_type = "admin"
            elif "editor" in role.lower() or "writer" in role.lower():
                perm_type = "write"
            else:
                perm_type = "read"
            
            for member in members:
                if member:
                    permissions.append((f"gcp.{member}", f"gcp.project", perm_type))
        
        return permissions


class MultiCloudScanner:
    """
    Unified scanner that handles AWS, Azure, and GCP resources.
    """
    
    def __init__(self):
        self.azure_parser = AzureParser()
        self.gcp_parser = GCPParser()
    
    def detect_provider(self, resource_type: str) -> str:
        """Detect the cloud provider from resource type."""
        if resource_type.startswith("aws_"):
            return "aws"
        elif resource_type.startswith("azurerm_"):
            return "azure"
        elif resource_type.startswith("google_"):
            return "gcp"
        return "unknown"
    
    def parse_terraform_resources(self, resources: List[Dict]) -> InfrastructureGraph:
        """
        Parse a list of Terraform resources into an InfrastructureGraph.
        Supports AWS, Azure, and GCP.
        """
        graph = InfrastructureGraph(name="multi-cloud-infrastructure")
        
        for resource in resources:
            resource_type = resource.get("type", "")
            resource_name = resource.get("name", "")
            config = resource.get("values", resource.get("config", {}))
            
            provider = self.detect_provider(resource_type)
            
            if provider == "azure":
                cloud_resource = self.azure_parser.parse_resource(
                    resource_type, resource_name, config
                )
                if cloud_resource:
                    graph.add_resource(
                        resource_id=cloud_resource.resource_id,
                        resource_type=cloud_resource.resource_type,
                        properties=cloud_resource.properties,
                        is_public=cloud_resource.is_public,
                        contains_sensitive_data=cloud_resource.contains_sensitive_data
                    )
                
                # Extract and add permissions
                permissions = self.azure_parser.extract_permissions(
                    resource_type, resource_name, config
                )
                for source, target, perm_type in permissions:
                    if source in graph.graph and target in graph.graph:
                        graph.add_permission(source, target, perm_type)
            
            elif provider == "gcp":
                cloud_resource = self.gcp_parser.parse_resource(
                    resource_type, resource_name, config
                )
                if cloud_resource:
                    graph.add_resource(
                        resource_id=cloud_resource.resource_id,
                        resource_type=cloud_resource.resource_type,
                        properties=cloud_resource.properties,
                        is_public=cloud_resource.is_public,
                        contains_sensitive_data=cloud_resource.contains_sensitive_data
                    )
                
                permissions = self.gcp_parser.extract_permissions(
                    resource_type, resource_name, config
                )
                for source, target, perm_type in permissions:
                    if source in graph.graph and target in graph.graph:
                        graph.add_permission(source, target, perm_type)
        
        return graph


def get_multi_cloud_scanner() -> MultiCloudScanner:
    """Get a configured multi-cloud scanner."""
    return MultiCloudScanner()
