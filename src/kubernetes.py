#!/usr/bin/env python3
"""
Lateryx Kubernetes Security Scanner
====================================
Analyzes Kubernetes manifests, Helm charts, and Kustomize configurations
for security issues and attack paths.
"""

import os
import re
import json
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

from .main import InfrastructureGraph


@dataclass
class K8sResource:
    """Represents a Kubernetes resource."""
    kind: str
    name: str
    namespace: str
    api_version: str
    spec: Dict
    is_privileged: bool = False
    has_host_network: bool = False
    has_host_pid: bool = False
    exposed_ports: List[int] = field(default_factory=list)
    service_account: str = "default"
    secrets_mounted: List[str] = field(default_factory=list)


class KubernetesParser:
    """Parse Kubernetes manifests into security-analyzable structures."""
    
    # Risk scores for different resource types
    RESOURCE_WEIGHTS = {
        "Secret": 0.9,
        "ConfigMap": 0.3,
        "ServiceAccount": 0.5,
        "Role": 0.4,
        "ClusterRole": 0.7,
        "RoleBinding": 0.5,
        "ClusterRoleBinding": 0.8,
        "Pod": 0.4,
        "Deployment": 0.4,
        "StatefulSet": 0.5,
        "DaemonSet": 0.6,
        "Service": 0.3,
        "Ingress": 0.5,
        "NetworkPolicy": 0.2,
        "PersistentVolumeClaim": 0.4,
    }
    
    # Dangerous configurations
    SECURITY_ISSUES = {
        "privileged_container": {
            "severity": "CRITICAL",
            "description": "Container runs as privileged, granting full host access",
            "remediation": "Set securityContext.privileged to false"
        },
        "host_network": {
            "severity": "HIGH",
            "description": "Pod uses host network namespace",
            "remediation": "Set hostNetwork to false unless absolutely required"
        },
        "host_pid": {
            "severity": "HIGH",
            "description": "Pod shares host PID namespace",
            "remediation": "Set hostPID to false"
        },
        "run_as_root": {
            "severity": "HIGH",
            "description": "Container runs as root user",
            "remediation": "Set securityContext.runAsNonRoot to true"
        },
        "no_resource_limits": {
            "severity": "MEDIUM",
            "description": "Container has no resource limits defined",
            "remediation": "Define resources.limits for CPU and memory"
        },
        "default_service_account": {
            "severity": "MEDIUM",
            "description": "Pod uses default service account",
            "remediation": "Create and use a dedicated service account with minimal permissions"
        },
        "secrets_in_env": {
            "severity": "HIGH",
            "description": "Secrets exposed via environment variables",
            "remediation": "Mount secrets as files instead of environment variables"
        },
        "no_network_policy": {
            "severity": "MEDIUM",
            "description": "Namespace has no NetworkPolicy defined",
            "remediation": "Define NetworkPolicy to restrict pod-to-pod communication"
        },
        "wildcard_rbac": {
            "severity": "CRITICAL",
            "description": "RBAC rule uses wildcard (*) permissions",
            "remediation": "Specify explicit resources and verbs instead of wildcards"
        },
        "cluster_admin_binding": {
            "severity": "CRITICAL",
            "description": "ClusterRoleBinding grants cluster-admin privileges",
            "remediation": "Use more restrictive ClusterRole instead of cluster-admin"
        },
    }
    
    def parse_yaml_file(self, file_path: str) -> List[K8sResource]:
        """Parse a YAML file containing Kubernetes manifests."""
        if not YAML_AVAILABLE:
            return []
        
        resources = []
        
        try:
            with open(file_path, 'r') as f:
                content = f.read()
            
            # Handle multi-document YAML
            docs = list(yaml.safe_load_all(content))
            
            for doc in docs:
                if doc and isinstance(doc, dict):
                    resource = self._parse_manifest(doc)
                    if resource:
                        resources.append(resource)
        except Exception as e:
            pass
        
        return resources
    
    def _parse_manifest(self, manifest: Dict) -> Optional[K8sResource]:
        """Parse a single Kubernetes manifest."""
        kind = manifest.get("kind", "")
        metadata = manifest.get("metadata", {})
        spec = manifest.get("spec", {})
        
        if not kind or not metadata:
            return None
        
        resource = K8sResource(
            kind=kind,
            name=metadata.get("name", "unknown"),
            namespace=metadata.get("namespace", "default"),
            api_version=manifest.get("apiVersion", ""),
            spec=spec
        )
        
        # Analyze security properties
        self._analyze_security(resource, manifest)
        
        return resource
    
    def _analyze_security(self, resource: K8sResource, manifest: Dict):
        """Analyze security properties of a resource."""
        spec = manifest.get("spec", {})
        
        if resource.kind in ["Pod", "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob"]:
            # Get pod spec
            pod_spec = spec
            if resource.kind != "Pod":
                pod_spec = spec.get("template", {}).get("spec", {})
            
            # Check host namespaces
            resource.has_host_network = pod_spec.get("hostNetwork", False)
            resource.has_host_pid = pod_spec.get("hostPID", False)
            
            # Check service account
            resource.service_account = pod_spec.get("serviceAccountName", "default")
            
            # Analyze containers
            containers = pod_spec.get("containers", []) + pod_spec.get("initContainers", [])
            
            for container in containers:
                security_context = container.get("securityContext", {})
                
                if security_context.get("privileged", False):
                    resource.is_privileged = True
                
                # Check for secret env vars
                env_vars = container.get("env", [])
                for env in env_vars:
                    if "valueFrom" in env and "secretKeyRef" in env.get("valueFrom", {}):
                        secret_name = env["valueFrom"]["secretKeyRef"].get("name", "")
                        if secret_name:
                            resource.secrets_mounted.append(secret_name)
                
                # Check volume mounts for secrets
                volume_mounts = container.get("volumeMounts", [])
                volumes = pod_spec.get("volumes", [])
                
                for volume in volumes:
                    if "secret" in volume:
                        resource.secrets_mounted.append(volume["secret"].get("secretName", ""))
        
        elif resource.kind == "Service":
            # Check for exposed ports
            ports = spec.get("ports", [])
            for port in ports:
                resource.exposed_ports.append(port.get("port", 0))
            
            # Check if LoadBalancer (public)
            if spec.get("type") == "LoadBalancer":
                resource.exposed_ports.append(-1)  # Marker for public exposure
    
    def get_security_findings(self, resources: List[K8sResource]) -> List[Dict]:
        """Analyze resources and return security findings."""
        findings = []
        
        for resource in resources:
            if resource.is_privileged:
                findings.append({
                    "resource": f"{resource.kind}/{resource.name}",
                    "namespace": resource.namespace,
                    **self.SECURITY_ISSUES["privileged_container"]
                })
            
            if resource.has_host_network:
                findings.append({
                    "resource": f"{resource.kind}/{resource.name}",
                    "namespace": resource.namespace,
                    **self.SECURITY_ISSUES["host_network"]
                })
            
            if resource.has_host_pid:
                findings.append({
                    "resource": f"{resource.kind}/{resource.name}",
                    "namespace": resource.namespace,
                    **self.SECURITY_ISSUES["host_pid"]
                })
            
            if resource.service_account == "default" and resource.kind in ["Pod", "Deployment"]:
                findings.append({
                    "resource": f"{resource.kind}/{resource.name}",
                    "namespace": resource.namespace,
                    **self.SECURITY_ISSUES["default_service_account"]
                })
            
            if resource.secrets_mounted:
                # Check if secrets are in env (vs file mounts)
                findings.append({
                    "resource": f"{resource.kind}/{resource.name}",
                    "namespace": resource.namespace,
                    "severity": "MEDIUM",
                    "description": f"Pod accesses secrets: {', '.join(resource.secrets_mounted)}",
                    "remediation": "Ensure secrets are rotated regularly and access is audited"
                })
        
        return findings


class KubernetesScanner:
    """Scan Kubernetes manifests in a directory."""
    
    def __init__(self):
        self.parser = KubernetesParser()
    
    def scan_directory(self, directory: str) -> Tuple[List[K8sResource], List[Dict]]:
        """
        Scan a directory for Kubernetes manifests.
        
        Returns:
            Tuple of (resources, findings)
        """
        all_resources = []
        dir_path = Path(directory)
        
        if not dir_path.exists():
            return [], []
        
        # Find all YAML files
        yaml_files = list(dir_path.glob("**/*.yaml")) + list(dir_path.glob("**/*.yml"))
        
        for yaml_file in yaml_files:
            # Skip helm template directories and tests
            if "templates" in str(yaml_file) and "helm" in str(yaml_file).lower():
                continue
            if "test" in str(yaml_file).lower():
                continue
            
            resources = self.parser.parse_yaml_file(str(yaml_file))
            all_resources.extend(resources)
        
        # Get security findings
        findings = self.parser.get_security_findings(all_resources)
        
        return all_resources, findings
    
    def build_graph(self, resources: List[K8sResource]) -> InfrastructureGraph:
        """Build an infrastructure graph from Kubernetes resources."""
        graph = InfrastructureGraph(name="kubernetes-cluster")
        
        # Track namespaces
        namespaces = set()
        
        for resource in resources:
            namespaces.add(resource.namespace)
            
            # Determine if public/sensitive
            is_public = -1 in resource.exposed_ports  # LoadBalancer
            is_sensitive = resource.kind == "Secret" or len(resource.secrets_mounted) > 0
            
            # Add resource node
            graph.add_resource(
                resource_id=f"k8s.{resource.namespace}.{resource.kind}.{resource.name}",
                resource_type=resource.kind.lower(),
                properties={"spec": resource.spec},
                is_public=is_public,
                contains_sensitive_data=is_sensitive
            )
            
            # Add service account relationships
            if resource.service_account and resource.service_account != "default":
                sa_id = f"k8s.{resource.namespace}.ServiceAccount.{resource.service_account}"
                if sa_id in graph.graph:
                    graph.add_permission(
                        sa_id,
                        f"k8s.{resource.namespace}.{resource.kind}.{resource.name}",
                        "assume_role"
                    )
            
            # Add secret access relationships
            for secret in resource.secrets_mounted:
                secret_id = f"k8s.{resource.namespace}.Secret.{secret}"
                graph.add_permission(
                    f"k8s.{resource.namespace}.{resource.kind}.{resource.name}",
                    secret_id,
                    "read"
                )
        
        return graph


def get_kubernetes_scanner() -> KubernetesScanner:
    """Get a configured Kubernetes scanner."""
    return KubernetesScanner()
