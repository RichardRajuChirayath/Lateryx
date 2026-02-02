#!/usr/bin/env python3
"""
Lateryx Cloud State Sync
========================
Pulls live infrastructure state from cloud APIs to identify drift
and runtime vulnerabilities that don't exist in the Terraform code.

Supports:
- AWS (via boto3)
- Azure (via azure-identity)
- GCP (via google-cloud)
"""

import json
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Dict, List, Optional

from .main import InfrastructureGraph


@dataclass
class CloudResource:
    """Represents a live cloud resource."""
    resource_id: str
    resource_type: str
    arn: Optional[str]
    region: str
    tags: Dict[str, str]
    properties: Dict
    is_public: bool = False
    contains_sensitive: bool = False


class CloudProvider(ABC):
    """Abstract base class for cloud providers."""
    
    @abstractmethod
    def list_resources(self) -> List[CloudResource]:
        """List all resources in the account/subscription."""
        pass
    
    @abstractmethod
    def get_resource_permissions(self, resource_id: str) -> List[Dict]:
        """Get permissions attached to a resource."""
        pass
    
    @abstractmethod
    def build_graph(self) -> InfrastructureGraph:
        """Build complete infrastructure graph from live state."""
        pass


class AWSCloudSync(CloudProvider):
    """
    Syncs infrastructure state from AWS using boto3.
    
    Supported resources:
    - EC2 instances
    - S3 buckets
    - RDS instances
    - Lambda functions
    - IAM roles
    - Security groups
    - Load balancers
    """
    
    SENSITIVE_SERVICES = {"rds", "dynamodb", "secretsmanager", "s3"}
    
    def __init__(self, session=None, regions: List[str] = None):
        """
        Initialize AWS sync.
        
        Args:
            session: Optional boto3.Session (uses default if None)
            regions: List of regions to scan (uses all if None)
        """
        self.session = session
        self.regions = regions or ["us-east-1"]
        self.resources: List[CloudResource] = []
        
    def list_resources(self) -> List[CloudResource]:
        """List all resources across configured regions."""
        try:
            import boto3
        except ImportError:
            print("Warning: boto3 not installed. Install with: pip install boto3")
            return []
        
        if not self.session:
            self.session = boto3.Session()
        
        self.resources = []
        
        for region in self.regions:
            self._scan_ec2(region)
            self._scan_s3(region)
            self._scan_rds(region)
            self._scan_lambda(region)
            self._scan_iam()  # IAM is global
        
        return self.resources
    
    def _scan_ec2(self, region: str):
        """Scan EC2 instances and security groups."""
        ec2 = self.session.client("ec2", region_name=region)
        
        # Instances
        try:
            instances = ec2.describe_instances()
            for reservation in instances.get("Reservations", []):
                for instance in reservation.get("Instances", []):
                    tags = {t["Key"]: t["Value"] for t in instance.get("Tags", [])}
                    
                    # Check if public
                    is_public = bool(instance.get("PublicIpAddress"))
                    
                    self.resources.append(CloudResource(
                        resource_id=instance["InstanceId"],
                        resource_type="ec2",
                        arn=f"arn:aws:ec2:{region}::instance/{instance['InstanceId']}",
                        region=region,
                        tags=tags,
                        properties={
                            "state": instance.get("State", {}).get("Name"),
                            "instance_type": instance.get("InstanceType"),
                            "vpc_id": instance.get("VpcId"),
                            "subnet_id": instance.get("SubnetId"),
                            "security_groups": [
                                sg["GroupId"] for sg in instance.get("SecurityGroups", [])
                            ],
                            "iam_instance_profile": instance.get("IamInstanceProfile", {}).get("Arn")
                        },
                        is_public=is_public
                    ))
        except Exception as e:
            print(f"Warning: Could not scan EC2 in {region}: {e}")
        
        # Security Groups
        try:
            sgs = ec2.describe_security_groups()
            for sg in sgs.get("SecurityGroups", []):
                # Check if allows public ingress
                is_public = False
                for rule in sg.get("IpPermissions", []):
                    for ip_range in rule.get("IpRanges", []):
                        if ip_range.get("CidrIp") == "0.0.0.0/0":
                            is_public = True
                            break
                
                self.resources.append(CloudResource(
                    resource_id=sg["GroupId"],
                    resource_type="security_group",
                    arn=f"arn:aws:ec2:{region}::security-group/{sg['GroupId']}",
                    region=region,
                    tags={t["Key"]: t["Value"] for t in sg.get("Tags", [])},
                    properties={
                        "name": sg.get("GroupName"),
                        "vpc_id": sg.get("VpcId"),
                        "ingress_rules": sg.get("IpPermissions", []),
                        "egress_rules": sg.get("IpPermissionsEgress", [])
                    },
                    is_public=is_public
                ))
        except Exception as e:
            print(f"Warning: Could not scan Security Groups in {region}: {e}")
    
    def _scan_s3(self, region: str):
        """Scan S3 buckets."""
        # S3 is global but we only scan once
        if region != self.regions[0]:
            return
            
        s3 = self.session.client("s3")
        
        try:
            buckets = s3.list_buckets()
            for bucket in buckets.get("Buckets", []):
                bucket_name = bucket["Name"]
                
                # Check public access
                is_public = False
                try:
                    public_access = s3.get_public_access_block(Bucket=bucket_name)
                    config = public_access.get("PublicAccessBlockConfiguration", {})
                    if not all([
                        config.get("BlockPublicAcls", False),
                        config.get("BlockPublicPolicy", False),
                        config.get("IgnorePublicAcls", False),
                        config.get("RestrictPublicBuckets", False)
                    ]):
                        is_public = True
                except:
                    is_public = True  # Assume public if we can't check
                
                # Get tags
                tags = {}
                try:
                    tag_response = s3.get_bucket_tagging(Bucket=bucket_name)
                    tags = {t["Key"]: t["Value"] for t in tag_response.get("TagSet", [])}
                except:
                    pass
                
                self.resources.append(CloudResource(
                    resource_id=bucket_name,
                    resource_type="s3",
                    arn=f"arn:aws:s3:::{bucket_name}",
                    region="global",
                    tags=tags,
                    properties={"creation_date": str(bucket.get("CreationDate"))},
                    is_public=is_public,
                    contains_sensitive=True  # S3 often contains sensitive data
                ))
        except Exception as e:
            print(f"Warning: Could not scan S3: {e}")
    
    def _scan_rds(self, region: str):
        """Scan RDS instances."""
        rds = self.session.client("rds", region_name=region)
        
        try:
            instances = rds.describe_db_instances()
            for db in instances.get("DBInstances", []):
                self.resources.append(CloudResource(
                    resource_id=db["DBInstanceIdentifier"],
                    resource_type="rds",
                    arn=db.get("DBInstanceArn"),
                    region=region,
                    tags={t["Key"]: t["Value"] for t in db.get("TagList", [])},
                    properties={
                        "engine": db.get("Engine"),
                        "status": db.get("DBInstanceStatus"),
                        "publicly_accessible": db.get("PubliclyAccessible", False),
                        "encrypted": db.get("StorageEncrypted", False),
                        "vpc_security_groups": [
                            sg["VpcSecurityGroupId"] 
                            for sg in db.get("VpcSecurityGroups", [])
                        ]
                    },
                    is_public=db.get("PubliclyAccessible", False),
                    contains_sensitive=True
                ))
        except Exception as e:
            print(f"Warning: Could not scan RDS in {region}: {e}")
    
    def _scan_lambda(self, region: str):
        """Scan Lambda functions."""
        lambda_client = self.session.client("lambda", region_name=region)
        
        try:
            functions = lambda_client.list_functions()
            for func in functions.get("Functions", []):
                # Check for public access via function URL
                is_public = False
                try:
                    url_config = lambda_client.get_function_url_config(
                        FunctionName=func["FunctionName"]
                    )
                    if url_config.get("AuthType") == "NONE":
                        is_public = True
                except:
                    pass
                
                self.resources.append(CloudResource(
                    resource_id=func["FunctionName"],
                    resource_type="lambda",
                    arn=func.get("FunctionArn"),
                    region=region,
                    tags=func.get("Tags", {}),
                    properties={
                        "runtime": func.get("Runtime"),
                        "role": func.get("Role"),
                        "handler": func.get("Handler"),
                        "memory_size": func.get("MemorySize"),
                        "timeout": func.get("Timeout")
                    },
                    is_public=is_public
                ))
        except Exception as e:
            print(f"Warning: Could not scan Lambda in {region}: {e}")
    
    def _scan_iam(self):
        """Scan IAM roles (global)."""
        iam = self.session.client("iam")
        
        try:
            roles = iam.list_roles()
            for role in roles.get("Roles", []):
                self.resources.append(CloudResource(
                    resource_id=role["RoleName"],
                    resource_type="iam_role",
                    arn=role.get("Arn"),
                    region="global",
                    tags={t["Key"]: t["Value"] for t in role.get("Tags", [])},
                    properties={
                        "path": role.get("Path"),
                        "assume_role_policy": role.get("AssumeRolePolicyDocument"),
                        "max_session_duration": role.get("MaxSessionDuration")
                    }
                ))
        except Exception as e:
            print(f"Warning: Could not scan IAM: {e}")
    
    def get_resource_permissions(self, resource_id: str) -> List[Dict]:
        """Get permissions for a specific resource."""
        # Implementation depends on resource type
        return []
    
    def build_graph(self) -> InfrastructureGraph:
        """Build infrastructure graph from live AWS resources."""
        if not self.resources:
            self.list_resources()
        
        graph = InfrastructureGraph(name="aws-live")
        
        # Add all resources as nodes
        for resource in self.resources:
            graph.add_resource(
                resource_id=resource.arn or resource.resource_id,
                resource_type=resource.resource_type,
                properties=resource.properties,
                is_public=resource.is_public,
                contains_sensitive_data=resource.contains_sensitive
            )
        
        # Add edges based on relationships
        for resource in self.resources:
            self._add_resource_edges(graph, resource)
        
        return graph
    
    def _add_resource_edges(self, graph: InfrastructureGraph, resource: CloudResource):
        """Add edges for a resource based on its relationships."""
        props = resource.properties
        resource_id = resource.arn or resource.resource_id
        
        # EC2 -> Security Groups
        if resource.resource_type == "ec2":
            for sg_id in props.get("security_groups", []):
                sg_node = self._find_resource_node(sg_id)
                if sg_node:
                    graph.add_permission(sg_node, resource_id, "network_access")
            
            # EC2 -> IAM Instance Profile
            profile_arn = props.get("iam_instance_profile")
            if profile_arn:
                graph.add_permission(profile_arn, resource_id, "instance_profile")
        
        # Lambda -> IAM Role
        if resource.resource_type == "lambda":
            role_arn = props.get("role")
            if role_arn:
                graph.add_permission(role_arn, resource_id, "execution_role")
        
        # RDS -> Security Groups
        if resource.resource_type == "rds":
            for sg_id in props.get("vpc_security_groups", []):
                sg_node = self._find_resource_node(sg_id)
                if sg_node:
                    graph.add_permission(sg_node, resource_id, "network_access")
    
    def _find_resource_node(self, resource_id: str) -> Optional[str]:
        """Find a resource's graph node ID."""
        for resource in self.resources:
            if resource.resource_id == resource_id:
                return resource.arn or resource.resource_id
        return None


def sync_aws_state(regions: List[str] = None, 
                   output_file: str = None) -> InfrastructureGraph:
    """
    Main entry point for AWS state sync.
    
    Args:
        regions: List of AWS regions to scan
        output_file: Optional file to save graph JSON
        
    Returns:
        InfrastructureGraph from live AWS state
    """
    sync = AWSCloudSync(regions=regions)
    graph = sync.build_graph()
    
    if output_file:
        with open(output_file, 'w') as f:
            json.dump(graph.to_dict(), f, indent=2)
    
    return graph


def compare_live_to_plan(live_graph: InfrastructureGraph, 
                         plan_graph: InfrastructureGraph) -> Dict:
    """
    Compare live infrastructure to planned infrastructure.
    
    Returns:
        Dictionary with drift analysis
    """
    live_nodes = set(live_graph.graph.nodes())
    plan_nodes = set(plan_graph.graph.nodes())
    
    # Find drift
    only_in_live = live_nodes - plan_nodes  # Resources created outside Terraform
    only_in_plan = plan_nodes - live_nodes  # Resources not yet created
    
    # Check for configuration drift
    config_drift = []
    for node in live_nodes & plan_nodes:
        live_data = live_graph.graph.nodes[node]
        plan_data = plan_graph.graph.nodes[node]
        
        if live_data.get("is_public") != plan_data.get("is_public"):
            config_drift.append({
                "resource": node,
                "attribute": "is_public",
                "live": live_data.get("is_public"),
                "planned": plan_data.get("is_public")
            })
    
    return {
        "unmanaged_resources": list(only_in_live),
        "pending_resources": list(only_in_plan),
        "configuration_drift": config_drift,
        "drift_detected": bool(only_in_live or config_drift)
    }
