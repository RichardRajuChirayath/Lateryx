#!/usr/bin/env python3
"""
Lateryx Infrastructure Scanner
==============================
Parses Terraform/HCL files into infrastructure graphs using Checkov CLI.

This module:
1. Runs Checkov to parse Terraform files into structured JSON
2. Transforms Checkov output into Lateryx InfrastructureGraph format
3. Identifies public resources, sensitive data, and permission relationships
"""

import json
import os
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .main import InfrastructureGraph


@dataclass
class ScanResult:
    """Result of scanning Terraform files."""
    success: bool
    graph: Optional[InfrastructureGraph]
    errors: list[str]
    warnings: list[str]
    resources_count: int
    permissions_count: int


class TerraformScanner:
    """
    Scans Terraform files and converts them to InfrastructureGraph.
    
    Uses Checkov CLI for parsing Terraform/HCL files into JSON,
    then transforms the output into our graph representation.
    """
    
    # Resource types that are typically public-facing
    PUBLIC_RESOURCE_TYPES = {
        "aws_lb",
        "aws_alb",
        "aws_elb",
        "aws_api_gateway_rest_api",
        "aws_api_gateway_v2_api",
        "aws_cloudfront_distribution",
        "aws_route53_record",
        "aws_apigatewayv2_api",
    }
    
    # Resource types that typically contain sensitive data
    SENSITIVE_RESOURCE_TYPES = {
        "aws_s3_bucket",
        "aws_rds_cluster",
        "aws_db_instance",
        "aws_dynamodb_table",
        "aws_secretsmanager_secret",
        "aws_ssm_parameter",
        "aws_kms_key",
    }
    
    # Map Terraform resource types to Lateryx node types
    RESOURCE_TYPE_MAP = {
        "aws_s3_bucket": "s3",
        "aws_instance": "ec2",
        "aws_ecs_service": "ecs",
        "aws_ecs_cluster": "ecs",
        "aws_lambda_function": "lambda",
        "aws_iam_role": "iam_role",
        "aws_iam_user": "iam_user",
        "aws_iam_policy": "iam_role",
        "aws_lb": "alb",
        "aws_alb": "alb",
        "aws_elb": "alb",
        "aws_api_gateway_rest_api": "api_gateway",
        "aws_api_gateway_v2_api": "api_gateway",
        "aws_rds_cluster": "rds",
        "aws_db_instance": "rds",
        "aws_dynamodb_table": "dynamodb",
        "aws_secretsmanager_secret": "secrets_manager",
        "aws_kms_key": "kms",
    }
    
    def __init__(self, checkov_path: str = "checkov"):
        """
        Initialize scanner.
        
        Args:
            checkov_path: Path to checkov CLI executable
        """
        self.checkov_path = checkov_path
    
    def scan_directory(self, terraform_dir: str) -> ScanResult:
        """
        Scan a directory containing Terraform files.
        
        Args:
            terraform_dir: Path to directory containing .tf files
            
        Returns:
            ScanResult with the infrastructure graph
        """
        errors = []
        warnings = []
        
        # Validate directory exists
        if not os.path.isdir(terraform_dir):
            return ScanResult(
                success=False,
                graph=None,
                errors=[f"Directory not found: {terraform_dir}"],
                warnings=[],
                resources_count=0,
                permissions_count=0
            )
        
        # Run Checkov to parse Terraform
        try:
            checkov_output = self._run_checkov(terraform_dir)
        except Exception as e:
            return ScanResult(
                success=False,
                graph=None,
                errors=[f"Checkov execution failed: {str(e)}"],
                warnings=[],
                resources_count=0,
                permissions_count=0
            )
        
        # Parse Checkov output and build graph
        try:
            graph, resource_count, permission_count = self._build_graph_from_checkov(
                checkov_output, 
                terraform_dir
            )
        except Exception as e:
            return ScanResult(
                success=False,
                graph=None,
                errors=[f"Graph construction failed: {str(e)}"],
                warnings=warnings,
                resources_count=0,
                permissions_count=0
            )
        
        return ScanResult(
            success=True,
            graph=graph,
            errors=errors,
            warnings=warnings,
            resources_count=resource_count,
            permissions_count=permission_count
        )
    
    def scan_file(self, terraform_file: str) -> ScanResult:
        """
        Scan a single Terraform file.
        
        Args:
            terraform_file: Path to .tf file
            
        Returns:
            ScanResult with the infrastructure graph
        """
        return self.scan_directory(os.path.dirname(terraform_file))
    
    def _run_checkov(self, terraform_dir: str) -> dict:
        """
        Run Checkov CLI to parse Terraform files.
        
        Uses Checkov's JSON output format for structured parsing.
        """
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            output_file = f.name
        
        try:
            # Run Checkov with JSON output
            cmd = [
                self.checkov_path,
                "-d", terraform_dir,
                "--framework", "terraform",
                "--output", "json",
                "--output-file-path", os.path.dirname(output_file),
                "--compact",
                "--quiet"
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            
            # Checkov exits with non-zero for policy failures, which is fine
            # We just want the parsed resources
            
            # Read the output file
            checkov_result_file = os.path.join(
                os.path.dirname(output_file),
                "results_json.json"
            )
            
            if os.path.exists(checkov_result_file):
                with open(checkov_result_file, 'r') as f:
                    return json.load(f)
            
            # Fall back to parsing directly
            return self._parse_terraform_directly(terraform_dir)
            
        except subprocess.TimeoutExpired:
            raise RuntimeError("Checkov execution timed out")
        except FileNotFoundError:
            # Checkov not installed, fall back to direct parsing
            return self._parse_terraform_directly(terraform_dir)
        finally:
            # Cleanup temp files
            for f in [output_file, output_file.replace('.json', '_json.json')]:
                if os.path.exists(f):
                    os.unlink(f)
    
    def _parse_terraform_directly(self, terraform_dir: str) -> dict:
        """
        Parse Terraform files directly without Checkov.
        
        This is a fallback for when Checkov is not available.
        Uses basic HCL parsing to extract resources.
        """
        resources = []
        
        # Find all .tf files
        tf_files = list(Path(terraform_dir).glob("**/*.tf"))
        
        for tf_file in tf_files:
            file_resources = self._parse_tf_file(tf_file)
            resources.extend(file_resources)
        
        return {"resources": resources}
    
    def _parse_tf_file(self, tf_file: Path) -> list[dict]:
        """
        Parse a single Terraform file to extract resources.
        
        This is a simplified parser that handles common patterns.
        For production use, consider using pyhcl2 or similar.
        """
        resources = []
        content = tf_file.read_text()
        
        # Simple regex-based parsing for resource blocks
        import re
        
        # Match resource blocks: resource "type" "name" { ... }
        resource_pattern = r'resource\s+"([^"]+)"\s+"([^"]+)"\s*\{([^}]*(?:\{[^}]*\}[^}]*)*)\}'
        
        for match in re.finditer(resource_pattern, content, re.DOTALL):
            resource_type = match.group(1)
            resource_name = match.group(2)
            resource_body = match.group(3)
            
            # Parse resource properties
            properties = self._parse_resource_body(resource_body)
            
            resources.append({
                "type": resource_type,
                "name": resource_name,
                "file_path": str(tf_file),
                "properties": properties
            })
        
        # Match data blocks: data "type" "name" { ... }
        data_pattern = r'data\s+"([^"]+)"\s+"([^"]+)"\s*\{([^}]*(?:\{[^}]*\}[^}]*)*)\}'
        
        for match in re.finditer(data_pattern, content, re.DOTALL):
            data_type = match.group(1)
            data_name = match.group(2)
            
            resources.append({
                "type": f"data.{data_type}",
                "name": data_name,
                "file_path": str(tf_file),
                "properties": {}
            })
        
        return resources
    
    def _parse_resource_body(self, body: str) -> dict:
        """Parse resource body to extract key properties."""
        import re
        
        properties = {}
        
        # Check for public access patterns
        if re.search(r'(public|0\.0\.0\.0/0|::/0)', body, re.IGNORECASE):
            properties['is_public'] = True
        
        # Check for sensitive data patterns
        if re.search(r'(secret|password|key|token|credential)', body, re.IGNORECASE):
            properties['contains_sensitive'] = True
        
        # Extract tags
        tags_match = re.search(r'tags\s*=\s*\{([^}]+)\}', body)
        if tags_match:
            properties['has_tags'] = True
        
        # Check for encryption
        if re.search(r'encrypt|kms', body, re.IGNORECASE):
            properties['encrypted'] = True
        
        # Check for IAM role references
        role_matches = re.findall(r'aws_iam_role\.(\w+)', body)
        if role_matches:
            properties['iam_roles'] = role_matches
        
        # Check for S3 bucket references
        s3_matches = re.findall(r'aws_s3_bucket\.(\w+)', body)
        if s3_matches:
            properties['s3_buckets'] = s3_matches
        
        return properties
    
    def _build_graph_from_checkov(self, checkov_output: dict, 
                                   terraform_dir: str) -> tuple[InfrastructureGraph, int, int]:
        """
        Build InfrastructureGraph from Checkov output.
        
        Transforms Checkov's parsed resources into our graph format,
        identifying nodes (resources) and edges (permissions).
        """
        graph = InfrastructureGraph(name=os.path.basename(terraform_dir))
        
        resources = checkov_output.get("resources", [])
        
        # Also check for results from Checkov scan output
        if "results" in checkov_output:
            for check_type in ["passed_checks", "failed_checks"]:
                for check in checkov_output["results"].get(check_type, []):
                    if "resource" in check:
                        resources.append({
                            "type": check.get("resource_type", "unknown"),
                            "name": check.get("resource", "unknown"),
                            "properties": {}
                        })
        
        # Track resources for edge creation
        resource_map = {}
        permission_count = 0
        
        # First pass: Create all nodes
        for resource in resources:
            resource_type = resource.get("type", "unknown")
            resource_name = resource.get("name", "unknown")
            resource_id = f"{resource_type}.{resource_name}"
            
            # Determine node type
            node_type = self.RESOURCE_TYPE_MAP.get(resource_type, "unknown")
            
            # Check if public
            is_public = (
                resource_type in self.PUBLIC_RESOURCE_TYPES or
                resource.get("properties", {}).get("is_public", False)
            )
            
            # Check if contains sensitive data
            contains_sensitive = (
                resource_type in self.SENSITIVE_RESOURCE_TYPES or
                resource.get("properties", {}).get("contains_sensitive", False)
            )
            
            # Add to graph
            graph.add_resource(
                resource_id=resource_id,
                resource_type=node_type,
                properties=resource.get("properties", {}),
                is_public=is_public,
                contains_sensitive_data=contains_sensitive
            )
            
            resource_map[resource_id] = resource
        
        # Second pass: Create edges based on relationships
        for resource in resources:
            resource_type = resource.get("type", "unknown")
            resource_name = resource.get("name", "unknown")
            source_id = f"{resource_type}.{resource_name}"
            properties = resource.get("properties", {})
            
            # Handle IAM role relationships
            for role_name in properties.get("iam_roles", []):
                target_id = f"aws_iam_role.{role_name}"
                if target_id in resource_map:
                    graph.add_permission(source_id, target_id, "assume_role")
                    permission_count += 1
            
            # Handle S3 bucket access
            for bucket_name in properties.get("s3_buckets", []):
                target_id = f"aws_s3_bucket.{bucket_name}"
                if target_id in resource_map:
                    graph.add_permission(source_id, target_id, "read")
                    permission_count += 1
            
            # IAM roles can access resources they're attached to
            if resource_type == "aws_iam_role_policy_attachment":
                # Link IAM role to resources it can access
                role_ref = properties.get("role")
                if role_ref:
                    graph.add_permission(
                        f"aws_iam_role.{role_ref}",
                        source_id,
                        "assume_role"
                    )
                    permission_count += 1
        
        return graph, len(resources), permission_count


def scan_terraform(terraform_path: str, 
                   output_file: Optional[str] = None) -> ScanResult:
    """
    Main entry point for scanning Terraform files.
    
    Args:
        terraform_path: Path to Terraform directory or file
        output_file: Optional path to write graph JSON
        
    Returns:
        ScanResult with infrastructure graph
    """
    scanner = TerraformScanner()
    
    if os.path.isfile(terraform_path):
        result = scanner.scan_file(terraform_path)
    else:
        result = scanner.scan_directory(terraform_path)
    
    # Write output if requested
    if output_file and result.success and result.graph:
        with open(output_file, 'w') as f:
            json.dump(result.graph.to_dict(), f, indent=2)
    
    return result


def main():
    """CLI entry point for scanner."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Lateryx Terraform Scanner - Parse infrastructure to graph"
    )
    parser.add_argument(
        "path",
        help="Path to Terraform directory or file"
    )
    parser.add_argument(
        "--output", "-o",
        default=None,
        help="Path to output JSON file"
    )
    parser.add_argument(
        "--checkov-path",
        default="checkov",
        help="Path to checkov CLI executable"
    )
    
    args = parser.parse_args()
    
    # Run scan
    scanner = TerraformScanner(checkov_path=args.checkov_path)
    
    if os.path.isfile(args.path):
        result = scanner.scan_file(args.path)
    else:
        result = scanner.scan_directory(args.path)
    
    if not result.success:
        print(f"❌ Scan failed:")
        for error in result.errors:
            print(f"  • {error}")
        return 1
    
    print(f"✅ Scan successful:")
    print(f"  • Resources: {result.resources_count}")
    print(f"  • Permissions: {result.permissions_count}")
    
    if args.output and result.graph:
        with open(args.output, 'w') as f:
            json.dump(result.graph.to_dict(), f, indent=2)
        print(f"  • Output: {args.output}")
    elif result.graph:
        print(json.dumps(result.graph.to_dict(), indent=2))
    
    return 0


if __name__ == "__main__":
    exit(main())
