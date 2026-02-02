#!/usr/bin/env python3
"""
Lateryx IAM Resolver
====================
Calculates "Effective Permissions" by evaluating multiple policy layers:
1. Identity-based policies (attached to IAM users/roles)
2. Resource-based policies (attached to S3, KMS, etc.)
3. Permissions Boundaries
4. Service Control Policies (SCPs)

This solves the "False Positive" problem where Lateryx might flag a path
that is actually blocked by an SCP or Permissions Boundary.
"""

import json
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple


class PolicyEffect(Enum):
    """IAM policy effect."""
    ALLOW = "Allow"
    DENY = "Deny"


@dataclass
class PolicyStatement:
    """Represents a single IAM policy statement."""
    sid: str
    effect: PolicyEffect
    principals: Set[str]
    actions: Set[str]
    resources: Set[str]
    conditions: Dict = field(default_factory=dict)
    not_actions: Set[str] = field(default_factory=set)
    not_resources: Set[str] = field(default_factory=set)
    not_principals: Set[str] = field(default_factory=set)


@dataclass
class IAMPolicy:
    """Represents an IAM policy document."""
    name: str
    statements: List[PolicyStatement]
    policy_type: str  # "identity", "resource", "boundary", "scp"


@dataclass 
class EffectivePermission:
    """Result of permission evaluation."""
    allowed: bool
    reason: str
    blocking_policy: Optional[str] = None
    allowing_policy: Optional[str] = None


class IAMResolver:
    """
    Calculates effective permissions by evaluating all policy layers.
    
    AWS permission evaluation order:
    1. Explicit Deny (anywhere) -> DENY
    2. SCP Allow required (if in org)
    3. Permissions Boundary Allow required (if exists)
    4. Identity or Resource policy Allow required
    5. Default -> DENY
    """
    
    def __init__(self):
        self.identity_policies: Dict[str, List[IAMPolicy]] = {}
        self.resource_policies: Dict[str, IAMPolicy] = {}
        self.permissions_boundaries: Dict[str, IAMPolicy] = {}
        self.scps: List[IAMPolicy] = []
        
    def add_identity_policy(self, principal: str, policy: IAMPolicy):
        """Add an identity-based policy for a principal."""
        if principal not in self.identity_policies:
            self.identity_policies[principal] = []
        self.identity_policies[principal].append(policy)
    
    def add_resource_policy(self, resource: str, policy: IAMPolicy):
        """Add a resource-based policy."""
        self.resource_policies[resource] = policy
    
    def add_permissions_boundary(self, principal: str, policy: IAMPolicy):
        """Add a permissions boundary for a principal."""
        self.permissions_boundaries[principal] = policy
    
    def add_scp(self, policy: IAMPolicy):
        """Add a Service Control Policy."""
        self.scps.append(policy)
    
    def parse_policy_document(self, policy_json: str, name: str, 
                               policy_type: str) -> IAMPolicy:
        """Parse an IAM policy document from JSON."""
        if isinstance(policy_json, str):
            doc = json.loads(policy_json)
        else:
            doc = policy_json
            
        statements = []
        for stmt in doc.get("Statement", []):
            statements.append(self._parse_statement(stmt))
        
        return IAMPolicy(
            name=name,
            statements=statements,
            policy_type=policy_type
        )
    
    def _parse_statement(self, stmt: Dict) -> PolicyStatement:
        """Parse a single policy statement."""
        effect = PolicyEffect.ALLOW if stmt.get("Effect") == "Allow" else PolicyEffect.DENY
        
        return PolicyStatement(
            sid=stmt.get("Sid", ""),
            effect=effect,
            principals=self._to_set(stmt.get("Principal", "*")),
            actions=self._to_set(stmt.get("Action", [])),
            resources=self._to_set(stmt.get("Resource", [])),
            conditions=stmt.get("Condition", {}),
            not_actions=self._to_set(stmt.get("NotAction", [])),
            not_resources=self._to_set(stmt.get("NotResource", [])),
            not_principals=self._to_set(stmt.get("NotPrincipal", []))
        )
    
    def _to_set(self, value) -> Set[str]:
        """Convert a value to a set of strings."""
        if value == "*":
            return {"*"}
        if isinstance(value, str):
            return {value}
        if isinstance(value, dict):
            # Handle {"AWS": "arn:..."} format
            result = set()
            for v in value.values():
                result.update(self._to_set(v))
            return result
        if isinstance(value, list):
            return set(value)
        return set()
    
    def evaluate_permission(self, principal: str, action: str, 
                            resource: str) -> EffectivePermission:
        """
        Evaluate if a principal can perform an action on a resource.
        
        This follows AWS's permission evaluation logic:
        1. Check for explicit denies first
        2. Check SCPs (if any)
        3. Check Permissions Boundaries (if any)
        4. Check identity policies
        5. Check resource policies
        
        Returns:
            EffectivePermission with the result and explanation
        """
        
        # Step 1: Check for explicit denies across all policies
        deny_result = self._check_explicit_denies(principal, action, resource)
        if deny_result:
            return deny_result
        
        # Step 2: Check SCPs (all must allow)
        if self.scps:
            scp_result = self._check_scps(principal, action, resource)
            if not scp_result.allowed:
                return scp_result
        
        # Step 3: Check Permissions Boundary (must allow if exists)
        if principal in self.permissions_boundaries:
            boundary_result = self._check_boundary(principal, action, resource)
            if not boundary_result.allowed:
                return boundary_result
        
        # Step 4: Check identity policies
        identity_result = self._check_identity_policies(principal, action, resource)
        if identity_result.allowed:
            return identity_result
        
        # Step 5: Check resource policies
        resource_result = self._check_resource_policy(principal, action, resource)
        if resource_result.allowed:
            return resource_result
        
        # Default: Deny
        return EffectivePermission(
            allowed=False,
            reason="No policy grants the required permission (implicit deny)"
        )
    
    def _check_explicit_denies(self, principal: str, action: str, 
                                resource: str) -> Optional[EffectivePermission]:
        """Check for explicit denies in any policy."""
        
        # Check identity policies
        for policies in self.identity_policies.values():
            for policy in policies:
                for stmt in policy.statements:
                    if stmt.effect == PolicyEffect.DENY:
                        if self._matches_statement(stmt, principal, action, resource):
                            return EffectivePermission(
                                allowed=False,
                                reason=f"Explicit deny in identity policy",
                                blocking_policy=policy.name
                            )
        
        # Check resource policies
        for res, policy in self.resource_policies.items():
            if self._resource_matches(resource, res):
                for stmt in policy.statements:
                    if stmt.effect == PolicyEffect.DENY:
                        if self._matches_statement(stmt, principal, action, resource):
                            return EffectivePermission(
                                allowed=False,
                                reason=f"Explicit deny in resource policy",
                                blocking_policy=policy.name
                            )
        
        # Check SCPs
        for scp in self.scps:
            for stmt in scp.statements:
                if stmt.effect == PolicyEffect.DENY:
                    if self._matches_statement(stmt, principal, action, resource):
                        return EffectivePermission(
                            allowed=False,
                            reason=f"Explicit deny in SCP",
                            blocking_policy=scp.name
                        )
        
        return None
    
    def _check_scps(self, principal: str, action: str, 
                    resource: str) -> EffectivePermission:
        """Check if SCPs allow the action (all SCPs must allow)."""
        for scp in self.scps:
            allowed = False
            for stmt in scp.statements:
                if stmt.effect == PolicyEffect.ALLOW:
                    if self._matches_statement(stmt, principal, action, resource):
                        allowed = True
                        break
            
            if not allowed:
                return EffectivePermission(
                    allowed=False,
                    reason=f"SCP does not allow this action",
                    blocking_policy=scp.name
                )
        
        return EffectivePermission(
            allowed=True,
            reason="All SCPs allow this action"
        )
    
    def _check_boundary(self, principal: str, action: str, 
                        resource: str) -> EffectivePermission:
        """Check if the permissions boundary allows the action."""
        boundary = self.permissions_boundaries[principal]
        
        for stmt in boundary.statements:
            if stmt.effect == PolicyEffect.ALLOW:
                if self._matches_statement(stmt, principal, action, resource):
                    return EffectivePermission(
                        allowed=True,
                        reason="Permissions boundary allows this action"
                    )
        
        return EffectivePermission(
            allowed=False,
            reason="Permissions boundary does not allow this action",
            blocking_policy=boundary.name
        )
    
    def _check_identity_policies(self, principal: str, action: str, 
                                  resource: str) -> EffectivePermission:
        """Check if identity policies allow the action."""
        if principal not in self.identity_policies:
            return EffectivePermission(
                allowed=False,
                reason="No identity policies attached to principal"
            )
        
        for policy in self.identity_policies[principal]:
            for stmt in policy.statements:
                if stmt.effect == PolicyEffect.ALLOW:
                    if self._matches_statement(stmt, principal, action, resource):
                        return EffectivePermission(
                            allowed=True,
                            reason="Identity policy allows this action",
                            allowing_policy=policy.name
                        )
        
        return EffectivePermission(
            allowed=False,
            reason="No identity policy allows this action"
        )
    
    def _check_resource_policy(self, principal: str, action: str, 
                                resource: str) -> EffectivePermission:
        """Check if the resource policy allows the action."""
        for res, policy in self.resource_policies.items():
            if self._resource_matches(resource, res):
                for stmt in policy.statements:
                    if stmt.effect == PolicyEffect.ALLOW:
                        if self._matches_statement(stmt, principal, action, resource):
                            return EffectivePermission(
                                allowed=True,
                                reason="Resource policy allows this action",
                                allowing_policy=policy.name
                            )
        
        return EffectivePermission(
            allowed=False,
            reason="No resource policy allows this action"
        )
    
    def _matches_statement(self, stmt: PolicyStatement, principal: str, 
                           action: str, resource: str) -> bool:
        """Check if a statement matches the request."""
        
        # Check principal
        if not self._principal_matches(stmt, principal):
            return False
        
        # Check action
        if not self._action_matches(stmt, action):
            return False
        
        # Check resource
        if not self._resource_matches_stmt(stmt, resource):
            return False
        
        return True
    
    def _principal_matches(self, stmt: PolicyStatement, principal: str) -> bool:
        """Check if the principal matches the statement."""
        if "*" in stmt.principals:
            return True
        
        # Check NotPrincipal
        if stmt.not_principals:
            return principal not in stmt.not_principals
        
        for p in stmt.principals:
            if self._wildcard_match(p, principal):
                return True
        
        return False
    
    def _action_matches(self, stmt: PolicyStatement, action: str) -> bool:
        """Check if the action matches the statement."""
        
        # Handle NotAction
        if stmt.not_actions:
            for na in stmt.not_actions:
                if self._wildcard_match(na, action):
                    return False
            return True
        
        for a in stmt.actions:
            if self._wildcard_match(a, action):
                return True
        
        return False
    
    def _resource_matches_stmt(self, stmt: PolicyStatement, resource: str) -> bool:
        """Check if the resource matches the statement."""
        
        # Handle NotResource
        if stmt.not_resources:
            for nr in stmt.not_resources:
                if self._wildcard_match(nr, resource):
                    return False
            return True
        
        for r in stmt.resources:
            if self._wildcard_match(r, resource):
                return True
        
        return False
    
    def _resource_matches(self, resource: str, pattern: str) -> bool:
        """Check if a resource matches a pattern."""
        return self._wildcard_match(pattern, resource)
    
    def _wildcard_match(self, pattern: str, value: str) -> bool:
        """Match a pattern with wildcards (* and ?) against a value."""
        if pattern == "*":
            return True
        
        # Convert IAM wildcard pattern to regex
        regex_pattern = pattern.replace("*", ".*").replace("?", ".")
        regex_pattern = f"^{regex_pattern}$"
        
        try:
            return bool(re.match(regex_pattern, value, re.IGNORECASE))
        except re.error:
            return pattern == value


def create_resolver_from_terraform(resources: Dict) -> IAMResolver:
    """
    Create an IAM resolver from terraform resources.
    
    Args:
        resources: Dictionary of resource_address -> resource_values
        
    Returns:
        Configured IAMResolver
    """
    resolver = IAMResolver()
    
    for address, resource in resources.items():
        resource_type = resource.get("type", "")
        values = resource.get("values", {})
        
        # IAM Role inline policies
        if resource_type == "aws_iam_role":
            inline_policy = values.get("inline_policy", [])
            for policy in inline_policy:
                if policy.get("policy"):
                    parsed = resolver.parse_policy_document(
                        policy["policy"],
                        f"{address}/inline/{policy.get('name', 'default')}",
                        "identity"
                    )
                    resolver.add_identity_policy(address, parsed)
        
        # IAM Role Policy
        if resource_type == "aws_iam_role_policy":
            policy_doc = values.get("policy", "")
            if policy_doc:
                parsed = resolver.parse_policy_document(
                    policy_doc, address, "identity"
                )
                role = values.get("role", "")
                resolver.add_identity_policy(role, parsed)
        
        # S3 Bucket Policy
        if resource_type == "aws_s3_bucket_policy":
            policy_doc = values.get("policy", "")
            bucket = values.get("bucket", "")
            if policy_doc:
                parsed = resolver.parse_policy_document(
                    policy_doc, address, "resource"
                )
                resolver.add_resource_policy(bucket, parsed)
        
        # KMS Key Policy
        if resource_type == "aws_kms_key":
            policy_doc = values.get("policy", "")
            if policy_doc:
                parsed = resolver.parse_policy_document(
                    policy_doc, address, "resource"
                )
                resolver.add_resource_policy(address, parsed)
    
    return resolver
