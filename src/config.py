#!/usr/bin/env python3
"""
Lateryx Configuration Loader
============================
Loads and validates lateryx.config.yml for customizable risk scoring.
"""

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

try:
    import yaml
except ImportError:
    yaml = None


@dataclass
class CrownJewelsConfig:
    """Configuration for sensitive resources."""
    tags: List[Dict[str, str]] = field(default_factory=list)
    name_patterns: List[str] = field(default_factory=list)
    explicit: List[str] = field(default_factory=list)


@dataclass
class AnalysisConfig:
    """Analysis behavior configuration."""
    max_path_length: int = 15
    max_paths: int = 1000
    min_risk_threshold: float = 0.3
    resolve_iam: bool = True
    sync_cloud_state: bool = False


@dataclass
class SeverityConfig:
    """Severity threshold configuration."""
    critical: float = 0.8
    high: float = 0.6
    medium: float = 0.4
    low: float = 0.0


@dataclass
class GitHubConfig:
    """GitHub Action configuration."""
    post_comment: bool = True
    fail_on_breach: bool = True
    fail_severity: str = "HIGH"
    add_labels: bool = True
    labels: Dict[str, str] = field(default_factory=lambda: {
        "critical": "security-critical",
        "high": "security-high",
        "medium": "security-review",
        "low": "security-minor"
    })


@dataclass
class ObservabilityConfig:
    """Observability (Immune System) configuration."""
    cloudtrail: bool = True
    guardduty: bool = True
    output_format: str = "json"


@dataclass
class PrivacyConfig:
    """Privacy/Zero-Knowledge configuration."""
    tokenize: bool = False
    salt: str = ""
    redact_fields: List[str] = field(default_factory=lambda: [
        "password", "secret", "token", "api_key"
    ])


@dataclass
class LaterxyConfig:
    """Complete Lateryx configuration."""
    version: str = "1.0"
    crown_jewels: CrownJewelsConfig = field(default_factory=CrownJewelsConfig)
    risk_weights: Dict[str, float] = field(default_factory=lambda: {
        "path_length": 0.3,
        "node_centrality": 0.3,
        "edge_permissions": 0.2,
        "public_exposure": 0.2
    })
    resource_scores: Dict[str, float] = field(default_factory=lambda: {
        "s3": 0.7,
        "rds": 0.9,
        "dynamodb": 0.7,
        "secretsmanager": 1.0,
        "kms": 1.0,
        "ec2": 0.4,
        "lambda": 0.5,
        "iam_role": 0.6,
        "iam_user": 0.8,
        "api_gateway": 0.3,
        "alb": 0.2
    })
    permission_scores: Dict[str, float] = field(default_factory=lambda: {
        "admin": 1.0,
        "write": 0.7,
        "delete": 0.8,
        "read": 0.3,
        "invoke": 0.5,
        "assume_role": 0.7,
        "public_access": 0.9,
        "execute": 0.6
    })
    analysis: AnalysisConfig = field(default_factory=AnalysisConfig)
    severity: SeverityConfig = field(default_factory=SeverityConfig)
    ignore_resources: List[str] = field(default_factory=list)
    ignore_paths: List[str] = field(default_factory=list)
    ignore_tags: List[Dict[str, str]] = field(default_factory=list)
    github: GitHubConfig = field(default_factory=GitHubConfig)
    observability: ObservabilityConfig = field(default_factory=ObservabilityConfig)
    privacy: PrivacyConfig = field(default_factory=PrivacyConfig)


class ConfigLoader:
    """Loads and validates Lateryx configuration."""
    
    CONFIG_FILENAMES = [
        "lateryx.config.yml",
        "lateryx.config.yaml",
        ".lateryx.yml",
        ".lateryx.yaml"
    ]
    
    def __init__(self, config_path: Optional[str] = None):
        self.config_path = config_path
        self.config = LaterxyConfig()
    
    def load(self, search_dir: str = ".") -> LaterxyConfig:
        """
        Load configuration from file.
        
        Args:
            search_dir: Directory to search for config file
            
        Returns:
            LaterxyConfig with loaded settings
        """
        if yaml is None:
            print("Warning: PyYAML not installed. Using default config.")
            return self.config
        
        config_file = self._find_config_file(search_dir)
        if not config_file:
            return self.config
        
        with open(config_file, 'r') as f:
            raw_config = yaml.safe_load(f) or {}
        
        return self._parse_config(raw_config)
    
    def _find_config_file(self, search_dir: str) -> Optional[Path]:
        """Find the configuration file."""
        if self.config_path:
            path = Path(self.config_path)
            if path.exists():
                return path
        
        search_path = Path(search_dir)
        for filename in self.CONFIG_FILENAMES:
            config_file = search_path / filename
            if config_file.exists():
                return config_file
        
        return None
    
    def _parse_config(self, raw: Dict) -> LaterxyConfig:
        """Parse raw YAML into configuration objects."""
        config = LaterxyConfig()
        
        config.version = raw.get("version", "1.0")
        
        # Parse crown jewels
        if "crown_jewels" in raw:
            cj = raw["crown_jewels"]
            config.crown_jewels = CrownJewelsConfig(
                tags=cj.get("tags", []),
                name_patterns=cj.get("name_patterns", []),
                explicit=cj.get("explicit", [])
            )
        
        # Parse risk weights
        if "risk_weights" in raw:
            config.risk_weights.update(raw["risk_weights"])
        
        # Parse resource scores
        if "resource_scores" in raw:
            config.resource_scores.update(raw["resource_scores"])
        
        # Parse permission scores
        if "permission_scores" in raw:
            config.permission_scores.update(raw["permission_scores"])
        
        # Parse analysis config
        if "analysis" in raw:
            a = raw["analysis"]
            config.analysis = AnalysisConfig(
                max_path_length=a.get("max_path_length", 15),
                max_paths=a.get("max_paths", 1000),
                min_risk_threshold=a.get("min_risk_threshold", 0.3),
                resolve_iam=a.get("resolve_iam", True),
                sync_cloud_state=a.get("sync_cloud_state", False)
            )
        
        # Parse severity thresholds
        if "severity" in raw:
            s = raw["severity"]
            config.severity = SeverityConfig(
                critical=s.get("critical", 0.8),
                high=s.get("high", 0.6),
                medium=s.get("medium", 0.4),
                low=s.get("low", 0.0)
            )
        
        # Parse ignore rules
        if "ignore" in raw:
            ign = raw["ignore"]
            config.ignore_resources = ign.get("resources", [])
            config.ignore_paths = ign.get("paths", [])
            config.ignore_tags = ign.get("tags", [])
        
        # Parse GitHub config
        if "github" in raw:
            g = raw["github"]
            config.github = GitHubConfig(
                post_comment=g.get("post_comment", True),
                fail_on_breach=g.get("fail_on_breach", True),
                fail_severity=g.get("fail_severity", "HIGH"),
                add_labels=g.get("add_labels", True),
                labels=g.get("labels", config.github.labels)
            )
        
        # Parse observability config
        if "observability" in raw:
            o = raw["observability"]
            config.observability = ObservabilityConfig(
                cloudtrail=o.get("cloudtrail", True),
                guardduty=o.get("guardduty", True),
                output_format=o.get("output_format", "json")
            )
        
        # Parse privacy config
        if "privacy" in raw:
            p = raw["privacy"]
            config.privacy = PrivacyConfig(
                tokenize=p.get("tokenize", False),
                salt=p.get("salt", ""),
                redact_fields=p.get("redact_fields", config.privacy.redact_fields)
            )
        
        return config
    
    def get_resource_score(self, resource_type: str) -> float:
        """Get the configured risk score for a resource type."""
        return self.config.resource_scores.get(resource_type, 0.5)
    
    def get_permission_score(self, permission_type: str) -> float:
        """Get the configured risk score for a permission type."""
        # Handle partial matches
        permission_lower = permission_type.lower()
        for key, score in self.config.permission_scores.items():
            if key in permission_lower:
                return score
        return 0.5
    
    def is_crown_jewel(self, resource_id: str, tags: Dict[str, str] = None) -> bool:
        """Check if a resource is a crown jewel (highly sensitive)."""
        cj = self.config.crown_jewels
        
        # Check explicit list
        for pattern in cj.explicit:
            if self._matches_pattern(pattern, resource_id):
                return True
        
        # Check name patterns
        for pattern in cj.name_patterns:
            if self._matches_pattern(pattern, resource_id):
                return True
        
        # Check tags
        if tags:
            for tag_rule in cj.tags:
                key = tag_rule.get("key", "")
                value = tag_rule.get("value", "")
                if tags.get(key) == value:
                    return True
        
        return False
    
    def should_ignore(self, resource_id: str, tags: Dict[str, str] = None) -> bool:
        """Check if a resource should be ignored."""
        # Check resource patterns
        for pattern in self.config.ignore_resources:
            if self._matches_pattern(pattern, resource_id):
                return True
        
        # Check tags
        if tags:
            for tag_rule in self.config.ignore_tags:
                key = tag_rule.get("key", "")
                value = tag_rule.get("value", "")
                if tags.get(key) == value:
                    return True
        
        return False
    
    def get_severity(self, risk_score: float) -> str:
        """Get severity level for a risk score."""
        if risk_score >= self.config.severity.critical:
            return "CRITICAL"
        elif risk_score >= self.config.severity.high:
            return "HIGH"
        elif risk_score >= self.config.severity.medium:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _matches_pattern(self, pattern: str, value: str) -> bool:
        """Check if a value matches a wildcard pattern."""
        import fnmatch
        return fnmatch.fnmatch(value, pattern)


def load_config(config_path: Optional[str] = None, 
                search_dir: str = ".") -> LaterxyConfig:
    """
    Load Lateryx configuration.
    
    Args:
        config_path: Explicit path to config file
        search_dir: Directory to search for config
        
    Returns:
        LaterxyConfig object
    """
    loader = ConfigLoader(config_path)
    return loader.load(search_dir)
