#!/usr/bin/env python3
"""
Lateryx Historical Trends Tracker
===================================
Tracks security posture over time to show improvement or regression.
Stores scan results locally for trend analysis.
"""

import json
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict


@dataclass
class ScanRecord:
    """Record of a single security scan."""
    timestamp: str
    commit_sha: str
    branch: str
    total_resources: int
    total_attack_paths: int
    findings_critical: int
    findings_high: int
    findings_medium: int
    findings_low: int
    compliance_score: float  # 0-100
    frameworks_violated: List[str]
    is_safe: bool
    
    def to_dict(self) -> Dict:
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'ScanRecord':
        return cls(**data)


class TrendTracker:
    """
    Tracks and analyzes security trends over time.
    Stores data in a JSON file in the repository.
    """
    
    DEFAULT_HISTORY_FILE = ".lateryx/history.json"
    MAX_RECORDS = 1000  # Keep last 1000 scans
    
    def __init__(self, repo_root: str = "."):
        self.repo_root = Path(repo_root)
        self.history_file = self.repo_root / self.DEFAULT_HISTORY_FILE
        self.records: List[ScanRecord] = []
        self._load_history()
    
    def _load_history(self):
        """Load historical scan records."""
        if self.history_file.exists():
            try:
                with open(self.history_file, 'r') as f:
                    data = json.load(f)
                    self.records = [ScanRecord.from_dict(r) for r in data.get("scans", [])]
            except Exception:
                self.records = []
    
    def _save_history(self):
        """Save scan records to file."""
        self.history_file.parent.mkdir(parents=True, exist_ok=True)
        
        data = {
            "version": "1.0",
            "last_updated": datetime.utcnow().isoformat(),
            "scans": [r.to_dict() for r in self.records[-self.MAX_RECORDS:]]
        }
        
        with open(self.history_file, 'w') as f:
            json.dump(data, f, indent=2)
    
    def record_scan(self, scan_result: Dict, commit_sha: str = "", branch: str = "main"):
        """
        Record a new scan result.
        
        Args:
            scan_result: The analysis result from Lateryx
            commit_sha: Git commit SHA
            branch: Git branch name
        """
        # Count findings by severity
        findings = scan_result.get("breaches", []) + scan_result.get("findings", [])
        
        critical = sum(1 for f in findings if f.get("severity") == "CRITICAL")
        high = sum(1 for f in findings if f.get("severity") == "HIGH")
        medium = sum(1 for f in findings if f.get("severity") == "MEDIUM")
        low = sum(1 for f in findings if f.get("severity") == "LOW")
        
        # Calculate compliance score (simple formula)
        total_findings = critical + high + medium + low
        if total_findings == 0:
            compliance_score = 100.0
        else:
            # Weight: Critical=-20, High=-10, Medium=-5, Low=-2
            penalty = (critical * 20) + (high * 10) + (medium * 5) + (low * 2)
            compliance_score = max(0, 100 - penalty)
        
        # Get violated frameworks
        frameworks = set()
        for finding in findings:
            for violation in finding.get("compliance_violations", []):
                # Extract framework name (e.g., "SOC2 CC6.1" -> "SOC2")
                framework = violation.split()[0] if violation else ""
                if framework:
                    frameworks.add(framework)
        
        record = ScanRecord(
            timestamp=datetime.utcnow().isoformat(),
            commit_sha=commit_sha or self._get_commit_sha(),
            branch=branch,
            total_resources=scan_result.get("total_resources", 0),
            total_attack_paths=scan_result.get("attack_paths_count", 0),
            findings_critical=critical,
            findings_high=high,
            findings_medium=medium,
            findings_low=low,
            compliance_score=compliance_score,
            frameworks_violated=list(frameworks),
            is_safe=scan_result.get("is_safe", False)
        )
        
        self.records.append(record)
        self._save_history()
        
        return record
    
    def _get_commit_sha(self) -> str:
        """Try to get the current git commit SHA."""
        try:
            import subprocess
            result = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                capture_output=True,
                text=True,
                cwd=str(self.repo_root)
            )
            return result.stdout.strip()[:8]
        except Exception:
            return "unknown"
    
    def get_trend_summary(self, days: int = 30) -> Dict:
        """
        Get a summary of security trends over the specified period.
        """
        if not self.records:
            return {
                "status": "NO_DATA",
                "message": "No historical data available. Run more scans to see trends."
            }
        
        # Filter records by date
        cutoff = datetime.utcnow().isoformat()[:10]  # Current date
        recent_records = self.records[-min(len(self.records), 100):]  # Last 100 or all
        
        if len(recent_records) < 2:
            return {
                "status": "INSUFFICIENT_DATA",
                "message": "Need at least 2 scans to show trends.",
                "current_score": recent_records[-1].compliance_score if recent_records else 0
            }
        
        # Calculate trend
        first_record = recent_records[0]
        last_record = recent_records[-1]
        
        score_change = last_record.compliance_score - first_record.compliance_score
        critical_change = last_record.findings_critical - first_record.findings_critical
        
        # Determine trend status
        if score_change > 5:
            trend_status = "IMPROVING"
            trend_icon = "📈"
        elif score_change < -5:
            trend_status = "DECLINING"
            trend_icon = "📉"
        else:
            trend_status = "STABLE"
            trend_icon = "➡️"
        
        # Calculate averages
        avg_score = sum(r.compliance_score for r in recent_records) / len(recent_records)
        avg_critical = sum(r.findings_critical for r in recent_records) / len(recent_records)
        
        return {
            "status": trend_status,
            "icon": trend_icon,
            "current_score": last_record.compliance_score,
            "score_change": round(score_change, 1),
            "average_score": round(avg_score, 1),
            "critical_findings_change": critical_change,
            "average_critical": round(avg_critical, 1),
            "total_scans": len(recent_records),
            "first_scan": first_record.timestamp,
            "last_scan": last_record.timestamp,
            "safe_percentage": round(
                sum(1 for r in recent_records if r.is_safe) / len(recent_records) * 100, 1
            ),
            "most_common_frameworks": self._get_common_frameworks(recent_records)
        }
    
    def _get_common_frameworks(self, records: List[ScanRecord]) -> List[str]:
        """Get the most commonly violated frameworks."""
        framework_counts = {}
        for record in records:
            for framework in record.frameworks_violated:
                framework_counts[framework] = framework_counts.get(framework, 0) + 1
        
        sorted_frameworks = sorted(framework_counts.items(), key=lambda x: x[1], reverse=True)
        return [f[0] for f in sorted_frameworks[:5]]
    
    def generate_trend_report(self) -> str:
        """Generate a Markdown trend report."""
        summary = self.get_trend_summary()
        
        if summary.get("status") in ["NO_DATA", "INSUFFICIENT_DATA"]:
            return f"# 📊 Lateryx Trend Report\n\n{summary.get('message', 'No data available.')}\n"
        
        md = f"""# 📊 Lateryx Security Trend Report

## {summary['icon']} Overall Trend: **{summary['status']}**

| Metric | Current | Average | Change |
|--------|---------|---------|--------|
| Compliance Score | {summary['current_score']}% | {summary['average_score']}% | {'+' if summary['score_change'] >= 0 else ''}{summary['score_change']}% |
| Critical Findings | - | {summary['average_critical']} | {'+' if summary['critical_findings_change'] >= 0 else ''}{summary['critical_findings_change']} |
| Safe Deployments | {summary['safe_percentage']}% | - | - |

## 📈 Key Insights

- **Total Scans Analyzed:** {summary['total_scans']}
- **First Scan:** {summary['first_scan'][:10]}
- **Latest Scan:** {summary['last_scan'][:10]}

"""
        
        if summary['most_common_frameworks']:
            md += "## ⚠️ Most Commonly Violated Frameworks\n\n"
            for i, framework in enumerate(summary['most_common_frameworks'], 1):
                md += f"{i}. {framework}\n"
            md += "\n"
        
        if summary['status'] == "IMPROVING":
            md += "> 🎉 Great job! Your security posture is improving over time.\n"
        elif summary['status'] == "DECLINING":
            md += "> ⚠️ Attention needed! Security issues are increasing. Review recent changes.\n"
        else:
            md += "> ℹ️ Security posture is stable. Keep up the good work!\n"
        
        md += "\n---\n_Generated by Lateryx_\n"
        
        return md


def get_trend_tracker(repo_root: str = ".") -> TrendTracker:
    """Get a configured trend tracker."""
    return TrendTracker(repo_root)
