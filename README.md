# Lateryx Security Engine

> Analyzes infrastructure changes to predict new attack paths using graph theory.

[![GitHub Action](https://img.shields.io/badge/GitHub-Action-blue?logo=github)](https://github.com/marketplace/actions/lateryx-security-analyzer)
[![Python 3.11+](https://img.shields.io/badge/Python-3.11+-green?logo=python)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## Overview

Lateryx is a **security analysis engine** that uses **graph theory** to identify potential attack paths in cloud infrastructure. It detects **"Causality Breaches"** - security regressions introduced by infrastructure changes.

### Core Concept

| Component | Description |
|-----------|-------------|
| **Nodes** | Infrastructure components (S3, EC2, IAM, RDS, Lambda, etc.) |
| **Edges** | Permissions and access relationships between components |
| **Source** | `Internet` - the entry point for attackers |
| **Target** | `ProtectedData` - sensitive data that must be protected |
| **Detection** | New or shortened attack paths = **Causality Breach** |

## How It Works

1. **Graph Construction**: Maps all infrastructure components as nodes, permissions as edges
2. **Pathfinding**: Uses NetworkX algorithms to find all paths from `Internet` to `ProtectedData`
3. **Change Analysis**: Compares "before" and "after" infrastructure graphs
4. **Scoring**: Flags new paths or shortened paths as security risks

## Quick Start

### Installation

```bash
pip install -r requirements.txt
```

### CLI Usage

```bash
# Analyze infrastructure changes
python -m src.main --before before.json --after after.json

# With failure on breach
python -m src.main --before before.json --after after.json --fail-on-breach
```

### As a GitHub Action

```yaml
name: Security Analysis

on: [pull_request]

jobs:
  lateryx:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Run Lateryx Security Analysis
        uses: lateryx/lateryx@v1
        with:
          terraform_directory: './infrastructure'
          fail_on_breach: 'true'
          severity_threshold: 'HIGH'
```

## Project Structure

```
lateryx/
├── src/
│   ├── __init__.py
│   ├── main.py          # Core graph analysis engine
│   └── scanner.py       # Terraform/HCL parser using Checkov
├── tests/
│   ├── scenarios/
│   │   ├── safe/        # Secure infrastructure example
│   │   └── hacked/      # Vulnerable infrastructure example
│   └── test_validation.py
├── action.yml           # GitHub Action definition
├── Dockerfile           # Container for GitHub Action
├── entrypoint.sh        # Action entrypoint script
└── requirements.txt
```

## API Reference

### InfrastructureGraph

Represents cloud infrastructure as a directed graph.

```python
from src.main import InfrastructureGraph

graph = InfrastructureGraph(name="my-infrastructure")

# Add resources
graph.add_resource(
    resource_id="s3.my_bucket",
    resource_type="s3",
    is_public=False,
    contains_sensitive_data=True
)

# Add permissions
graph.add_permission(
    source="iam.my_role",
    target="s3.my_bucket",
    permission_type="read",
    conditions={"vpc_endpoint": True}
)

# Find attack paths
paths = graph.find_all_attack_paths()
```

### LaterxyAnalyzer

Compares infrastructure states to detect Causality Breaches.

```python
from src.main import LaterxyAnalyzer, InfrastructureGraph

analyzer = LaterxyAnalyzer()

before = InfrastructureGraph.from_dict(before_data)
after = InfrastructureGraph.from_dict(after_data)

result = analyzer.analyze(before, after)

if not result.is_safe:
    for breach in result.breaches:
        print(f"[{breach.severity}] {breach.description}")
```

## Breach Types

| Type | Description | Severity |
|------|-------------|----------|
| `NEW_PATH` | A new path from Internet to ProtectedData was created | HIGH/CRITICAL |
| `SHORTENED_PATH` | An existing path was shortened (fewer hops to exploit) | HIGH |
| `WIDENED_ACCESS` | Access permissions were broadened | MEDIUM/HIGH |

## Example Output

```json
{
  "is_safe": false,
  "breaches": [
    {
      "breach_type": "NEW_PATH",
      "severity": "CRITICAL",
      "description": "New attack path created: Internet -> s3.public_bucket -> ProtectedData",
      "remediation": "Review the permissions of 's3.public_bucket'. Consider removing public access."
    }
  ],
  "before_paths_count": 0,
  "after_paths_count": 3,
  "new_paths_count": 3,
  "summary": "CAUSALITY BREACH DETECTED\n  - 3 new attack path(s) created"
}
```

## Running Tests

```bash
# Run validation suite
python tests/test_validation.py

# Expected output:
# [PASS] Safe Infrastructure
# [PASS] Hacked Infrastructure
# [PASS] Safe-to-Hacked Transition
# 
# *** ALL VALIDATIONS PASSED! ***
```

## Constraints

- **Privacy First**: Never accesses PII or user data
- **Config Only**: Only analyzes architecture and configuration (Terraform/HCL)
- **Graph Math**: Uses NetworkX for reliable pathfinding algorithms

## Technology Stack

- **Python 3.11+** - Core runtime
- **NetworkX** - Graph analysis and pathfinding algorithms
- **Checkov** - Terraform/HCL parsing and scanning
- **Docker** - GitHub Action container

## License

MIT License - See [LICENSE](LICENSE) for details.

---

Built with graph theory for infrastructure security.
