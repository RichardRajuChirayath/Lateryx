# Lateryx: Cloud Safety & Compliance on Autopilot

> Automated security audits and risk assessment for infrastructure-as-code.

Lateryx is an **intelligence engine** that translates complex cloud changes into clear business risks. It ensures your infrastructure is always compliant (SOC2, HIPAA) and safe-to-ship without needing a security expert on every PR.

### Core Concept

| Component | Description |
|-----------|-------------|
| **Nodes** | Infrastructure components (S3, EC2, IAM, RDS, Lambda, etc.) |
| **Edges** | Permissions and access relationships between components |
| **Source** | `Internet` - the entry point for attackers |
| **Target** | `ProtectedData` - sensitive data that must be protected |
| **Detection** | New or shortened attack paths = **Causality Breach** |

## Legendary Features (v1.1.0)

Lateryx has evolved into a **War-Gaming Engine** for infrastructure.

### ⚔️ Shadow Path Discovery (War-Gaming)
Simulate "Assume Breach" scenarios. Lateryx can predict an attacker's lateral movement and "Blast Radius" from any compromised node.
*   **Use Case:** *"If our Web Server is hacked, what is the shortest path to our Customer DB?"*

### 🔐 Zero-Knowledge Analysis
Anonymize your infrastructure graph using SHA-256 tokenization. Audit your security architecture without revealing internal resource names or sensitive metadata.
*   **Use Case:** Sending infrastructure graphs to third-party auditors or external AI without data leakage.

### 🧬 Immune System Loop
Lateryx identifies "Choke Points"—critical nodes that sit on multiple attack paths. It generates a monitoring manifest for high-fidelity logging (CloudTrail/GuardDuty).
*   **Use Case:** Prioritizing observability on the 5% of nodes that represent 90% of your risk.

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
│   ├── main.py              # Core graph analysis engine
│   ├── scanner.py           # Terraform/HCL parser using Checkov
│   ├── plan_analyzer.py     # Terraform plan JSON parser (v1.2+)
│   ├── iam_resolver.py      # AWS IAM effective permissions (v1.2+)
│   ├── cloud_sync.py        # Live cloud state sync (v1.2+)
│   ├── optimized_engine.py  # Centrality & blast radius (v1.2+)
│   └── config.py            # Configuration loader (v1.2+)
├── tests/
│   ├── scenarios/
│   │   ├── safe/            # Secure infrastructure example
│   │   └── hacked/          # Vulnerable infrastructure example
│   ├── test_validation.py
│   ├── test_legendary.py    # War-gaming tests
│   └── test_enterprise.py   # Enterprise feature tests
├── lateryx.config.example.yml  # Example configuration
├── action.yml               # GitHub Action definition
├── Dockerfile               # Container for GitHub Action
├── entrypoint.sh            # Action entrypoint script
└── requirements.txt
```

## Enterprise Features (v1.2.0)

Lateryx now includes **enterprise-grade** security analysis capabilities.

### 📊 Terraform Plan Analyzer
Parse `terraform plan -json` output for accurate resource analysis. This solves the "module/variable resolution" problem by analyzing the actual planned infrastructure.

```python
from src.plan_analyzer import TerraformPlanAnalyzer

analyzer = TerraformPlanAnalyzer()
graph, changes = analyzer.parse_plan_file("tfplan.json")

print(f"Resources: {len(graph.graph.nodes)}")
print(f"Changes: {len(changes)}")
```

### 🔒 IAM Permission Resolver
Calculates **effective permissions** by evaluating multiple policy layers:
- Identity-based policies
- Resource-based policies  
- Permissions boundaries
- Service Control Policies (SCPs)

```python
from src.iam_resolver import IAMResolver

resolver = IAMResolver()
result = resolver.evaluate_permission(
    principal="arn:aws:iam::123456789:role/MyRole",
    action="s3:GetObject",
    resource="arn:aws:s3:::my-bucket/*"
)
print(f"Allowed: {result.allowed}, Reason: {result.reason}")
```

### ☁️ Live Cloud State Sync
Pull live infrastructure state from AWS to identify **drift** between Terraform code and actual cloud configuration.

```python
from src.cloud_sync import AWSCloudSync, compare_live_to_plan

sync = AWSCloudSync(regions=["us-east-1"])
live_graph = sync.build_graph()

drift = compare_live_to_plan(live_graph, plan_graph)
print(f"Unmanaged resources: {len(drift['unmanaged_resources'])}")
```

### 🚀 Optimized Graph Engine
Handle **10,000+ resource** infrastructures using centrality algorithms and intelligent path sampling.

```python
from src.optimized_engine import OptimizedGraphEngine

engine = OptimizedGraphEngine(graph)

# Get the most important nodes
centrality = engine.analyze_centrality()

# Calculate blast radius of a compromise
blast = engine.get_blast_radius("ec2.web_server")
print(f"Blast radius: {blast['blast_radius_percent']}%")

# Find critical paths efficiently
paths = engine.find_critical_paths(max_paths=100)
```

### ⚙️ Configuration System
Customize risk scoring, define crown jewels, and configure severity thresholds via `lateryx.config.yml`.

```yaml
# lateryx.config.yml
crown_jewels:
  name_patterns:
    - "*customer*"
    - "*production*"

resource_scores:
  rds: 0.9
  s3: 0.7
  
severity:
  critical: 0.8
  high: 0.6
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

## Privacy & Legal Promise

Lateryx is designed for the most regulated industries (FinTech, HealthTech, Gov).
- **No Data Collection**: Lateryx runs entirely within your CI/CD environment. We never see your code or infrastructure.
- **Architecture Only**: We analyze structural relationship definitions (IAM, Network), never actual customer data or PII.
- **Zero-Knowledge Path**: Our tokenization module allows you to anonymize your entire graph before storage or external audit.
- **Legal Confidence**: By mapping to SOC2/HIPAA controls, Lateryx provides an automated paper trail for compliance audits.

## Technology Stack

- **Python 3.11+** - Core runtime
- **NetworkX** - Graph analysis and pathfinding algorithms
- **Checkov** - Terraform/HCL parsing and scanning
- **Docker** - GitHub Action container

## License

MIT License - See [LICENSE](LICENSE) for details.

---

Built with graph theory for infrastructure security.
