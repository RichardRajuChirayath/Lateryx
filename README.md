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

## Why Lateryx?

Traditional security scanners look for static misconfigurations (e.g., "Is this bucket public?"). Lateryx looks for **Architectural Causality**. 

By analyzing the relationship between your entire cloud stack, Lateryx identifies paths that a simple scanner would miss. It’s the difference between checking if a door is locked and checking if a window on the 3rd floor can be reached via a ladder in the garden.

## Key Capabilities

Lateryx is a comprehensive security and compliance engine.

- **✅ Automated Compliance Audits**: Maps infrastructure changes directly to SOC2, HIPAA, and ISO27001 controls.
- **📢 Human-Readable Impact**: Translates security math into plain English: "This PR lets anyone read your database."
- **🛡️ The 'Safe-to-Ship' Light**: Gives developers 100% confidence to deploy without security bottlenecks.
- **🔒 Zero-Knowledge Analysis**: Anonymizes your entire infrastructure graph for privacy-first auditing.
- **🧬 Immune System Loop**: Identifies critical "Choke Points" in your architecture for high-fidelity monitoring.
- **📊 Enterprise IAM Resolver**: Calculates effective permissions across complex policy layers (Boundaries, SCPs, etc.).

## Usage & Integration

### As a GitHub Action (Recommended)
Add Lateryx to your CI/CD pipeline to catch regressions before they merge.

```yaml
- uses: RichardRajuChirayath/Lateryx@v1
  with:
    terraform_directory: './infrastructure'
    fail_on_breach: 'true'
    severity_threshold: 'HIGH'
```

### Enterprise Configuration
Customize Lateryx for your specific environment using `lateryx.config.yml`.

```yaml
crown_jewels:
  name_patterns:
    - "*customer*"
    - "*production*"
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

GNU Affero General Public License v3.0 (AGPL-3.0) - See [LICENSE](LICENSE) for details.

---

Built with graph theory for infrastructure security.
