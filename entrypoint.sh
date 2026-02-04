#!/bin/bash
# Lateryx Security Analyzer - GitHub Action Entrypoint
# =====================================================

set -e

# Parse arguments
TERRAFORM_DIR="${1:-.}"
BASE_REF="${2:-}"
HEAD_REF="${3:-}"
FAIL_ON_BREACH="${4:-true}"
SEVERITY_THRESHOLD="${5:-HIGH}"
OUTPUT_FORMAT="${6:-both}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

echo -e "${PURPLE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${PURPLE}   🔒 Lateryx Security Analyzer${NC}"
echo -e "${PURPLE}   Detecting Causality Breaches in Infrastructure Changes${NC}"
echo -e "${PURPLE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Create output directory
OUTPUT_DIR="${GITHUB_WORKSPACE:-/tmp}/.lateryx"
mkdir -p "$OUTPUT_DIR"

# Function to scan terraform and generate graph
scan_terraform() {
    local ref="$1"
    local output_file="$2"
    
    echo -e "${YELLOW}📂 Scanning Terraform at ref: ${ref:-current}${NC}"
    
    if [ -n "$ref" ]; then
        # Checkout specific ref
        git checkout "$ref" --quiet 2>/dev/null || true
    fi
    
    # Run scanner
    python -m src.scanner "$TERRAFORM_DIR" -o "$output_file"
    
    if [ -f "$output_file" ]; then
        echo -e "${GREEN}✅ Graph generated: $output_file${NC}"
        return 0
    else
        echo -e "${RED}❌ Failed to generate graph${NC}"
        return 1
    fi
}

# Scan base (before) state
BEFORE_GRAPH="$OUTPUT_DIR/before.json"
if [ -n "$BASE_REF" ]; then
    echo -e "\n${YELLOW}📊 Scanning BASE state (before changes)...${NC}"
    scan_terraform "$BASE_REF" "$BEFORE_GRAPH"
else
    # No base ref, create empty graph
    echo '{"name": "empty", "nodes": [{"id": "Internet", "type": "internet", "weight": 0.0}, {"id": "ProtectedData", "type": "protected_data", "weight": 1.0}], "edges": []}' > "$BEFORE_GRAPH"
    echo -e "${YELLOW}📊 No base ref provided, using empty baseline${NC}"
fi

# Return to head
if [ -n "$HEAD_REF" ]; then
    git checkout "$HEAD_REF" --quiet 2>/dev/null || true
fi

# Scan head (after) state
AFTER_GRAPH="$OUTPUT_DIR/after.json"
echo -e "\n${YELLOW}📊 Scanning HEAD state (after changes)...${NC}"
scan_terraform "" "$AFTER_GRAPH"

# Run analysis
echo -e "\n${YELLOW}🔍 Running Causality Breach Analysis...${NC}"
RESULT_JSON="$OUTPUT_DIR/result.json"
python -m src.main --before "$BEFORE_GRAPH" --after "$AFTER_GRAPH" --output "$RESULT_JSON"

# Parse results
IS_SAFE=$(jq -r '.is_safe' "$RESULT_JSON")
BREACHES_COUNT=$(jq -r '.breaches | length' "$RESULT_JSON")
NEW_PATHS=$(jq -r '.new_paths_count' "$RESULT_JSON")
SHORTENED_PATHS=$(jq -r '.shortened_paths_count' "$RESULT_JSON")
SUMMARY=$(jq -r '.summary' "$RESULT_JSON")

# Determine highest severity
HIGHEST_SEVERITY="NONE"
if [ "$BREACHES_COUNT" -gt 0 ]; then
    HIGHEST_SEVERITY=$(jq -r '[.breaches[].severity] | if any(. == "CRITICAL") then "CRITICAL" elif any(. == "HIGH") then "HIGH" elif any(. == "MEDIUM") then "MEDIUM" else "LOW" end' "$RESULT_JSON")
fi

# Output results
echo -e "\n${PURPLE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${PURPLE}   📋 Analysis Results${NC}"
echo -e "${PURPLE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "$SUMMARY"
echo ""

if [ "$IS_SAFE" = "true" ]; then
    echo -e "${GREEN}✅ Infrastructure change is SAFE${NC}"
else
    echo -e "${RED}⚠️ CAUSALITY BREACHES DETECTED${NC}"
    echo -e "   Breaches: $BREACHES_COUNT"
    echo -e "   Highest Severity: $HIGHEST_SEVERITY"
    
    # Show breach details
    echo -e "\n${YELLOW}📌 Breach Details:${NC}"
    jq -r '.breaches[] | "  [\(.severity)] \(.description)"' "$RESULT_JSON"
fi

# Generate Markdown report
if [ "$OUTPUT_FORMAT" = "markdown" ] || [ "$OUTPUT_FORMAT" = "both" ]; then
    RESULT_MD="$OUTPUT_DIR/result.md"
    
    cat > "$RESULT_MD" << EOF
# 🛡️ Lateryx Security Intelligence Report

$(if [ "$IS_SAFE" = "true" ]; then 
    echo "### ✅ SAFE TO SHIP"
    echo "Lateryx analyzed your infrastructure changes and found **no new attack paths** or compliance violations."
else 
    echo "### ⚠️ BLOCKED: CAUSALITY BREACH DETECTED"
    echo "Lateryx identified **security regressions** that introduce new attack vectors or violate compliance policies."
fi)

---

## 📊 Risk Overview

| Metric | Status |
| :--- | :--- |
| **Security Status** | $(if [ "$IS_SAFE" = "true" ]; then echo "🛡️ SECURE"; else echo "❌ VULNERABLE"; fi) |
| **Highest Risk** | \`$HIGHEST_SEVERITY\` |
| **Action Items** | $BREACHES_COUNT |
| **New Attack Paths** | $NEW_PATHS |

---

EOF
    
    if [ "$BREACHES_COUNT" -gt 0 ]; then
        echo "## 🚨 Critical Security Findings" >> "$RESULT_MD"
        echo "" >> "$RESULT_MD"
        
        # Populate detailed breach cards
        jq -r '.breaches[] | "
### [\(.severity)] \(.description)
**Business Impact:** \(.impact_summary)

**📜 Compliance Violations:**
\(.compliance_violations | map(" - " + .) | join("\n"))

**⚖️ Legal Exposure:** \(.legal_exposure)

**🛠️ How to Resolve:**
> \(.remediation)

---
"' "$RESULT_JSON" >> "$RESULT_MD"

        echo "## 🎯 Next Steps" >> "$RESULT_MD"
        echo "1. Review the **How to Resolve** steps above." >> "$RESULT_MD"
        echo "2. Update your Terraform code to restrict access." >> "$RESULT_MD"
        echo "3. Push changes to this branch to trigger a re-scan." >> "$RESULT_MD"
    fi

    echo "" >> "$RESULT_MD"
    echo "> _Generated by [Lateryx Intelligence](https://lateryx.io) — Cloud Safety & Compliance on Autopilot_" >> "$RESULT_MD"
    
    echo -e "${GREEN}📄 Markdown report: $RESULT_MD${NC}"
fi

# Set GitHub Actions outputs
if [ -n "$GITHUB_OUTPUT" ]; then
    echo "is_safe=$IS_SAFE" >> "$GITHUB_OUTPUT"
    echo "breaches_count=$BREACHES_COUNT" >> "$GITHUB_OUTPUT"
    echo "new_paths_count=$NEW_PATHS" >> "$GITHUB_OUTPUT"
    echo "shortened_paths_count=$SHORTENED_PATHS" >> "$GITHUB_OUTPUT"
    echo "highest_severity=$HIGHEST_SEVERITY" >> "$GITHUB_OUTPUT"
    echo "report_json=$RESULT_JSON" >> "$GITHUB_OUTPUT"
    echo "report_markdown=$RESULT_MD" >> "$GITHUB_OUTPUT"
fi

# Post PR comment if GitHub token is available
if [ -n "$GITHUB_TOKEN" ] && [ -n "$GITHUB_EVENT_PATH" ]; then
    PR_NUMBER=$(jq -r '.pull_request.number // empty' "$GITHUB_EVENT_PATH")
    
    if [ -n "$PR_NUMBER" ] && [ -f "$RESULT_MD" ]; then
        echo -e "\n${YELLOW}📝 Posting comment to PR #$PR_NUMBER...${NC}"
        
        COMMENT_BODY=$(cat "$RESULT_MD")
        
        # Use GitHub API to post comment
        curl -s -X POST \
            -H "Authorization: token $GITHUB_TOKEN" \
            -H "Accept: application/vnd.github.v3+json" \
            "https://api.github.com/repos/$GITHUB_REPOSITORY/issues/$PR_NUMBER/comments" \
            -d "$(jq -n --arg body "$COMMENT_BODY" '{body: $body}')" > /dev/null
        
        echo -e "${GREEN}✅ Comment posted${NC}"
    fi
fi

# Determine exit code
EXIT_CODE=0
if [ "$FAIL_ON_BREACH" = "true" ] && [ "$IS_SAFE" = "false" ]; then
    # Check severity threshold
    SEVERITY_ORDER="LOW MEDIUM HIGH CRITICAL"
    THRESHOLD_INDEX=$(echo "$SEVERITY_ORDER" | tr ' ' '\n' | grep -n "^$SEVERITY_THRESHOLD$" | cut -d: -f1)
    ACTUAL_INDEX=$(echo "$SEVERITY_ORDER" | tr ' ' '\n' | grep -n "^$HIGHEST_SEVERITY$" | cut -d: -f1)
    
    if [ "${ACTUAL_INDEX:-0}" -ge "${THRESHOLD_INDEX:-0}" ]; then
        echo -e "\n${RED}❌ Failing due to $HIGHEST_SEVERITY severity breach (threshold: $SEVERITY_THRESHOLD)${NC}"
        EXIT_CODE=1
    fi
fi

echo -e "\n${PURPLE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
exit $EXIT_CODE
