# SABHA-DevSec: Security Tool Export Guide

## Quick Reference

SABHA-DevSec supports **JSON, CSV, and XML** formats from major security tools.

### Supported Tools Summary

| Category | Tools | Formats |
|----------|-------|---------|
| **Vulnerability Management** | Faraday | XML, JSON |
| **Network Scanners** | Nessus, Qualys | XML (.nessus), XML |
| **Web App Security** | Burp Suite, OWASP ZAP, Acunetix | XML |
| **SAST** | Semgrep, CodeQL, SonarQube | JSON |
| **SCA** | Snyk, Trivy, Dependabot | JSON |
| **Custom/Generic** | Any tool | JSON, CSV, XML |

---

## Tool-Specific Export Instructions

### Faraday

**Export XML:**
```bash
# From Faraday Web UI:
Workspace → Export → XML Format

# From Faraday CLI:
faraday-cli workspace export -w workspace_name -o output.xml
```

**Export JSON:**
```bash
# API endpoint:
GET /api/v3/ws/{workspace_name}/vulns

# Export to file:
faraday-cli workspace export -w workspace_name -o output.json --json
```

**Parsed Fields:**
- Host IP/Name
- Vulnerability name and description
- Severity levels (info, low, medium, high, critical)
- Service-level vulnerabilities
- References and CVEs

---

### Nessus

**Export .nessus File:**
```
1. Open Nessus Web UI
2. Navigate to Scans → [Your Scan]
3. Click "Export" → Select "Nessus" format
4. Download .nessus file
```

**Parsed Fields:**
- Plugin ID and name
- Risk factor (Critical, High, Medium, Low, Info)
- CVSS v2/v3 scores
- CVE identifiers
- Synopsis and solutions
- Affected hosts and ports

---

### Burp Suite

**Export XML:**
```
1. Burp Suite → Target → Site map
2. Right-click on scope → "Report selected issues"
3. Format: XML
4. Save as .xml file
```

**Parsed Fields:**
- Issue name and background
- Severity (High, Medium, Low, Information)
- Confidence level
- Host, path, and affected URLs
- Remediation guidance

---

### OWASP ZAP

**Export XML:**
```
1. ZAP → Report → Generate XML Report
2. Save report to file

# Or via CLI:
zap-cli report -o output.xml -f xml
```

**Parsed Fields:**
- Alert names
- Risk levels (0-3 mapping to Info/Low/Medium/High)
- Confidence ratings
- Affected URIs
- CWE/WASC identifiers
- Solutions and references

---

### Acunetix

**Export XML:**
```
1. Acunetix → Scans → [Your Scan]
2. Generate Reports → XML Format
3. Download report
```

**Parsed Fields:**
- Vulnerability names
- Severity levels
- Affected URLs/components
- Technical details
- Recommendations
- CWE mappings

---

### Qualys

**Export XML:**
```
1. Qualys VMDR → Reports
2. Create New Report → XML Output
3. Template: "Technical Report"
4. Download XML

# Or via API:
curl -u "username:password" \
  "https://qualysapi.qualys.com/api/2.0/fo/scan/result/?scan_ref={ref}&output_format=xml"
```

**Parsed Fields:**
- QID (Qualys ID)
- Vulnerability titles
- Severity (1-5 scale)
- CVSS base scores
- CVE lists
- Diagnosis and consequences
- Solutions

---

### Semgrep (SAST)

**Export JSON:**
```bash
# Run scan with JSON output:
semgrep --config auto --json -o results.json /path/to/code

# Or from Semgrep Cloud:
semgrep login
semgrep ci --json > results.json
```

**Expected JSON Structure:**
```json
{
  "results": [
    {
      "check_id": "rule-id",
      "path": "file/path.js",
      "extra": {
        "message": "Vulnerability description",
        "severity": "ERROR"
      }
    }
  ]
}
```

---

### CodeQL (SAST)

**Export JSON:**
```bash
# Run CodeQL analysis:
codeql database analyze db \
  --format=sarif-latest \
  --output=results.sarif

# Convert SARIF to JSON (if needed):
# SABHA-DevSec accepts standard JSON schemas
```

---

### Snyk (SCA)

**Export JSON:**
```bash
# Test and output JSON:
snyk test --json > snyk-results.json

# Or for container scans:
snyk container test image:tag --json > results.json
```

---

### Trivy (Container/IaC Scanner)

**Export JSON:**
```bash
# Scan container image:
trivy image --format json -o results.json alpine:latest

# Scan filesystem:
trivy fs --format json -o results.json /path/to/code
```

---

## Generic/Custom Tool Exports

### CSV Format

Create a CSV file with these required columns:

```csv
id,title,severity,domain,description,age,status
VULN-001,SQL Injection,critical,API Security,Description here,30,Open
VULN-002,XSS Vulnerability,high,Web Security,Description here,15,Open
```

**Required Fields:**
- `id`: Unique identifier
- `title`: Vulnerability name
- `severity`: critical/high/medium/low
- `domain`: Security category
- `age`: Days since discovery (optional)
- `status`: Open/In Progress/Resolved

### JSON Format

```json
{
  "findings": [
    {
      "id": "VULN-001",
      "title": "SQL Injection",
      "severity": "critical",
      "domain": "API Security",
      "description": "Detailed description",
      "cve": "CVE-2024-12345",
      "cvss": 9.8,
      "age": 30,
      "status": "Open"
    }
  ]
}
```

### XML Format (Generic)

```xml
<?xml version="1.0"?>
<scan>
  <vulnerability>
    <name>SQL Injection</name>
    <severity>critical</severity>
    <description>Detailed description</description>
  </vulnerability>
</scan>
```

The generic XML parser will automatically detect vulnerability-related elements.

---

## Severity Normalization

SABHA-DevSec automatically normalizes severity ratings from different tools:

| Input | Normalized |
|-------|-----------|
| P0, 10, 9, Critical | **Critical** |
| P1, 8, 7, High | **High** |
| P2, 6, 5, Medium | **Medium** |
| P3, 4, 3, 2, 1, Low | **Low** |
| Info, Informational, 0 | **Info** |

---

## Batch Upload

You can upload **multiple files simultaneously**:

1. Select multiple files from your file browser (Ctrl+Click or Cmd+Click)
2. Or drag-and-drop multiple files at once
3. Mix different formats (JSON + XML + CSV)
4. SABHA-DevSec will auto-detect and parse each file appropriately

**Example Multi-Tool Upload:**
- `faraday-scan.xml` (Faraday)
- `nessus-scan.nessus` (Nessus)
- `burp-results.xml` (Burp Suite)
- `semgrep-output.json` (Semgrep)
- All findings will be aggregated into a single comprehensive analysis

---

## Troubleshooting

### File Not Parsing Correctly

**Check:**
1. **File Extension**: Ensure `.json`, `.csv`, `.xml`, or `.nessus`
2. **XML Structure**: Must be valid XML (not HTML)
3. **Encoding**: Use UTF-8 encoding
4. **File Size**: Very large files (>50MB) may take longer to process

### Missing Findings

**Possible Causes:**
- For Nessus: Informational findings (severity 0) are automatically skipped
- For CSV: Missing required columns (id, title, severity)
- For JSON: Non-standard structure (check `findings` or `vulnerabilities` key)

### Incorrect Severity Mapping

If severity levels seem off, check your source tool's output. SABHA-DevSec uses intelligent normalization but some tools use non-standard severity scales.

---

## Best Practices

1. **Export Full Details**: Include descriptions, CVEs, and remediation advice
2. **Use Native Formats**: Prefer tool-native exports (e.g., `.nessus` for Nessus)
3. **Regular Exports**: For trend analysis, export scans regularly
4. **Combine Sources**: Upload multiple scan types for comprehensive analysis
5. **Validate Data**: Review the dashboard after upload to ensure accuracy

---

## Need Help?

If your security tool isn't listed or you're having issues:

1. Try **CSV export** as a universal format
2. Use **Generic XML** parser (auto-detected)
3. Export as **JSON** with `findings` array
4. Check the browser console for parsing errors

SABHA-DevSec is designed to be flexible and will attempt to parse any reasonable security data format.
