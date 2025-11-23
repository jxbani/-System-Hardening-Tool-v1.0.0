# API Usage Example - PDF Report Generation

## Overview
The `/api/report` endpoint now generates comprehensive security reports in PDF, HTML, or JSON format with full security scan data.

## Endpoint Details

**URL:** `POST /api/report`

**Request Body:**
```json
{
  "format": "pdf",                    // Options: "pdf", "html", "json"
  "title": "System Security Report", // Optional: Report title
  "scan_results": {                   // Optional: Current scan results
    "scan_id": "scan_001",
    "findings": [
      {
        "title": "SSH Root Login Enabled",
        "description": "SSH server allows root user login",
        "severity": "critical",
        "category": "Network Security",
        "remediation": "Disable root login in sshd_config",
        "affected_item": "/etc/ssh/sshd_config"
      }
      // ... more findings
    ]
  },
  "hardening_session": {              // Optional: Hardening actions taken
    "session_id": "hardening_001",
    "total_rules": 5,
    "successful_rules": 4,
    "failed_rules": 1,
    "results": [
      {
        "rule_name": "Disable SSH Root Login",
        "status": "success",
        "before_value": "yes",
        "after_value": "no",
        "duration_seconds": 1.2
      }
      // ... more results
    ]
  },
  "before_scan": {                    // Optional: Scan before hardening
    "findings": [/* findings */]
  },
  "after_scan": {                     // Optional: Scan after hardening
    "findings": [/* findings */]
  }
}
```

## Response

**Success (PDF/HTML):**
- Returns the file as a downloadable attachment
- Content-Type: `application/pdf` or `text/html`
- Includes `Content-Disposition` header for download

**Success (JSON):**
```json
{
  "status": "success",
  "report": {
    // Complete report data structure
  },
  "file_path": "/path/to/report.json"
}
```

**Error:**
```json
{
  "status": "error",
  "message": "Error description",
  "error": "Detailed error message"
}
```

## Usage Examples

### Example 1: Generate PDF Report from Scan Results

```python
import requests

# Prepare scan results
scan_data = {
    "scan_id": "scan_20251123",
    "findings": [
        {
            "title": "Weak Password Policy",
            "description": "Password minimum length is too short",
            "severity": "high",
            "category": "Authentication",
            "remediation": "Increase minimum password length to 12 characters"
        }
    ]
}

# Generate PDF report
response = requests.post(
    "http://localhost:5000/api/report",
    json={
        "format": "pdf",
        "title": "Security Audit Report",
        "scan_results": scan_data
    }
)

# Save PDF file
if response.status_code == 200:
    with open("security_report.pdf", "wb") as f:
        f.write(response.content)
    print("PDF report downloaded successfully!")
```

### Example 2: Generate Report with Before/After Comparison

```python
import requests

before_scan = {
    "findings": [
        {"title": "Issue 1", "severity": "critical", "category": "Network"},
        {"title": "Issue 2", "severity": "high", "category": "Auth"},
        {"title": "Issue 3", "severity": "medium", "category": "Files"}
    ]
}

after_scan = {
    "findings": [
        {"title": "Issue 3", "severity": "medium", "category": "Files"}
    ]
}

hardening_session = {
    "session_id": "hardening_001",
    "total_rules": 3,
    "successful_rules": 2,
    "failed_rules": 0,
    "results": [
        {
            "rule_name": "Fix Critical Issue",
            "status": "success",
            "before_value": "vulnerable",
            "after_value": "secured"
        }
    ]
}

response = requests.post(
    "http://localhost:5000/api/report",
    json={
        "format": "pdf",
        "title": "Hardening Results Report",
        "before_scan": before_scan,
        "after_scan": after_scan,
        "hardening_session": hardening_session
    }
)

if response.status_code == 200:
    with open("hardening_report.pdf", "wb") as f:
        f.write(response.content)
    print("Report saved!")
```

### Example 3: Using cURL

```bash
# Generate HTML report
curl -X POST http://localhost:5000/api/report \
  -H "Content-Type: application/json" \
  -d '{
    "format": "html",
    "title": "Security Report",
    "scan_results": {
      "scan_id": "test_001",
      "findings": [
        {
          "title": "Test Finding",
          "severity": "medium",
          "category": "Test",
          "description": "Test description",
          "remediation": "Test remediation"
        }
      ]
    }
  }' \
  --output security_report.html
```

### Example 4: JavaScript/Fetch API

```javascript
async function generateReport() {
    const reportData = {
        format: "pdf",
        title: "System Security Report",
        scan_results: {
            scan_id: "scan_001",
            findings: [
                {
                    title: "Security Issue",
                    severity: "high",
                    category: "Network",
                    description: "Issue description",
                    remediation: "Fix description"
                }
            ]
        }
    };

    try {
        const response = await fetch('http://localhost:5000/api/report', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(reportData)
        });

        if (response.ok) {
            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'security_report.pdf';
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            console.log('Report downloaded!');
        } else {
            const error = await response.json();
            console.error('Error:', error);
        }
    } catch (error) {
        console.error('Request failed:', error);
    }
}

generateReport();
```

## Report Features

The generated PDF report includes:

1. **Executive Summary**
   - Overall compliance score
   - Total findings by severity
   - Summary cards with key metrics

2. **Security Findings Distribution**
   - Visual bar charts showing issue distribution
   - Breakdown by severity levels

3. **Detailed Findings Table**
   - Complete list of all security issues
   - Severity badges
   - Category classification
   - Remediation steps

4. **Before/After Comparison** (if provided)
   - Side-by-side comparison of security posture
   - Improvement metrics
   - Percentage improvement calculations

5. **Remediation Actions** (if provided)
   - List of hardening rules applied
   - Success/failure status for each action
   - Before and after values
   - Execution duration

6. **Action Timeline**
   - Chronological sequence of hardening actions
   - Visual timeline with status indicators

7. **Compliance Framework Mapping**
   - CIS Controls
   - NIST CSF
   - PCI DSS
   - HIPAA
   - ISO 27001
   - SOC 2

8. **Recommendations**
   - Prioritized action items
   - Next steps for security improvement

## Test the Implementation

Run the test script to verify everything works:

```bash
# Run the test script
cd /home/jacob/system-hardening/system-hardening-tool
src/backend/venv/bin/python test_report_generation.py
```

This will generate sample PDF, HTML, and JSON reports in the `reports/` directory.

## Notes

- At least one of `scan_results`, `hardening_session`, `before_scan`, or `after_scan` must be provided
- The report generator requires `weasyprint` to be installed for PDF generation
- If weasyprint is not available, an HTML file will be returned instead
- Generated reports are saved in the `reports/` directory
- Each report includes a timestamp in the filename
