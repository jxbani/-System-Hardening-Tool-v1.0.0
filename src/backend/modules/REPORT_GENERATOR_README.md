# Report Generator Module

Comprehensive security report generation with compliance scoring, charts, and before/after analysis.

## Features

✅ **Multiple Output Formats**
- HTML reports with interactive charts
- JSON data export
- PDF generation (requires weasyprint or pdfkit)

✅ **Compliance Scoring**
- Automatic compliance calculation (0-100%)
- Before/after improvement tracking
- Severity-weighted deductions

✅ **Visual Analytics**
- Issues by severity (doughnut chart)
- Compliance improvement (bar chart)
- Hardening results (pie chart)
- Uses Chart.js for interactive visualizations

✅ **Before/After Comparison**
- Side-by-side security posture comparison
- Detailed improvement metrics
- Issue resolution tracking

✅ **Timeline Visualization**
- Chronological action timeline
- Status-based color coding
- Duration tracking

## Usage

### Basic Report Generation

```python
from report_generator import ReportGenerator

generator = ReportGenerator()

# Generate from scan results
report_path = generator.generate_report(
    scan_results=scan_data,
    report_format="html",
    title="Security Scan Report"
)
```

### Comprehensive Hardening Report

```python
# With before/after comparison
report_path = generator.generate_report(
    before_scan=before_scan_data,
    after_scan=after_scan_data,
    hardening_session=hardening_data,
    report_format="html",
    title="System Hardening Report"
)
```

### Convenience Functions

```python
from report_generator import generate_scan_report, generate_hardening_report

# Quick scan report
path = generate_scan_report(scan_results, format="html")

# Quick hardening report
path = generate_hardening_report(
    hardening_session,
    before_scan=before,
    after_scan=after,
    format="pdf"
)
```

## Data Structures

### Scan Results Format

```python
{
    "scan_id": "scan_001",
    "findings": [
        {
            "title": "Issue Title",
            "severity": "critical",  # critical, high, medium, low, info
            "description": "Issue description",
            "category": "Category Name",
            "remediation": "How to fix"
        }
    ]
}
```

### Hardening Session Format

```python
{
    "session_id": "hardening_001",
    "start_time": "2025-11-06T10:00:00",
    "end_time": "2025-11-06T10:05:00",
    "total_rules": 10,
    "successful_rules": 8,
    "failed_rules": 2,
    "skipped_rules": 0,
    "checkpoint_id": "checkpoint_abc123",
    "rollback_performed": False,
    "results": [
        {
            "rule_id": "rule_001",
            "rule_name": "Rule Name",
            "status": "success",  # success, failed, skipped
            "rule_severity": "critical",
            "before_value": "old value",
            "after_value": "new value",
            "duration_seconds": 1.2,
            "error_message": None,
            "end_time": "2025-11-06T10:01:00"
        }
    ]
}
```

## Compliance Scoring Algorithm

The compliance score (0-100%) is calculated by deducting points from a perfect score:

- **Critical**: -10 points each
- **High**: -5 points each
- **Medium**: -2 points each
- **Low**: -0.5 points each
- **Info**: No deduction

Formula: `Score = max(0, min(100, 100 - total_deductions))`

Example:
- 1 Critical + 2 High + 3 Medium = 10 + 10 + 6 = -26 points
- Compliance Score = 74%

## Report Sections

### 1. Executive Summary
- Overall compliance score (large circular badge)
- Quick statistics (total findings, critical, high, medium)
- Visual stat cards with gradient backgrounds

### 2. Security Posture Improvement
- Before/after comparison grid
- Issue count by severity
- Percentage improvement metric
- Total issues resolved count

### 3. Visual Analysis
- **Issues by Severity Chart**: Doughnut chart showing distribution
- **Compliance Improvement Chart**: Grouped bar chart comparing before/after
- **Hardening Results Chart**: Pie chart showing success/failure/skipped

### 4. Timeline of Actions
- Chronological list of applied rules
- Status icons and color coding
- Duration tracking for each action

### 5. Detailed Findings
- Comprehensive table of all findings
- Severity badges
- Category classification
- Full descriptions

### 6. Hardening Session Details
- Summary statistics
- Checkpoint ID for rollback
- Detailed table of applied rules
- Before/after values for each rule

### 7. Recommendations
- Priority-based recommendations
- Actionable advice
- Context-specific suggestions

## Output Formats

### HTML Report
- Self-contained single file
- Responsive design
- Interactive Chart.js charts
- Print-friendly CSS
- Professional gradient styling

### JSON Report
- Complete data export
- Machine-readable format
- Includes all metrics and calculations
- Perfect for API integration

### PDF Report
- Generated from HTML template
- Requires `weasyprint` or `pdfkit`
- Preserves all formatting
- Suitable for archival

## Installation Requirements

### Basic (HTML & JSON)
```bash
pip install jinja2
```

### PDF Support (Optional)
```bash
# Option 1: weasyprint (recommended)
pip install weasyprint

# Option 2: pdfkit
pip install pdfkit
# Also requires wkhtmltopdf system package
```

## Directory Structure

```
project/
├── config/
│   └── templates/
│       └── report_template.html    # Jinja2 template
├── reports/                         # Generated reports
│   ├── security_report_*.html
│   ├── security_report_*.json
│   └── security_report_*.pdf
└── src/backend/modules/
    └── report_generator.py
```

## Configuration

### Custom Template Directory
```python
generator = ReportGenerator(
    template_dir="/path/to/templates",
    output_dir="/path/to/reports"
)
```

### Default Paths
- Templates: `config/templates/`
- Output: `reports/`

## Example Output

### Sample Metrics
```
Compliance Scores:
  Before: 80.5%
  After:  97.5%
  Improvement: +17.0%

Issues Summary:
  Before: 5 total (1 critical, 1 high, 2 medium, 1 low)
  After:  2 total (0 critical, 0 high, 1 medium, 1 low)
  Resolved: 3 issues
  Improvement: 60.0%
```

## Chart Customization

Charts use Chart.js with the following color scheme:
- **Critical**: #dc3545 (red)
- **High**: #fd7e14 (orange)
- **Medium**: #ffc107 (yellow)
- **Low**: #17a2b8 (teal)
- **Info**: #6c757d (gray)
- **Success**: #28a745 (green)

## Error Handling

The module includes comprehensive error handling:
- Missing Jinja2 → Warning, HTML disabled
- Missing PDF libraries → Falls back to HTML
- Template not found → Clear error message
- Invalid data → ValueError with details

## Testing

Run the standalone test:
```bash
python3 src/backend/modules/report_generator.py
```

This will generate sample HTML and JSON reports in the `reports/` directory.

## Best Practices

1. **Always provide before/after scans** for hardening reports to show improvement
2. **Include checkpoint IDs** in hardening sessions for rollback capability
3. **Use descriptive titles** to differentiate between report types
4. **Store reports** with timestamps for historical tracking
5. **Export to JSON** for programmatic analysis and API integration

## API Integration

```python
# REST API endpoint example
@app.route('/api/report', methods=['POST'])
def generate_report():
    data = request.json
    generator = ReportGenerator()

    report_path = generator.generate_report(
        scan_results=data.get('scan_results'),
        hardening_session=data.get('hardening_session'),
        before_scan=data.get('before_scan'),
        after_scan=data.get('after_scan'),
        report_format=data.get('format', 'html'),
        title=data.get('title', 'Security Report')
    )

    return {
        'success': True,
        'report_path': report_path
    }
```

## License

Part of the System Hardening Tool project.
