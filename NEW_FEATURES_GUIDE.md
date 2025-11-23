# New Features Guide

## 🎉 Recently Added Features

### 1. Multiple Report Formats

You can now export security reports in **5 different formats**:

- **PDF** - Professional reports with charts (existing)
- **Excel (.xlsx)** - Multi-sheet workbook with data analysis
- **CSV** - Simple data export for spreadsheets
- **Word (.docx)** - Formatted document reports
- **Markdown (.md)** - Git-friendly reports

#### How to Use

**Via API:**
```bash
# Generate Excel report
curl -X POST http://localhost:5000/api/report \
  -H "Content-Type: application/json" \
  -d '{
    "format": "excel",
    "title": "Security Report",
    "scan_results": { ... }
  }' \
  --output report.xlsx

# Generate CSV report
curl -X POST http://localhost:5000/api/report \
  -H "Content-Type: application/json" \
  -d '{
    "format": "csv",
    "scan_results": { ... }
  }' \
  --output findings.csv

# Generate Word document
curl -X POST http://localhost:5000/api/report \
  -H "Content-Type: application/json" \
  -d '{
    "format": "docx",
    "scan_results": { ... }
  }' \
  --output report.docx

# Generate Markdown
curl -X POST http://localhost:5000/api/report \
  -H "Content-Type: application/json" \
  -d '{
    "format": "markdown",
    "scan_results": { ... }
  }' \
  --output report.md
```

**Via Python:**
```python
from modules.export_formats import ReportExporter

exporter = ReportExporter()

# Export to Excel
excel_path = exporter.export_to_excel(report_data)

# Export to CSV
csv_path = exporter.export_to_csv(report_data)

# Export to Word
docx_path = exporter.export_to_docx(report_data)

# Export to Markdown
md_path = exporter.export_to_markdown(report_data)
```

### 2. Email Delivery System

Send reports and alerts via email automatically!

#### Setup Email Configuration

Create a `.env` file or set environment variables:

```bash
# For Gmail
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USE_TLS=True
MAIL_USERNAME=your-email@gmail.com
MAIL_PASSWORD=your-app-password
MAIL_DEFAULT_SENDER=your-email@gmail.com

# For other providers
MAIL_SERVER=smtp.office365.com  # Office 365
MAIL_SERVER=smtp.sendgrid.net   # SendGrid
```

**Gmail Setup:**
1. Go to Google Account settings
2. Enable 2-Factor Authentication
3. Generate an "App Password"
4. Use that password (not your regular password)

#### Send Reports via Email

```python
from modules.email_service import EmailService
from flask import Flask

app = Flask(__name__)
email_service = EmailService(app)

# Send report to administrators
email_service.send_report(
    recipients=['admin@company.com', 'security@company.com'],
    subject='Daily Security Report',
    report_path='/path/to/report.pdf',
    scan_summary=scan_data
)

# Send security alert
email_service.send_alert(
    recipients=['security-team@company.com'],
    alert_type='Critical Finding Detected',
    message='SSH root login is enabled on production server',
    severity='critical'
)
```

### 3. Report Scheduling (Coming Soon)

Automatic daily/weekly/monthly scans and reports!

**Configuration file:** `config/schedule.json`

```json
{
  "schedules": [
    {
      "name": "Daily Security Scan",
      "type": "daily",
      "time": "02:00",
      "scan_type": "full",
      "report_format": "pdf",
      "email_recipients": ["admin@company.com"],
      "enabled": true
    },
    {
      "name": "Weekly Compliance Report",
      "type": "weekly",
      "day_of_week": "monday",
      "time": "09:00",
      "report_format": "excel",
      "email_recipients": ["compliance@company.com"],
      "enabled": true
    },
    {
      "name": "Monthly Executive Summary",
      "type": "monthly",
      "day_of_month": 1,
      "time": "08:00",
      "report_format": "docx",
      "email_recipients": ["ceo@company.com", "cto@company.com"],
      "enabled": true
    }
  ]
}
```

## 📊 Excel Report Features

The Excel export includes **multiple sheets**:

1. **Summary Sheet** - Key metrics and statistics
2. **Security Findings** - Detailed vulnerability list
3. **Hardening Results** - Applied fixes and changes
4. **Recommendations** - Action items
5. **Before-After** - Comparison analysis

Perfect for:
- Data analysis and pivot tables
- Sharing with non-technical stakeholders
- Long-term tracking and trending

## 📝 Word Report Features

Professional formatted documents with:
- Color-coded severity levels
- Structured sections
- Easy to edit and customize
- Perfect for formal documentation

## 📋 Markdown Report Features

Git-friendly reports with:
- Emoji indicators for severity
- Clean formatting
- Easy version control
- Great for README files and wikis

## 🔔 Email Features

### Report Delivery
```python
# Automated report sending
email_service.send_scheduled_report(
    recipients=['team@company.com'],
    report_path='/path/to/report.pdf',
    scan_summary=scan_data,
    schedule_type='daily'
)
```

### Security Alerts
```python
# Critical findings
if critical_count > 0:
    email_service.send_alert(
        recipients=['security@company.com'],
        alert_type='Critical Vulnerabilities Found',
        message=f'Found {critical_count} critical issues',
        severity='critical'
    )
```

## 🚀 Quick Start Examples

### Example 1: Generate All Report Formats
```python
from modules.report_generator import ReportGenerator
from modules.export_formats import ReportExporter

# Generate data
generator = ReportGenerator()
report_data = generator._compile_report_data(scan_results=scan_data)

# Export to all formats
exporter = ReportExporter()
pdf_path = generator.generate_report(scan_data, report_format='pdf')
excel_path = exporter.export_to_excel(report_data)
csv_path = exporter.export_to_csv(report_data)
docx_path = exporter.export_to_docx(report_data)
md_path = exporter.export_to_markdown(report_data)
```

### Example 2: Scan + Email Report
```python
# Run scan
scanner = Scanner('linux')
results = scanner.scan('full')

# Generate PDF report
generator = ReportGenerator()
report_path = generator.generate_report(
    scan_results=results.to_dict(),
    report_format='pdf'
)

# Email to team
email_service.send_report(
    recipients=['team@company.com'],
    subject='Security Scan Complete',
    report_path=report_path,
    scan_summary=results.to_dict()
)
```

### Example 3: Weekly Compliance Report
```python
from apscheduler.schedulers.background import BackgroundScheduler

def weekly_compliance_check():
    # Run scan
    results = scanner.scan('compliance')

    # Generate Excel report (best for compliance)
    report_data = generator._compile_report_data(scan_results=results.to_dict())
    report_path = exporter.export_to_excel(report_data)

    # Email to compliance team
    email_service.send_report(
        recipients=['compliance@company.com'],
        subject='Weekly Compliance Report',
        report_path=report_path
    )

# Schedule it
scheduler = BackgroundScheduler()
scheduler.add_job(
    weekly_compliance_check,
    'cron',
    day_of_week='mon',
    hour=9,
    minute=0
)
scheduler.start()
```

## 📦 Installed Packages

The following packages were installed:
- `pandas` - Data manipulation for Excel/CSV
- `openpyxl` - Excel file generation
- `python-docx` - Word document generation
- `flask-mail` - Email delivery
- `apscheduler` - Task scheduling

## 🔧 Configuration Files

### Email Configuration (.env)
```bash
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USE_TLS=True
MAIL_USERNAME=your-email@gmail.com
MAIL_PASSWORD=your-app-password
MAIL_DEFAULT_SENDER=your-email@gmail.com
```

### Schedule Configuration (config/schedule.json)
```json
{
  "enabled": true,
  "timezone": "UTC",
  "schedules": [ ... ]
}
```

## 📚 Additional Resources

- **Report Generator:** `src/backend/modules/report_generator.py`
- **Export Formats:** `src/backend/modules/export_formats.py`
- **Email Service:** `src/backend/modules/email_service.py`
- **API Documentation:** `API_USAGE_EXAMPLE.md`

## 🐛 Troubleshooting

### Email Not Sending
1. Check email credentials in `.env`
2. For Gmail, use App Password (not regular password)
3. Test connection:
```python
email_service.test_connection()
```

### Excel Files Won't Open
- Make sure `openpyxl` is installed
- Check file permissions in reports directory

### Scheduled Jobs Not Running
- Verify scheduler is started
- Check timezone settings
- Review logs for errors

## 🎯 Next Steps

1. Configure email settings
2. Test report generation in all formats
3. Set up automated schedules
4. Customize report templates
5. Integrate with your workflow

---

**Need Help?** Check the logs in `logs/app.log` or run test scripts in the modules.
