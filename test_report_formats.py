#!/usr/bin/env python3
"""
Test script to generate reports in all supported formats
"""

import sys
import os
sys.path.insert(0, 'src/backend')

from modules.report_generator import ReportGenerator
from modules.export_formats import ReportExporter
from datetime import datetime

# Sample scan data - before hardening
before_scan = {
    "scan_id": "scan_before_001",
    "findings": [
        {
            "title": "SSH Root Login Enabled",
            "severity": "critical",
            "description": "SSH service allows root login with password authentication",
            "category": "Network Security",
            "remediation": "Disable root login and password authentication in /etc/ssh/sshd_config"
        },
        {
            "title": "Weak Password Policy",
            "severity": "high",
            "description": "Password maximum age not configured properly",
            "category": "Authentication",
            "remediation": "Set PASS_MAX_DAYS to 90 in /etc/login.defs"
        },
        {
            "title": "Firewall Disabled",
            "severity": "high",
            "description": "System firewall is not enabled",
            "category": "Network Security",
            "remediation": "Enable and configure ufw or iptables"
        },
        {
            "title": "Outdated Packages",
            "severity": "medium",
            "description": "15 packages require security updates",
            "category": "System Updates",
            "remediation": "Run apt update && apt upgrade"
        },
        {
            "title": "Unnecessary Services Running",
            "severity": "low",
            "description": "Some unnecessary services are running",
            "category": "Services",
            "remediation": "Review and disable unnecessary services"
        }
    ]
}

# Sample scan data - after hardening
after_scan = {
    "scan_id": "scan_after_001",
    "findings": [
        {
            "title": "Outdated Packages",
            "severity": "medium",
            "description": "3 packages require security updates",
            "category": "System Updates",
            "remediation": "Run apt update && apt upgrade"
        },
        {
            "title": "Unnecessary Services Running",
            "severity": "low",
            "description": "One unnecessary service is still running",
            "category": "Services",
            "remediation": "Review and disable unnecessary service"
        }
    ]
}

# Sample hardening session data
hardening_session = {
    "session_id": "hardening_session_001",
    "start_time": "2025-12-19T10:00:00",
    "end_time": "2025-12-19T10:05:00",
    "total_rules": 5,
    "successful_rules": 4,
    "failed_rules": 1,
    "skipped_rules": 0,
    "checkpoint_id": "checkpoint_xyz789",
    "results": [
        {
            "rule_id": "ssh_root_login",
            "rule_name": "Disable SSH Root Login",
            "status": "success",
            "rule_severity": "critical",
            "before_value": "PermitRootLogin yes",
            "after_value": "PermitRootLogin no",
            "duration_seconds": 1.2
        },
        {
            "rule_id": "ssh_password_auth",
            "rule_name": "Disable SSH Password Authentication",
            "status": "success",
            "rule_severity": "critical",
            "before_value": "PasswordAuthentication yes",
            "after_value": "PasswordAuthentication no",
            "duration_seconds": 0.8
        },
        {
            "rule_id": "password_policy",
            "rule_name": "Configure Password Policy",
            "status": "success",
            "rule_severity": "high",
            "before_value": "PASS_MAX_DAYS 99999",
            "after_value": "PASS_MAX_DAYS 90",
            "duration_seconds": 0.5
        },
        {
            "rule_id": "enable_firewall",
            "rule_name": "Enable Firewall",
            "status": "success",
            "rule_severity": "high",
            "before_value": "inactive",
            "after_value": "active",
            "duration_seconds": 2.3
        },
        {
            "rule_id": "disable_service",
            "rule_name": "Disable Unnecessary Service",
            "status": "failed",
            "rule_severity": "low",
            "error": "Service not found",
            "duration_seconds": 0.3
        }
    ]
}

print("=" * 80)
print("Testing Report Generation in All Formats")
print("=" * 80)

# Initialize generators
report_generator = ReportGenerator()
report_exporter = ReportExporter()

# Test 1: JSON Report
print("\n1. Testing JSON Report...")
try:
    json_path = report_generator.generate_report(
        scan_results=after_scan,
        before_scan=before_scan,
        after_scan=after_scan,
        hardening_session=hardening_session,
        report_format="json",
        title="System Security Report - JSON"
    )
    print(f"   ✓ JSON report generated: {json_path}")
except Exception as e:
    print(f"   ✗ JSON report failed: {e}")

# Test 2: HTML Report
print("\n2. Testing HTML Report...")
try:
    html_path = report_generator.generate_report(
        scan_results=after_scan,
        before_scan=before_scan,
        after_scan=after_scan,
        hardening_session=hardening_session,
        report_format="html",
        title="System Security Report - HTML"
    )
    print(f"   ✓ HTML report generated: {html_path}")
except Exception as e:
    print(f"   ✗ HTML report failed: {e}")

# Test 3: PDF Report
print("\n3. Testing PDF Report...")
try:
    pdf_path = report_generator.generate_report(
        scan_results=after_scan,
        before_scan=before_scan,
        after_scan=after_scan,
        hardening_session=hardening_session,
        report_format="pdf",
        title="System Security Report - PDF"
    )
    print(f"   ✓ PDF report generated: {pdf_path}")
except Exception as e:
    print(f"   ✗ PDF report failed: {e}")

# For the export formats, we need to compile report data first
report_data = report_generator._compile_report_data(
    scan_results=after_scan,
    before_scan=before_scan,
    after_scan=after_scan,
    hardening_session=hardening_session,
    title="System Security Report"
)

# Test 4: Excel Report
print("\n4. Testing Excel Report...")
try:
    excel_path = report_exporter.export_to_excel(report_data)
    print(f"   ✓ Excel report generated: {excel_path}")
except Exception as e:
    print(f"   ✗ Excel report failed: {e}")

# Test 5: CSV Report
print("\n5. Testing CSV Report...")
try:
    csv_path = report_exporter.export_to_csv(report_data)
    print(f"   ✓ CSV report generated: {csv_path}")
except Exception as e:
    print(f"   ✗ CSV report failed: {e}")

# Test 6: Word (DOCX) Report
print("\n6. Testing Word (DOCX) Report...")
try:
    docx_path = report_exporter.export_to_docx(report_data)
    print(f"   ✓ DOCX report generated: {docx_path}")
except Exception as e:
    print(f"   ✗ DOCX report failed: {e}")

# Test 7: Markdown Report
print("\n7. Testing Markdown Report...")
try:
    md_path = report_exporter.export_to_markdown(report_data)
    print(f"   ✓ Markdown report generated: {md_path}")
except Exception as e:
    print(f"   ✗ Markdown report failed: {e}")

print("\n" + "=" * 80)
print("Report Generation Testing Complete!")
print("=" * 80)
print(f"\nAll reports saved to: {report_generator.output_dir}")
print("Check the reports directory for generated files.")
