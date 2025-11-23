#!/usr/bin/env python3
"""
Test script for PDF report generation
Tests the complete report generation flow with sample data
"""

import sys
import os
import json

# Add backend to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src', 'backend'))

from modules.report_generator import ReportGenerator

def create_sample_scan_results():
    """Create sample scan results for testing"""
    return {
        "scan_id": "test_scan_001",
        "scan_type": "full",
        "timestamp": "2025-11-23T10:00:00",
        "status": "completed",
        "findings": [
            {
                "title": "SSH Root Login Enabled",
                "description": "SSH server allows root user login which poses a security risk",
                "severity": "critical",
                "category": "Network Security",
                "remediation": "Disable root login by setting 'PermitRootLogin no' in /etc/ssh/sshd_config",
                "affected_item": "/etc/ssh/sshd_config"
            },
            {
                "title": "Weak Password Policy",
                "description": "Password minimum length is below recommended 12 characters",
                "severity": "high",
                "category": "Authentication",
                "remediation": "Update password policy to require minimum 12 characters",
                "affected_item": "/etc/security/pwquality.conf"
            },
            {
                "title": "Firewall Not Configured",
                "description": "System firewall is not properly configured",
                "severity": "high",
                "category": "Network Security",
                "remediation": "Configure and enable firewall with appropriate rules",
                "affected_item": "iptables/firewalld"
            },
            {
                "title": "Missing Security Updates",
                "description": "15 security updates are available but not installed",
                "severity": "medium",
                "category": "System Updates",
                "remediation": "Run system update to install security patches",
                "affected_item": "apt/yum packages"
            },
            {
                "title": "World-Writable Files Found",
                "description": "Several files have overly permissive permissions",
                "severity": "medium",
                "category": "File System",
                "remediation": "Review and restrict file permissions",
                "affected_item": "/tmp directory"
            },
            {
                "title": "Unnecessary Services Running",
                "description": "Some unnecessary network services are enabled",
                "severity": "low",
                "category": "Services",
                "remediation": "Disable unused services to reduce attack surface",
                "affected_item": "systemd services"
            }
        ]
    }

def create_sample_hardening_session():
    """Create sample hardening session data"""
    return {
        "session_id": "hardening_test_001",
        "start_time": "2025-11-23T10:05:00",
        "end_time": "2025-11-23T10:08:00",
        "total_rules": 5,
        "successful_rules": 4,
        "failed_rules": 1,
        "skipped_rules": 0,
        "checkpoint_id": "checkpoint_abc123xyz",
        "rollback_performed": False,
        "results": [
            {
                "rule_id": "ssh_001",
                "rule_name": "Disable SSH Root Login",
                "status": "success",
                "rule_severity": "critical",
                "before_value": "yes",
                "after_value": "no",
                "duration_seconds": 1.2,
                "end_time": "2025-11-23T10:05:30"
            },
            {
                "rule_id": "pass_001",
                "rule_name": "Enforce Strong Password Policy",
                "status": "success",
                "rule_severity": "high",
                "before_value": "minlen=8",
                "after_value": "minlen=12",
                "duration_seconds": 0.8,
                "end_time": "2025-11-23T10:06:00"
            },
            {
                "rule_id": "fw_001",
                "rule_name": "Configure Firewall Rules",
                "status": "success",
                "rule_severity": "high",
                "before_value": "disabled",
                "after_value": "enabled with rules",
                "duration_seconds": 2.5,
                "end_time": "2025-11-23T10:06:30"
            },
            {
                "rule_id": "update_001",
                "rule_name": "Install Security Updates",
                "status": "success",
                "rule_severity": "medium",
                "before_value": "15 updates pending",
                "after_value": "all updates installed",
                "duration_seconds": 45.0,
                "end_time": "2025-11-23T10:07:30"
            },
            {
                "rule_id": "svc_001",
                "rule_name": "Disable Unnecessary Services",
                "status": "failed",
                "rule_severity": "low",
                "error_message": "Service telnet not found on system",
                "duration_seconds": 0.5,
                "end_time": "2025-11-23T10:08:00"
            }
        ]
    }

def create_before_after_scans():
    """Create before and after scan results for comparison"""
    before = {
        "scan_id": "before_scan_001",
        "findings": [
            {"title": "Issue 1", "severity": "critical", "category": "Network", "description": "Critical issue"},
            {"title": "Issue 2", "severity": "high", "category": "Auth", "description": "High issue"},
            {"title": "Issue 3", "severity": "high", "category": "Network", "description": "High issue"},
            {"title": "Issue 4", "severity": "medium", "category": "Files", "description": "Medium issue"},
            {"title": "Issue 5", "severity": "medium", "category": "System", "description": "Medium issue"},
            {"title": "Issue 6", "severity": "low", "category": "Services", "description": "Low issue"},
        ]
    }

    after = {
        "scan_id": "after_scan_001",
        "findings": [
            {"title": "Issue 4", "severity": "medium", "category": "Files", "description": "Medium issue"},
            {"title": "Issue 6", "severity": "low", "category": "Services", "description": "Low issue"},
        ]
    }

    return before, after

def main():
    print("=" * 70)
    print("PDF Report Generation Test")
    print("=" * 70)

    # Create sample data
    print("\n1. Creating sample scan data...")
    scan_results = create_sample_scan_results()
    hardening_session = create_sample_hardening_session()
    before_scan, after_scan = create_before_after_scans()

    print("   ✓ Sample data created")
    print(f"   - Scan findings: {len(scan_results['findings'])}")
    print(f"   - Hardening rules: {hardening_session['total_rules']}")
    print(f"   - Before scan issues: {len(before_scan['findings'])}")
    print(f"   - After scan issues: {len(after_scan['findings'])}")

    # Initialize report generator
    print("\n2. Initializing ReportGenerator...")
    generator = ReportGenerator()
    print(f"   ✓ Generator initialized")
    print(f"   - Template directory: {generator.template_dir}")
    print(f"   - Output directory: {generator.output_dir}")

    # Generate JSON report (always works)
    print("\n3. Generating JSON report...")
    try:
        json_path = generator.generate_report(
            scan_results=scan_results,
            hardening_session=hardening_session,
            before_scan=before_scan,
            after_scan=after_scan,
            report_format="json",
            title="Test Security Report - JSON"
        )
        print(f"   ✓ JSON report generated: {json_path}")
    except Exception as e:
        print(f"   ✗ JSON report failed: {e}")
        return 1

    # Generate HTML report
    print("\n4. Generating HTML report...")
    try:
        html_path = generator.generate_report(
            scan_results=scan_results,
            hardening_session=hardening_session,
            before_scan=before_scan,
            after_scan=after_scan,
            report_format="html",
            title="Test Security Report - HTML"
        )
        print(f"   ✓ HTML report generated: {html_path}")
    except Exception as e:
        print(f"   ✗ HTML report failed: {e}")
        return 1

    # Generate PDF report
    print("\n5. Generating PDF report...")
    try:
        pdf_path = generator.generate_report(
            scan_results=scan_results,
            hardening_session=hardening_session,
            before_scan=before_scan,
            after_scan=after_scan,
            report_format="pdf",
            title="Test Security Report - PDF"
        )
        print(f"   ✓ PDF report generated: {pdf_path}")

        # Check if it's actually a PDF or HTML fallback
        if pdf_path.endswith('.pdf'):
            print("   ✓ True PDF file created")
        else:
            print("   ⚠ HTML file returned (PDF library not available)")
            print("   To enable PDF generation, install:")
            print("     pip install weasyprint  OR")
            print("     pip install pdfkit")
    except Exception as e:
        print(f"   ✗ PDF report failed: {e}")
        import traceback
        traceback.print_exc()
        return 1

    print("\n" + "=" * 70)
    print("Report Generation Test Complete!")
    print("=" * 70)
    print("\nGenerated files:")
    print(f"  - JSON: {json_path}")
    print(f"  - HTML: {html_path}")
    print(f"  - PDF:  {pdf_path}")
    print("\nYou can now use these reports or integrate the API endpoint.")

    return 0

if __name__ == "__main__":
    sys.exit(main())
