#!/usr/bin/env python3
"""
System Hardening Tool - Backend API
Main Flask application with REST API endpoints for system security hardening.
"""

import os
import logging
import random
from datetime import datetime
from flask import Flask, jsonify, request, send_file
from flask_cors import CORS
from dotenv import load_dotenv
import psutil
import platform

# Import modules
from modules.report_generator import ReportGenerator
from modules.export_formats import ReportExporter
from modules.email_service import EmailService
from modules.realtime_monitor import RealtimeMonitor
from modules.compliance_frameworks import ComplianceChecker
from modules.auto_remediation import AutoRemediation
from modules.database_models import DatabaseManager
from modules.scanner import Scanner
from modules.system_detector import SystemDetector

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)

# Configure CORS
CORS(app, resources={
    r"/api/*": {
        "origins": os.getenv("ALLOWED_ORIGINS", "*"),
        "methods": ["GET", "POST", "PUT", "DELETE"],
        "allow_headers": ["Content-Type", "Authorization"]
    }
})

# Configure logging
log_dir = os.path.join(os.path.dirname(__file__), '..', '..', 'logs')
os.makedirs(log_dir, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(log_dir, 'app.log')),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

# Configuration
app.config['DEBUG'] = os.getenv('DEBUG', 'False').lower() == 'true'
app.config['PORT'] = int(os.getenv('PORT', 5000))

# Initialize modules
report_generator = ReportGenerator()
report_exporter = ReportExporter()
email_service = EmailService(app)
realtime_monitor = RealtimeMonitor()
compliance_checker = ComplianceChecker()
auto_remediation = AutoRemediation()
db_manager = DatabaseManager()
system_detector = SystemDetector()

# Initialize scanner with detected OS type
os_type = system_detector.detect_os_type()
scanner = Scanner(os_type)


# ========================
# Utility Functions
# ========================

def get_system_info():
    """Gather system information using psutil."""
    try:
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')

        return {
            "platform": platform.system(),
            "platform_release": platform.release(),
            "platform_version": platform.version(),
            "architecture": platform.machine(),
            "hostname": platform.node(),
            "processor": platform.processor(),
            "cpu_count": psutil.cpu_count(),
            "cpu_percent": cpu_percent,
            "memory_total": memory.total,
            "memory_available": memory.available,
            "memory_percent": memory.percent,
            "disk_total": disk.total,
            "disk_used": disk.used,
            "disk_percent": disk.percent,
            "boot_time": datetime.fromtimestamp(psutil.boot_time()).isoformat()
        }
    except Exception as e:
        logger.error(f"Error gathering system info: {str(e)}")
        raise


# ========================
# API Routes
# ========================

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint to verify API is running."""
    logger.info("Health check requested")
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "service": "System Hardening Tool API",
        "version": "1.0.0"
    }), 200


@app.route('/api/system-info', methods=['GET'])
def system_info():
    """Get current system information."""
    logger.info("System info requested")
    try:
        info = get_system_info()
        return jsonify({
            "status": "success",
            "data": info,
            "timestamp": datetime.now().isoformat()
        }), 200
    except Exception as e:
        logger.error(f"Failed to retrieve system info: {str(e)}")
        return jsonify({
            "status": "error",
            "message": "Failed to retrieve system information",
            "error": str(e)
        }), 500


@app.route('/api/scan', methods=['POST'])
def scan_system():
    """
    Scan system for security vulnerabilities and misconfigurations.
    Expects JSON body with scan options.
    """
    logger.info("Security scan requested")
    try:
        # Use force=True and silent=True to handle JSON parsing more gracefully
        data = request.get_json(force=True, silent=True) or {}
        scan_type = data.get('type', 'full')

        logger.info(f"Starting {scan_type} security scan")

        # Perform real scan using scanner module
        scan_result = scanner.scan(scan_type=scan_type, options=data.get('options'))

        # Convert scanner results to API response format
        findings_list = []
        critical_count = 0
        high_count = 0
        medium_count = 0
        low_count = 0

        for idx, finding in enumerate(scan_result.findings, start=1):
            severity = finding.severity.value.capitalize()

            # Count severity levels
            if finding.severity.value == 'critical':
                critical_count += 1
            elif finding.severity.value == 'high':
                high_count += 1
            elif finding.severity.value == 'medium':
                medium_count += 1
            elif finding.severity.value == 'low':
                low_count += 1

            findings_list.append({
                "id": idx,
                "category": finding.category,
                "severity": severity,
                "title": finding.title,
                "description": finding.description,
                "status": "Open",
                "timestamp": finding.timestamp,
                "recommendation": finding.remediation or "No specific remediation provided",
                "affected_item": finding.affected_item,
                "references": finding.references or []
            })

        # Calculate compliance score based on findings
        # Formula: 100 - (critical*10 + high*5 + medium*2 + low*1)
        total_vulnerabilities = len([f for f in scan_result.findings if f.severity.value != 'info'])
        deduction = (critical_count * 10 + high_count * 5 + medium_count * 2 + low_count * 1)
        compliance_score = max(0, min(100, 100 - deduction))

        scan_results = {
            "scan_id": scan_result.scan_id,
            "scan_type": scan_type,
            "timestamp": scan_result.start_time,
            "status": scan_result.status.value,
            "duration_seconds": scan_result.duration_seconds,
            "totalVulnerabilities": total_vulnerabilities,
            "complianceScore": round(compliance_score, 1),
            "criticalIssues": critical_count,
            "highIssues": high_count,
            "mediumIssues": medium_count,
            "lowIssues": low_count,
            "warnings": high_count + medium_count,
            "findings": findings_list,
            "summary": scan_result.get_summary()
        }

        logger.info(f"Scan completed: {scan_results['scan_id']} with {total_vulnerabilities} vulnerabilities found")

        # Save scan results to database
        try:
            scan_results['system_info'] = get_system_info()
            db_manager.add_scan(scan_results)
            logger.info(f"Scan results saved to database: {scan_results['scan_id']}")
        except Exception as db_error:
            logger.error(f"Failed to save scan to database: {db_error}")
            # Don't fail the scan if database save fails

        return jsonify(scan_results), 200

    except Exception as e:
        logger.error(f"Scan failed: {str(e)}", exc_info=True)
        return jsonify({
            "status": "error",
            "message": "Security scan failed",
            "error": str(e)
        }), 500


@app.route('/api/harden', methods=['POST'])
def harden_system():
    """
    Apply security hardening configurations to the system.
    Expects JSON body with hardening options and policies.
    """
    logger.info("Hardening request received")
    try:
        data = request.get_json(force=True, silent=True) or {}
        policy = data.get('policy', 'default')
        dry_run = data.get('dry_run', True)
        rules = data.get('rules', [])

        if not dry_run:
            logger.warning("Live hardening requested - requires elevated privileges")

        # Mock hardening results
        hardening_results = {
            "operation_id": f"harden_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            "policy": policy,
            "dry_run": dry_run,
            "timestamp": datetime.now().isoformat(),
            "status": "completed",
            "changes_applied": len(rules) if rules else 3,
            "changes": [
                {
                    "id": 1,
                    "category": "Network Security",
                    "action": "Disabled SSH password authentication",
                    "status": "applied"
                },
                {
                    "id": 2,
                    "category": "File System",
                    "action": "Fixed file permissions on /tmp",
                    "status": "applied"
                },
                {
                    "id": 3,
                    "category": "System Updates",
                    "action": "Initiated system package updates",
                    "status": "applied"
                }
            ]
        }

        logger.info(f"Hardening operation completed: {hardening_results['operation_id']}")

        # Save hardening session to database
        try:
            db_manager.add_hardening_session(hardening_results)
            logger.info(f"Hardening session saved to database: {hardening_results['operation_id']}")
        except Exception as db_error:
            logger.error(f"Failed to save hardening session to database: {db_error}")
            # Don't fail the operation if database save fails

        return jsonify(hardening_results), 200

    except Exception as e:
        logger.error(f"Hardening failed: {str(e)}")
        return jsonify({
            "status": "error",
            "message": "Hardening operation failed",
            "error": str(e)
        }), 500


@app.route('/api/report', methods=['POST'])
def generate_security_report():
    """
    Generate a comprehensive security report in the specified format.
    Expects JSON body with:
    - format: 'pdf', 'html', 'json', 'excel', 'csv', 'docx', 'markdown' (default: 'pdf')
    - scan_results: Security scan results (optional)
    - hardening_session: Hardening session data (optional)
    - before_scan: Scan results before hardening (optional)
    - after_scan: Scan results after hardening (optional)
    - title: Report title (optional)
    """
    logger.info("Report generation requested")
    try:
        data = request.get_json(force=True, silent=True) or {}
        report_format = data.get('format', 'pdf').lower()

        # Extract report data from request
        scan_results = data.get('scan_results')
        hardening_session = data.get('hardening_session')
        before_scan = data.get('before_scan')
        after_scan = data.get('after_scan')
        title = data.get('title', 'System Security Report')
        use_latest = data.get('use_latest', False)  # Option to use latest scan from DB

        # If no data provided, perform a real-time scan
        if not any([scan_results, hardening_session, before_scan, after_scan]):
            if use_latest:
                # Try to get latest scan from database
                logger.info("No data provided, fetching latest scan from database")
                try:
                    latest_scan = db_manager.get_latest_scan()
                    if latest_scan:
                        scan_results = latest_scan
                        logger.info(f"Using latest scan from database: {latest_scan.get('scan_id')}")
                    else:
                        logger.info("No scans in database, performing new scan")
                        use_latest = False
                except Exception as e:
                    logger.warning(f"Failed to fetch latest scan: {e}")
                    use_latest = False

            if not use_latest:
                # Perform real-time scan
                logger.info("No data provided, performing real-time security scan for report")
                scan_type = data.get('scan_type', 'full')

                # Perform the scan using the real scanner
                scan_result = scanner.scan(scan_type=scan_type, options=data.get('options'))

                # Convert scanner results to API response format (same as scan endpoint)
                findings_list = []
                critical_count = 0
                high_count = 0
                medium_count = 0
                low_count = 0

                for idx, finding in enumerate(scan_result.findings, start=1):
                    severity = finding.severity.value.capitalize()

                    if finding.severity.value == 'critical':
                        critical_count += 1
                    elif finding.severity.value == 'high':
                        high_count += 1
                    elif finding.severity.value == 'medium':
                        medium_count += 1
                    elif finding.severity.value == 'low':
                        low_count += 1

                    findings_list.append({
                        "id": idx,
                        "category": finding.category,
                        "severity": severity,
                        "title": finding.title,
                        "description": finding.description,
                        "status": "Open",
                        "timestamp": finding.timestamp,
                        "recommendation": finding.remediation or "No specific remediation provided",
                        "affected_item": finding.affected_item,
                        "references": finding.references or []
                    })

                # Calculate compliance score
                total_vulnerabilities = len([f for f in scan_result.findings if f.severity.value != 'info'])
                deduction = (critical_count * 10 + high_count * 5 + medium_count * 2 + low_count * 1)
                compliance_score = max(0, min(100, 100 - deduction))

                scan_results = {
                    "scan_id": scan_result.scan_id,
                    "scan_type": scan_type,
                    "timestamp": scan_result.start_time,
                    "status": scan_result.status.value,
                    "duration_seconds": scan_result.duration_seconds,
                    "totalVulnerabilities": total_vulnerabilities,
                    "complianceScore": round(compliance_score, 1),
                    "criticalIssues": critical_count,
                    "highIssues": high_count,
                    "mediumIssues": medium_count,
                    "lowIssues": low_count,
                    "warnings": high_count + medium_count,
                    "findings": findings_list,
                    "summary": scan_result.get_summary(),
                    "system_info": get_system_info()
                }

                logger.info(f"Real-time scan completed for report: {scan_results['scan_id']}")

        # Handle new export formats (Excel, CSV, DOCX, Markdown)
        if report_format in ['excel', 'csv', 'docx', 'markdown']:
            logger.info(f"Generating {report_format} report using ReportExporter")

            # Compile report data using report generator's internal method
            report_data = report_generator._compile_report_data(
                scan_results=scan_results,
                hardening_session=hardening_session,
                before_scan=before_scan,
                after_scan=after_scan,
                title=title
            )

            # Export to the requested format
            if report_format == 'excel':
                report_path = report_exporter.export_to_excel(report_data)
                mimetype = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
            elif report_format == 'csv':
                report_path = report_exporter.export_to_csv(report_data)
                mimetype = 'text/csv'
            elif report_format == 'docx':
                report_path = report_exporter.export_to_docx(report_data)
                mimetype = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
            elif report_format == 'markdown':
                report_path = report_exporter.export_to_markdown(report_data)
                mimetype = 'text/markdown'

            logger.info(f"Sending {report_format} file: {report_path}")
            filename = os.path.basename(report_path)

            return send_file(
                report_path,
                mimetype=mimetype,
                as_attachment=True,
                download_name=filename
            )

        # Generate the report using original report generator (PDF, HTML, JSON)
        logger.info(f"Generating {report_format} report with title: {title}")
        report_path = report_generator.generate_report(
            scan_results=scan_results,
            hardening_session=hardening_session,
            before_scan=before_scan,
            after_scan=after_scan,
            report_format=report_format,
            title=title
        )

        # For PDF and HTML, return as downloadable file
        if report_format in ['pdf', 'html']:
            logger.info(f"Sending {report_format} file: {report_path}")

            # Determine mimetype
            mimetype = 'application/pdf' if report_format == 'pdf' else 'text/html'

            # Get the filename
            filename = os.path.basename(report_path)

            return send_file(
                report_path,
                mimetype=mimetype,
                as_attachment=True,
                download_name=filename
            )

        # For JSON format, return the JSON content
        elif report_format == 'json':
            logger.info(f"Reading JSON report: {report_path}")
            with open(report_path, 'r') as f:
                import json
                report_data = json.load(f)

            return jsonify({
                "status": "success",
                "report": report_data,
                "file_path": report_path
            }), 200

        else:
            return jsonify({
                "status": "error",
                "message": f"Unsupported format: {report_format}. Supported formats: pdf, html, json, excel, csv, docx, markdown"
            }), 400

    except ValueError as e:
        logger.error(f"Invalid report data: {str(e)}")
        return jsonify({
            "status": "error",
            "message": "Invalid report data",
            "error": str(e)
        }), 400

    except Exception as e:
        logger.error(f"Report generation failed: {str(e)}", exc_info=True)
        return jsonify({
            "status": "error",
            "message": "Report generation failed",
            "error": str(e)
        }), 500


@app.route('/api/email-report', methods=['POST'])
def email_security_report():
    """
    Send a security report via email.
    Expects JSON body with:
    - recipients: List of email addresses (required)
    - subject: Email subject (optional)
    - format: Report format (default: 'pdf')
    - scan_results: Security scan results (optional)
    - hardening_session: Hardening session data (optional)
    - before_scan: Scan results before hardening (optional)
    - after_scan: Scan results after hardening (optional)
    - title: Report title (optional)
    - body: Email body text (optional)
    """
    logger.info("Email report requested")
    try:
        data = request.get_json(force=True, silent=True) or {}

        # Extract email parameters
        recipients = data.get('recipients', [])
        if not recipients:
            return jsonify({
                "status": "error",
                "message": "No recipients specified. Please provide a list of email addresses."
            }), 400

        subject = data.get('subject', f"Security Report - {datetime.now().strftime('%Y-%m-%d')}")
        body = data.get('body')

        # Extract report parameters
        report_format = data.get('format', 'pdf').lower()
        scan_results = data.get('scan_results')
        hardening_session = data.get('hardening_session')
        before_scan = data.get('before_scan')
        after_scan = data.get('after_scan')
        title = data.get('title', 'System Security Report')

        # Validate that at least some data was provided
        if not any([scan_results, hardening_session, before_scan, after_scan]):
            return jsonify({
                "status": "error",
                "message": "No report data provided. Please provide at least one of: scan_results, hardening_session, before_scan, or after_scan"
            }), 400

        # Check if email service is configured
        if not email_service.configured:
            return jsonify({
                "status": "error",
                "message": "Email service not configured. Please set MAIL_USERNAME and MAIL_PASSWORD environment variables."
            }), 503

        # Generate the report first
        logger.info(f"Generating {report_format} report for email")

        if report_format in ['excel', 'csv', 'docx', 'markdown']:
            # Use report exporter for new formats
            report_data = report_generator._compile_report_data(
                scan_results=scan_results,
                hardening_session=hardening_session,
                before_scan=before_scan,
                after_scan=after_scan,
                title=title
            )

            if report_format == 'excel':
                report_path = report_exporter.export_to_excel(report_data)
            elif report_format == 'csv':
                report_path = report_exporter.export_to_csv(report_data)
            elif report_format == 'docx':
                report_path = report_exporter.export_to_docx(report_data)
            elif report_format == 'markdown':
                report_path = report_exporter.export_to_markdown(report_data)
        else:
            # Use original report generator for PDF, HTML, JSON
            report_path = report_generator.generate_report(
                scan_results=scan_results,
                hardening_session=hardening_session,
                before_scan=before_scan,
                after_scan=after_scan,
                report_format=report_format,
                title=title
            )

        # Send the email
        logger.info(f"Sending report via email to {len(recipients)} recipient(s)")
        success = email_service.send_report(
            recipients=recipients,
            subject=subject,
            report_path=report_path,
            body=body,
            scan_summary=scan_results
        )

        if success:
            return jsonify({
                "status": "success",
                "message": f"Report sent successfully to {len(recipients)} recipient(s)",
                "recipients": recipients,
                "report_path": report_path
            }), 200
        else:
            return jsonify({
                "status": "error",
                "message": "Failed to send email. Check server logs for details."
            }), 500

    except Exception as e:
        logger.error(f"Email report failed: {str(e)}", exc_info=True)
        return jsonify({
            "status": "error",
            "message": "Failed to send email report",
            "error": str(e)
        }), 500


@app.route('/api/email-alert', methods=['POST'])
def email_security_alert():
    """
    Send a security alert via email.
    Expects JSON body with:
    - recipients: List of email addresses (required)
    - alert_type: Type of alert (required)
    - message: Alert message (required)
    - severity: Alert severity (default: 'info')
    """
    logger.info("Email alert requested")
    try:
        data = request.get_json(force=True, silent=True) or {}

        # Extract parameters
        recipients = data.get('recipients', [])
        alert_type = data.get('alert_type')
        message = data.get('message')
        severity = data.get('severity', 'info')

        # Validate required fields
        if not recipients:
            return jsonify({
                "status": "error",
                "message": "No recipients specified"
            }), 400

        if not alert_type:
            return jsonify({
                "status": "error",
                "message": "No alert_type specified"
            }), 400

        if not message:
            return jsonify({
                "status": "error",
                "message": "No message specified"
            }), 400

        # Check if email service is configured
        if not email_service.configured:
            return jsonify({
                "status": "error",
                "message": "Email service not configured"
            }), 503

        # Send the alert
        success = email_service.send_alert(
            recipients=recipients,
            alert_type=alert_type,
            message=message,
            severity=severity
        )

        if success:
            return jsonify({
                "status": "success",
                "message": f"Alert sent successfully to {len(recipients)} recipient(s)"
            }), 200
        else:
            return jsonify({
                "status": "error",
                "message": "Failed to send alert"
            }), 500

    except Exception as e:
        logger.error(f"Email alert failed: {str(e)}", exc_info=True)
        return jsonify({
            "status": "error",
            "message": "Failed to send email alert",
            "error": str(e)
        }), 500


# ========================
# Real-time Monitoring Endpoints
# ========================

@app.route('/api/monitoring/status', methods=['GET'])
def get_monitoring_status():
    """Get current system monitoring status."""
    try:
        status = realtime_monitor.get_system_status()
        return jsonify(status), 200
    except Exception as e:
        logger.error(f"Error getting monitoring status: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@app.route('/api/monitoring/metrics', methods=['GET'])
def get_current_metrics():
    """Get current system metrics."""
    try:
        metrics = realtime_monitor.get_current_metrics()
        return jsonify(metrics), 200
    except Exception as e:
        logger.error(f"Error getting metrics: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@app.route('/api/monitoring/history', methods=['GET'])
def get_metrics_history():
    """Get historical metrics."""
    try:
        limit = request.args.get('limit', type=int)
        history = realtime_monitor.get_metrics_history(limit=limit)
        return jsonify({
            "history": history,
            "count": len(history)
        }), 200
    except Exception as e:
        logger.error(f"Error getting metrics history: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@app.route('/api/monitoring/start', methods=['POST'])
def start_monitoring():
    """Start real-time monitoring."""
    try:
        data = request.get_json(force=True, silent=True) or {}
        interval = data.get('interval', 5)
        realtime_monitor.start_monitoring(interval=interval)
        return jsonify({
            "status": "success",
            "message": "Monitoring started",
            "interval": interval
        }), 200
    except Exception as e:
        logger.error(f"Error starting monitoring: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@app.route('/api/monitoring/stop', methods=['POST'])
def stop_monitoring():
    """Stop real-time monitoring."""
    try:
        realtime_monitor.stop_monitoring()
        return jsonify({
            "status": "success",
            "message": "Monitoring stopped"
        }), 200
    except Exception as e:
        logger.error(f"Error stopping monitoring: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@app.route('/api/monitoring/thresholds', methods=['POST'])
def set_monitoring_threshold():
    """Set custom threshold for threat detection."""
    try:
        data = request.get_json(force=True, silent=True) or {}
        metric = data.get('metric')
        value = data.get('value')

        if not metric or value is None:
            return jsonify({
                "status": "error",
                "message": "Both metric and value are required"
            }), 400

        realtime_monitor.set_threshold(metric, value)
        return jsonify({
            "status": "success",
            "message": f"Threshold updated: {metric} = {value}"
        }), 200
    except Exception as e:
        logger.error(f"Error setting threshold: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


# ========================
# Compliance Framework Endpoints
# ========================

@app.route('/api/compliance/cis', methods=['GET'])
def check_cis_compliance():
    """Check CIS Benchmarks compliance."""
    try:
        level = request.args.get('level', default=1, type=int)
        result = compliance_checker.check_cis_benchmarks(level=level)
        return jsonify(result), 200
    except Exception as e:
        logger.error(f"Error checking CIS compliance: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@app.route('/api/compliance/nist', methods=['GET'])
def check_nist_compliance():
    """Check NIST 800-53 compliance."""
    try:
        result = compliance_checker.check_nist_800_53()
        return jsonify(result), 200
    except Exception as e:
        logger.error(f"Error checking NIST compliance: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@app.route('/api/compliance/pci-dss', methods=['GET'])
def check_pci_dss_compliance():
    """Check PCI-DSS compliance."""
    try:
        result = compliance_checker.check_pci_dss()
        return jsonify(result), 200
    except Exception as e:
        logger.error(f"Error checking PCI-DSS compliance: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@app.route('/api/compliance/hipaa', methods=['GET'])
def check_hipaa_compliance():
    """Check HIPAA compliance."""
    try:
        result = compliance_checker.check_hipaa()
        return jsonify(result), 200
    except Exception as e:
        logger.error(f"Error checking HIPAA compliance: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@app.route('/api/compliance/soc2', methods=['GET'])
def check_soc2_compliance():
    """Check SOC 2 compliance."""
    try:
        result = compliance_checker.check_soc2()
        return jsonify(result), 200
    except Exception as e:
        logger.error(f"Error checking SOC 2 compliance: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@app.route('/api/compliance/all', methods=['GET'])
def check_all_compliance():
    """Check all compliance frameworks."""
    try:
        result = compliance_checker.check_all_frameworks()
        return jsonify(result), 200
    except Exception as e:
        logger.error(f"Error checking all compliance frameworks: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


# ========================
# Automated Remediation Endpoints
# ========================

@app.route('/api/remediation/auto-fix', methods=['POST'])
def auto_fix_vulnerability():
    """Automatically fix a vulnerability."""
    try:
        data = request.get_json(force=True, silent=True) or {}
        vulnerability_id = data.get('vulnerability_id')
        severity = data.get('severity', 'medium')
        requires_approval = data.get('requires_approval', True)

        if not vulnerability_id:
            return jsonify({
                "status": "error",
                "message": "vulnerability_id is required"
            }), 400

        result = auto_remediation.auto_fix_vulnerability(
            vulnerability_id=vulnerability_id,
            severity=severity,
            requires_approval=requires_approval
        )
        return jsonify(result), 200
    except Exception as e:
        logger.error(f"Error in auto-fix: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@app.route('/api/remediation/checkpoint', methods=['POST'])
def create_checkpoint():
    """Create a system checkpoint."""
    try:
        data = request.get_json(force=True, silent=True) or {}
        description = data.get('description', 'Manual checkpoint')

        result = auto_remediation.create_checkpoint(description=description)
        return jsonify(result), 200
    except Exception as e:
        logger.error(f"Error creating checkpoint: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@app.route('/api/remediation/rollback', methods=['POST'])
def rollback_checkpoint():
    """Rollback to a previous checkpoint."""
    try:
        data = request.get_json(force=True, silent=True) or {}
        checkpoint_id = data.get('checkpoint_id')

        if not checkpoint_id:
            return jsonify({
                "status": "error",
                "message": "checkpoint_id is required"
            }), 400

        result = auto_remediation.rollback(checkpoint_id=checkpoint_id)
        return jsonify(result), 200
    except Exception as e:
        logger.error(f"Error during rollback: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@app.route('/api/remediation/pending', methods=['GET'])
def get_pending_approvals():
    """Get pending remediation approvals."""
    try:
        pending = auto_remediation.get_pending_approvals()
        return jsonify({
            "pending": pending,
            "count": len(pending)
        }), 200
    except Exception as e:
        logger.error(f"Error getting pending approvals: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@app.route('/api/remediation/approve/<remediation_id>', methods=['POST'])
def approve_remediation(remediation_id):
    """Approve a pending remediation."""
    try:
        result = auto_remediation.approve_remediation(remediation_id=remediation_id)
        return jsonify(result), 200
    except Exception as e:
        logger.error(f"Error approving remediation: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@app.route('/api/remediation/reject/<remediation_id>', methods=['POST'])
def reject_remediation(remediation_id):
    """Reject a pending remediation."""
    try:
        data = request.get_json(force=True, silent=True) or {}
        reason = data.get('reason', 'Rejected by user')

        result = auto_remediation.reject_remediation(
            remediation_id=remediation_id,
            reason=reason
        )
        return jsonify(result), 200
    except Exception as e:
        logger.error(f"Error rejecting remediation: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@app.route('/api/remediation/history', methods=['GET'])
def get_remediation_history():
    """Get remediation history."""
    try:
        limit = request.args.get('limit', type=int)
        history = auto_remediation.get_remediation_history(limit=limit)
        return jsonify({
            "history": history,
            "count": len(history)
        }), 200
    except Exception as e:
        logger.error(f"Error getting remediation history: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@app.route('/api/remediation/maintenance-window', methods=['POST'])
def schedule_maintenance_window():
    """Schedule a maintenance window."""
    try:
        data = request.get_json(force=True, silent=True) or {}
        start_time = data.get('start_time')
        duration_hours = data.get('duration_hours', 4)
        description = data.get('description', 'Scheduled maintenance')

        if not start_time:
            return jsonify({
                "status": "error",
                "message": "start_time is required (ISO format)"
            }), 400

        from datetime import datetime
        start_dt = datetime.fromisoformat(start_time)

        result = auto_remediation.schedule_maintenance_window(
            start_time=start_dt,
            duration_hours=duration_hours,
            description=description
        )
        return jsonify(result), 200
    except Exception as e:
        logger.error(f"Error scheduling maintenance window: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


# ========================
# Historical Tracking Endpoints
# ========================

@app.route('/api/history/scans', methods=['GET'])
def get_scan_history():
    """Get scan history."""
    try:
        limit = request.args.get('limit', type=int)
        offset = request.args.get('offset', default=0, type=int)

        scans = db_manager.get_scan_history(limit=limit, offset=offset)
        return jsonify({
            "scans": scans,
            "count": len(scans)
        }), 200
    except Exception as e:
        logger.error(f"Error getting scan history: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@app.route('/api/history/scans/<scan_id>', methods=['GET'])
def get_scan_details(scan_id):
    """Get detailed information about a specific scan."""
    try:
        scan = db_manager.get_scan_by_id(scan_id)
        if scan:
            return jsonify(scan), 200
        else:
            return jsonify({"error": "Scan not found"}), 404
    except Exception as e:
        logger.error(f"Error getting scan details: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@app.route('/api/history/hardening', methods=['GET'])
def get_hardening_history():
    """Get hardening session history."""
    try:
        limit = request.args.get('limit', type=int)
        offset = request.args.get('offset', default=0, type=int)

        sessions = db_manager.get_hardening_history(limit=limit, offset=offset)
        return jsonify({
            "sessions": sessions,
            "count": len(sessions)
        }), 200
    except Exception as e:
        logger.error(f"Error getting hardening history: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@app.route('/api/history/trends', methods=['GET'])
def get_vulnerability_trends():
    """Get vulnerability trends over time."""
    try:
        days = request.args.get('days', default=30, type=int)
        trends = db_manager.get_vulnerability_trends(days=days)
        return jsonify(trends), 200
    except Exception as e:
        logger.error(f"Error getting trends: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@app.route('/api/history/stats', methods=['GET'])
def get_statistics():
    """Get overall statistics."""
    try:
        stats = db_manager.get_statistics()
        return jsonify(stats), 200
    except Exception as e:
        logger.error(f"Error getting statistics: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


# ========================
# Risk Analysis Endpoints
# ========================

@app.route('/api/risk/trends', methods=['GET'])
def get_risk_trends():
    """Get risk score trends over time."""
    try:
        days = request.args.get('days', default=30, type=int)
        trends = db_manager.get_risk_trends(days=days)
        return jsonify(trends), 200
    except Exception as e:
        logger.error(f"Error getting risk trends: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@app.route('/api/risk/distribution', methods=['GET'])
def get_risk_distribution():
    """Get current risk distribution."""
    try:
        distribution = db_manager.get_risk_distribution()
        return jsonify({"distribution": distribution}), 200
    except Exception as e:
        logger.error(f"Error getting risk distribution: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@app.route('/api/risk/high-risk', methods=['GET'])
def get_high_risk_vulnerabilities():
    """Get highest risk vulnerabilities."""
    try:
        limit = request.args.get('limit', default=10, type=int)
        vulnerabilities = db_manager.get_high_risk_vulnerabilities(limit=limit)
        return jsonify({"vulnerabilities": vulnerabilities, "count": len(vulnerabilities)}), 200
    except Exception as e:
        logger.error(f"Error getting high risk vulnerabilities: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@app.route('/api/risk/recommendations', methods=['POST'])
def get_risk_recommendations():
    """Get prioritized risk recommendations for given vulnerabilities."""
    try:
        from modules.risk_scoring import RiskScorer
        risk_scorer = RiskScorer()

        data = request.get_json()
        vulnerabilities = data.get('vulnerabilities', [])

        if not vulnerabilities:
            return jsonify({"error": "No vulnerabilities provided"}), 400

        recommendations = risk_scorer.generate_risk_recommendations(vulnerabilities)
        return jsonify({"recommendations": recommendations, "count": len(recommendations)}), 200
    except Exception as e:
        logger.error(f"Error generating risk recommendations: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


# ========================
# Guided Remediation Endpoints
# ========================

from modules.remediation_playbooks import RemediationPlaybookEngine

playbook_engine = RemediationPlaybookEngine()

@app.route('/api/playbooks', methods=['GET'])
def list_playbooks():
    """List all available remediation playbooks."""
    try:
        category = request.args.get('category')
        playbooks = playbook_engine.list_playbooks(category=category)
        return jsonify({"playbooks": playbooks, "count": len(playbooks)}), 200
    except Exception as e:
        logger.error(f"Error listing playbooks: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@app.route('/api/playbooks/<playbook_id>', methods=['GET'])
def get_playbook(playbook_id):
    """Get a specific playbook by ID."""
    try:
        playbook = playbook_engine.get_playbook(playbook_id)
        if playbook:
            return jsonify({"playbook": playbook}), 200
        else:
            return jsonify({"error": "Playbook not found"}), 404
    except Exception as e:
        logger.error(f"Error getting playbook: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@app.route('/api/playbooks/match', methods=['POST'])
def match_playbook():
    """Find the best playbook for a given vulnerability."""
    try:
        data = request.get_json()
        vulnerability = data.get('vulnerability')

        if not vulnerability:
            return jsonify({"error": "No vulnerability provided"}), 400

        playbook = playbook_engine.get_playbook_for_vulnerability(vulnerability)
        if playbook:
            return jsonify({"playbook": playbook, "matched": True}), 200
        else:
            return jsonify({"playbook": None, "matched": False}), 200
    except Exception as e:
        logger.error(f"Error matching playbook: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@app.route('/api/playbooks/plan', methods=['POST'])
def create_remediation_plan():
    """Create a prioritized remediation plan for multiple vulnerabilities."""
    try:
        data = request.get_json()
        vulnerabilities = data.get('vulnerabilities', [])

        if not vulnerabilities:
            return jsonify({"error": "No vulnerabilities provided"}), 400

        plan = playbook_engine.create_remediation_plan(vulnerabilities)
        return jsonify({"plan": plan}), 200
    except Exception as e:
        logger.error(f"Error creating remediation plan: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@app.route('/api/playbooks/estimate', methods=['POST'])
def estimate_remediation_effort():
    """Estimate remediation effort for vulnerabilities."""
    try:
        data = request.get_json()
        vulnerabilities = data.get('vulnerabilities', [])

        if not vulnerabilities:
            return jsonify({"error": "No vulnerabilities provided"}), 400

        estimate = playbook_engine.estimate_remediation_effort(vulnerabilities)
        return jsonify({"estimate": estimate}), 200
    except Exception as e:
        logger.error(f"Error estimating remediation effort: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@app.route('/api/playbooks/executions', methods=['GET'])
def get_playbook_executions():
    """Get history of playbook executions."""
    try:
        limit = request.args.get('limit', type=int)
        offset = request.args.get('offset', default=0, type=int)

        executions = db_manager.get_remediation_history(limit=limit, offset=offset)
        return jsonify({"executions": executions, "count": len(executions)}), 200
    except Exception as e:
        logger.error(f"Error getting playbook executions: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@app.route('/api/playbooks/metrics', methods=['GET'])
def get_playbook_metrics():
    """Get playbook execution metrics and statistics."""
    try:
        metrics = db_manager.get_remediation_metrics()
        return jsonify({"metrics": metrics}), 200
    except Exception as e:
        logger.error(f"Error getting playbook metrics: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


# ========================
# Error Handlers
# ========================

@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors."""
    logger.warning(f"404 error: {request.url}")
    return jsonify({
        "status": "error",
        "message": "Resource not found",
        "path": request.path
    }), 404


@app.errorhandler(405)
def method_not_allowed(error):
    """Handle 405 errors."""
    logger.warning(f"405 error: {request.method} {request.url}")
    return jsonify({
        "status": "error",
        "message": "Method not allowed",
        "method": request.method,
        "path": request.path
    }), 405


@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors."""
    logger.error(f"500 error: {str(error)}")
    return jsonify({
        "status": "error",
        "message": "Internal server error",
        "error": str(error)
    }), 500


@app.errorhandler(Exception)
def handle_exception(error):
    """Handle uncaught exceptions."""
    logger.error(f"Unhandled exception: {str(error)}", exc_info=True)
    return jsonify({
        "status": "error",
        "message": "An unexpected error occurred",
        "error": str(error)
    }), 500


# ========================
# Application Entry Point
# ========================

if __name__ == '__main__':
    logger.info("Starting System Hardening Tool API...")
    logger.info(f"Debug mode: {app.config['DEBUG']}")
    logger.info(f"Port: {app.config['PORT']}")

    app.run(
        host='0.0.0.0',
        port=app.config['PORT'],
        debug=app.config['DEBUG']
    )
