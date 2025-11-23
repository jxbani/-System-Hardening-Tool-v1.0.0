#!/usr/bin/env python3
"""
Email Service Module
Handles sending security reports via email
"""

import os
import logging
from pathlib import Path
from typing import List, Optional, Dict, Any
from flask import Flask
from flask_mail import Mail, Message
from datetime import datetime

logger = logging.getLogger(__name__)


class EmailService:
    """
    Service for sending email notifications and reports.
    """

    def __init__(self, app: Optional[Flask] = None):
        """
        Initialize email service.

        Args:
            app: Flask application instance
        """
        self.mail = None
        self.configured = False

        if app:
            self.init_app(app)

    def init_app(self, app: Flask):
        """
        Initialize with Flask app.

        Args:
            app: Flask application instance
        """
        # Configure Flask-Mail from environment variables or config
        app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
        app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
        app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'True').lower() == 'true'
        app.config['MAIL_USE_SSL'] = os.getenv('MAIL_USE_SSL', 'False').lower() == 'true'
        app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME', '')
        app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD', '')
        app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER', 'security@hardening-tool.com')

        self.mail = Mail(app)
        self.configured = bool(app.config['MAIL_USERNAME'] and app.config['MAIL_PASSWORD'])

        if self.configured:
            logger.info(f"Email service configured with SMTP server: {app.config['MAIL_SERVER']}")
        else:
            logger.warning("Email service not fully configured - set MAIL_USERNAME and MAIL_PASSWORD")

    def send_report(
        self,
        recipients: List[str],
        subject: str,
        report_path: str,
        body: Optional[str] = None,
        scan_summary: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Send security report via email.

        Args:
            recipients: List of email addresses
            subject: Email subject
            report_path: Path to the report file to attach
            body: Optional email body text
            scan_summary: Optional scan summary for email body

        Returns:
            True if sent successfully, False otherwise
        """
        if not self.configured:
            logger.error("Email service not configured")
            return False

        if not recipients:
            logger.error("No recipients specified")
            return False

        try:
            # Create message
            msg = Message(
                subject=subject,
                recipients=recipients
            )

            # Generate email body
            if body:
                msg.body = body
            else:
                msg.body = self._generate_email_body(scan_summary)

            # Attach report file
            if report_path and os.path.exists(report_path):
                with open(report_path, 'rb') as f:
                    filename = os.path.basename(report_path)
                    msg.attach(
                        filename=filename,
                        content_type=self._get_content_type(filename),
                        data=f.read()
                    )
                logger.info(f"Attached report: {filename}")

            # Send email
            self.mail.send(msg)
            logger.info(f"Email sent successfully to {len(recipients)} recipient(s)")
            return True

        except Exception as e:
            logger.error(f"Failed to send email: {e}", exc_info=True)
            return False

    def send_alert(
        self,
        recipients: List[str],
        alert_type: str,
        message: str,
        severity: str = "info"
    ) -> bool:
        """
        Send security alert email.

        Args:
            recipients: List of email addresses
            alert_type: Type of alert (e.g., "Critical Finding", "Scan Complete")
            message: Alert message
            severity: Alert severity (critical, high, medium, low, info)

        Returns:
            True if sent successfully, False otherwise
        """
        if not self.configured:
            logger.error("Email service not configured")
            return False

        try:
            severity_icons = {
                'critical': '🔴',
                'high': '🟠',
                'medium': '🟡',
                'low': '🔵',
                'info': 'ℹ️'
            }

            icon = severity_icons.get(severity.lower(), 'ℹ️')
            subject = f"{icon} Security Alert: {alert_type}"

            msg = Message(
                subject=subject,
                recipients=recipients,
                body=f"""
Security Alert - System Hardening Tool

Alert Type: {alert_type}
Severity: {severity.upper()}
Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Message:
{message}

---
This is an automated alert from the System Hardening Tool.
                """.strip()
            )

            self.mail.send(msg)
            logger.info(f"Alert sent to {len(recipients)} recipient(s): {alert_type}")
            return True

        except Exception as e:
            logger.error(f"Failed to send alert: {e}", exc_info=True)
            return False

    def send_scheduled_report(
        self,
        recipients: List[str],
        report_path: str,
        scan_summary: Dict[str, Any],
        schedule_type: str = "daily"
    ) -> bool:
        """
        Send scheduled security report.

        Args:
            recipients: List of email addresses
            report_path: Path to report file
            scan_summary: Scan summary data
            schedule_type: Type of schedule (daily, weekly, monthly)

        Returns:
            True if sent successfully, False otherwise
        """
        subject = f"Scheduled {schedule_type.capitalize()} Security Report - {datetime.now().strftime('%Y-%m-%d')}"

        body = f"""
Automated {schedule_type.capitalize()} Security Report

This is your scheduled security compliance report for {datetime.now().strftime('%B %d, %Y')}.

"""
        if scan_summary:
            body += self._generate_email_body(scan_summary)

        body += """

The detailed report is attached.

---
System Hardening Tool - Automated Report
"""

        return self.send_report(
            recipients=recipients,
            subject=subject,
            report_path=report_path,
            body=body,
            scan_summary=scan_summary
        )

    def _generate_email_body(self, scan_summary: Optional[Dict[str, Any]]) -> str:
        """
        Generate email body from scan summary.

        Args:
            scan_summary: Scan summary data

        Returns:
            Formatted email body text
        """
        body = """
Security Scan Report

"""

        if scan_summary:
            if 'compliance' in scan_summary and 'current_score' in scan_summary['compliance']:
                body += f"Overall Compliance Score: {scan_summary['compliance']['current_score']}%\n\n"

            if 'scan_summary' in scan_summary:
                ss = scan_summary['scan_summary']
                body += f"Total Findings: {ss.get('total_findings', 0)}\n"
                body += f"  - Critical: {ss.get('critical', 0)}\n"
                body += f"  - High: {ss.get('high', 0)}\n"
                body += f"  - Medium: {ss.get('medium', 0)}\n"
                body += f"  - Low: {ss.get('low', 0)}\n\n"

            if 'hardening_summary' in scan_summary:
                hs = scan_summary['hardening_summary']
                body += f"Hardening Actions:\n"
                body += f"  - Total Rules: {hs.get('total_rules', 0)}\n"
                body += f"  - Successful: {hs.get('successful_rules', 0)}\n"
                body += f"  - Failed: {hs.get('failed_rules', 0)}\n\n"

        body += "Please review the attached report for detailed information.\n"

        return body

    def _get_content_type(self, filename: str) -> str:
        """
        Get content type based on file extension.

        Args:
            filename: File name

        Returns:
            MIME content type
        """
        extension = Path(filename).suffix.lower()
        content_types = {
            '.pdf': 'application/pdf',
            '.html': 'text/html',
            '.csv': 'text/csv',
            '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            '.md': 'text/markdown',
            '.json': 'application/json'
        }
        return content_types.get(extension, 'application/octet-stream')

    def test_connection(self) -> bool:
        """
        Test email connection configuration.

        Returns:
            True if connection successful, False otherwise
        """
        if not self.configured:
            logger.error("Email not configured")
            return False

        try:
            # Try to send a test message (without actually sending)
            with self.mail.connect() as conn:
                logger.info("Email connection test successful")
                return True
        except Exception as e:
            logger.error(f"Email connection test failed: {e}")
            return False


# Example usage
if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    print("=" * 70)
    print("Email Service - Configuration Test")
    print("=" * 70)

    # Create Flask app for testing
    app = Flask(__name__)
    email_service = EmailService(app)

    if email_service.configured:
        print("✓ Email service is configured")
        print(f"  SMTP Server: {app.config['MAIL_SERVER']}")
        print(f"  Port: {app.config['MAIL_PORT']}")
        print(f"  Username: {app.config['MAIL_USERNAME']}")

        # Test connection
        if email_service.test_connection():
            print("✓ Email connection test passed")
        else:
            print("✗ Email connection test failed")
    else:
        print("✗ Email service not configured")
        print("\nTo configure email, set these environment variables:")
        print("  MAIL_SERVER=smtp.gmail.com")
        print("  MAIL_PORT=587")
        print("  MAIL_USERNAME=your-email@gmail.com")
        print("  MAIL_PASSWORD=your-app-password")
        print("  MAIL_DEFAULT_SENDER=your-email@gmail.com")

    print("=" * 70)
