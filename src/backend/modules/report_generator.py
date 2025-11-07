#!/usr/bin/env python3
"""
Report Generator Module
Generates comprehensive security reports from scan results and hardening actions.
"""

import os
import json
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple
from collections import Counter

try:
    from jinja2 import Environment, FileSystemLoader, select_autoescape
except ImportError:
    logging.warning("Jinja2 not installed. Install with: pip install jinja2")
    Environment = None

logger = logging.getLogger(__name__)


class ReportGenerator:
    """
    Generates security compliance reports with charts and analysis.
    """

    def __init__(self, template_dir: Optional[str] = None, output_dir: Optional[str] = None):
        """
        Initialize the report generator.

        Args:
            template_dir: Directory containing report templates
            output_dir: Directory for saving generated reports
        """
        # Set template directory
        if template_dir:
            self.template_dir = Path(template_dir)
        else:
            # Default: config/templates
            project_root = Path(__file__).parent.parent.parent.parent
            self.template_dir = project_root / "config" / "templates"

        # Set output directory
        if output_dir:
            self.output_dir = Path(output_dir)
        else:
            # Default: reports directory in project root
            project_root = Path(__file__).parent.parent.parent.parent
            self.output_dir = project_root / "reports"

        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Initialize Jinja2 environment
        if Environment:
            self.jinja_env = Environment(
                loader=FileSystemLoader(str(self.template_dir)),
                autoescape=select_autoescape(['html', 'xml'])
            )
        else:
            self.jinja_env = None
            logger.warning("Jinja2 not available - HTML reports disabled")

        logger.info(f"ReportGenerator initialized (templates: {self.template_dir}, output: {self.output_dir})")

    def generate_report(
        self,
        scan_results: Optional[Dict[str, Any]] = None,
        hardening_session: Optional[Dict[str, Any]] = None,
        before_scan: Optional[Dict[str, Any]] = None,
        after_scan: Optional[Dict[str, Any]] = None,
        report_format: str = "html",
        title: str = "Security Compliance Report"
    ) -> str:
        """
        Generate a comprehensive security report.

        Args:
            scan_results: Results from security scan
            hardening_session: Results from hardening session
            before_scan: Scan results before hardening
            after_scan: Scan results after hardening
            report_format: Output format ('html', 'pdf', 'json')
            title: Report title

        Returns:
            str: Path to generated report file

        Raises:
            ValueError: If no data provided or invalid format
        """
        if not any([scan_results, hardening_session, before_scan, after_scan]):
            raise ValueError("At least one data source must be provided")

        logger.info(f"Generating {report_format} report: {title}")

        # Compile report data
        report_data = self._compile_report_data(
            scan_results=scan_results,
            hardening_session=hardening_session,
            before_scan=before_scan,
            after_scan=after_scan,
            title=title
        )

        # Generate report based on format
        if report_format.lower() == "html":
            return self._generate_html_report(report_data)
        elif report_format.lower() == "pdf":
            return self._generate_pdf_report(report_data)
        elif report_format.lower() == "json":
            return self._generate_json_report(report_data)
        else:
            raise ValueError(f"Unsupported report format: {report_format}")

    def _compile_report_data(
        self,
        scan_results: Optional[Dict] = None,
        hardening_session: Optional[Dict] = None,
        before_scan: Optional[Dict] = None,
        after_scan: Optional[Dict] = None,
        title: str = "Security Report"
    ) -> Dict[str, Any]:
        """
        Compile all report data into a structured format.

        Args:
            scan_results: Scan results
            hardening_session: Hardening session data
            before_scan: Before hardening scan
            after_scan: After hardening scan
            title: Report title

        Returns:
            Dict containing all report data
        """
        report_data = {
            "title": title,
            "generated_at": datetime.now().isoformat(),
            "generated_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "metadata": {},
            "scan_summary": {},
            "hardening_summary": {},
            "compliance": {},
            "before_after": {},
            "charts": {},
            "timeline": [],
            "recommendations": []
        }

        # Process scan results
        if scan_results:
            report_data["scan_summary"] = self._process_scan_results(scan_results)

        # Process hardening session
        if hardening_session:
            report_data["hardening_summary"] = self._process_hardening_session(hardening_session)
            report_data["timeline"] = self._generate_timeline(hardening_session)

        # Process before/after comparison
        if before_scan and after_scan:
            report_data["before_after"] = self._create_before_after_comparison(before_scan, after_scan)
            report_data["compliance"] = self._calculate_compliance_improvement(before_scan, after_scan)

        # Calculate compliance score
        if scan_results:
            report_data["compliance"]["current_score"] = self._calculate_compliance_score(scan_results)
        elif after_scan:
            report_data["compliance"]["current_score"] = self._calculate_compliance_score(after_scan)

        # Generate chart data
        report_data["charts"] = self._generate_chart_data(
            scan_results=scan_results,
            hardening_session=hardening_session,
            before_scan=before_scan,
            after_scan=after_scan
        )

        # Generate recommendations
        report_data["recommendations"] = self._generate_recommendations(
            scan_results or after_scan,
            hardening_session
        )

        return report_data

    def _process_scan_results(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Process scan results into summary format."""
        summary = {
            "total_findings": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
            "findings": []
        }

        # Extract findings
        findings = scan_results.get("findings", [])
        summary["total_findings"] = len(findings)

        # Count by severity
        severity_counts = Counter(
            finding.get("severity", "info").lower()
            for finding in findings
        )

        summary["critical"] = severity_counts.get("critical", 0)
        summary["high"] = severity_counts.get("high", 0)
        summary["medium"] = severity_counts.get("medium", 0)
        summary["low"] = severity_counts.get("low", 0)
        summary["info"] = severity_counts.get("info", 0)

        # Process findings
        summary["findings"] = [
            {
                "title": finding.get("title", "Unknown"),
                "severity": finding.get("severity", "info"),
                "description": finding.get("description", ""),
                "category": finding.get("category", "General"),
                "remediation": finding.get("remediation", "")
            }
            for finding in findings[:50]  # Limit to top 50 for report
        ]

        return summary

    def _process_hardening_session(self, session: Dict[str, Any]) -> Dict[str, Any]:
        """Process hardening session into summary format."""
        summary = {
            "session_id": session.get("session_id", ""),
            "start_time": session.get("start_time", ""),
            "end_time": session.get("end_time", ""),
            "total_rules": session.get("total_rules", 0),
            "successful_rules": session.get("successful_rules", 0),
            "failed_rules": session.get("failed_rules", 0),
            "skipped_rules": session.get("skipped_rules", 0),
            "checkpoint_id": session.get("checkpoint_id", ""),
            "rollback_performed": session.get("rollback_performed", False),
            "results": []
        }

        # Process individual rule results
        results = session.get("results", [])
        summary["results"] = [
            {
                "rule_id": result.get("rule_id", ""),
                "rule_name": result.get("rule_name", ""),
                "status": result.get("status", ""),
                "severity": result.get("rule_severity", ""),
                "before_value": result.get("before_value", ""),
                "after_value": result.get("after_value", ""),
                "duration": result.get("duration_seconds", 0),
                "error": result.get("error_message", "")
            }
            for result in results
        ]

        return summary

    def _create_before_after_comparison(
        self,
        before: Dict[str, Any],
        after: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Create before/after comparison of security posture.

        Args:
            before: Scan results before hardening
            after: Scan results after hardening

        Returns:
            Dict containing comparison data
        """
        before_summary = self._process_scan_results(before)
        after_summary = self._process_scan_results(after)

        comparison = {
            "before": {
                "total": before_summary["total_findings"],
                "critical": before_summary["critical"],
                "high": before_summary["high"],
                "medium": before_summary["medium"],
                "low": before_summary["low"]
            },
            "after": {
                "total": after_summary["total_findings"],
                "critical": after_summary["critical"],
                "high": after_summary["high"],
                "medium": after_summary["medium"],
                "low": after_summary["low"]
            },
            "improvements": {
                "total_reduction": before_summary["total_findings"] - after_summary["total_findings"],
                "critical_reduction": before_summary["critical"] - after_summary["critical"],
                "high_reduction": before_summary["high"] - after_summary["high"],
                "medium_reduction": before_summary["medium"] - after_summary["medium"],
                "low_reduction": before_summary["low"] - after_summary["low"]
            }
        }

        # Calculate percentage improvements
        if before_summary["total_findings"] > 0:
            comparison["improvement_percentage"] = round(
                (comparison["improvements"]["total_reduction"] / before_summary["total_findings"]) * 100,
                1
            )
        else:
            comparison["improvement_percentage"] = 0

        return comparison

    def _calculate_compliance_score(self, scan_results: Dict[str, Any]) -> float:
        """
        Calculate compliance score based on scan results.

        Score calculation:
        - Start with 100
        - Deduct points based on severity:
          * Critical: -10 points each
          * High: -5 points each
          * Medium: -2 points each
          * Low: -0.5 points each

        Args:
            scan_results: Scan results

        Returns:
            Compliance score (0-100)
        """
        summary = self._process_scan_results(scan_results)

        deductions = (
            summary["critical"] * 10 +
            summary["high"] * 5 +
            summary["medium"] * 2 +
            summary["low"] * 0.5
        )

        score = max(0, min(100, 100 - deductions))
        return round(score, 1)

    def _calculate_compliance_improvement(
        self,
        before: Dict[str, Any],
        after: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Calculate compliance improvement metrics."""
        before_score = self._calculate_compliance_score(before)
        after_score = self._calculate_compliance_score(after)

        return {
            "before_score": before_score,
            "after_score": after_score,
            "improvement": round(after_score - before_score, 1),
            "improvement_percentage": round(
                ((after_score - before_score) / max(1, 100 - before_score)) * 100,
                1
            ) if before_score < 100 else 0
        }

    def _generate_timeline(self, session: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate timeline of hardening actions."""
        timeline = []

        results = session.get("results", [])

        for result in results:
            timeline.append({
                "time": result.get("end_time", ""),
                "rule_name": result.get("rule_name", ""),
                "status": result.get("status", ""),
                "duration": result.get("duration_seconds", 0),
                "icon": self._get_status_icon(result.get("status", ""))
            })

        return timeline

    def _get_status_icon(self, status: str) -> str:
        """Get icon for status."""
        icons = {
            "success": "✓",
            "failed": "✗",
            "skipped": "⊘",
            "in_progress": "⟳",
            "pending": "○"
        }
        return icons.get(status, "○")

    def _generate_chart_data(
        self,
        scan_results: Optional[Dict] = None,
        hardening_session: Optional[Dict] = None,
        before_scan: Optional[Dict] = None,
        after_scan: Optional[Dict] = None
    ) -> Dict[str, Any]:
        """Generate data for charts."""
        charts = {}

        # Severity distribution chart
        if scan_results:
            summary = self._process_scan_results(scan_results)
            charts["severity_distribution"] = {
                "labels": ["Critical", "High", "Medium", "Low", "Info"],
                "data": [
                    summary["critical"],
                    summary["high"],
                    summary["medium"],
                    summary["low"],
                    summary["info"]
                ],
                "colors": ["#dc3545", "#fd7e14", "#ffc107", "#17a2b8", "#6c757d"]
            }

        # Compliance improvement chart
        if before_scan and after_scan:
            before_summary = self._process_scan_results(before_scan)
            after_summary = self._process_scan_results(after_scan)

            charts["compliance_improvement"] = {
                "labels": ["Before", "After"],
                "datasets": [
                    {
                        "label": "Critical",
                        "data": [before_summary["critical"], after_summary["critical"]],
                        "color": "#dc3545"
                    },
                    {
                        "label": "High",
                        "data": [before_summary["high"], after_summary["high"]],
                        "color": "#fd7e14"
                    },
                    {
                        "label": "Medium",
                        "data": [before_summary["medium"], after_summary["medium"]],
                        "color": "#ffc107"
                    },
                    {
                        "label": "Low",
                        "data": [before_summary["low"], after_summary["low"]],
                        "color": "#17a2b8"
                    }
                ]
            }

        # Hardening session results chart
        if hardening_session:
            charts["hardening_results"] = {
                "labels": ["Success", "Failed", "Skipped"],
                "data": [
                    hardening_session.get("successful_rules", 0),
                    hardening_session.get("failed_rules", 0),
                    hardening_session.get("skipped_rules", 0)
                ],
                "colors": ["#28a745", "#dc3545", "#ffc107"]
            }

        return charts

    def _generate_recommendations(
        self,
        scan_results: Optional[Dict],
        hardening_session: Optional[Dict]
    ) -> List[Dict[str, str]]:
        """Generate recommendations based on results."""
        recommendations = []

        if scan_results:
            summary = self._process_scan_results(scan_results)

            # Critical issues
            if summary["critical"] > 0:
                recommendations.append({
                    "priority": "critical",
                    "title": "Address Critical Security Issues",
                    "description": f"Found {summary['critical']} critical security issue(s). "
                                 "These should be addressed immediately as they pose significant security risks."
                })

            # High severity issues
            if summary["high"] > 0:
                recommendations.append({
                    "priority": "high",
                    "title": "Resolve High Priority Issues",
                    "description": f"Found {summary['high']} high priority issue(s). "
                                 "Address these issues as soon as possible."
                })

        # Hardening recommendations
        if hardening_session:
            failed = hardening_session.get("failed_rules", 0)
            if failed > 0:
                recommendations.append({
                    "priority": "medium",
                    "title": "Review Failed Hardening Rules",
                    "description": f"{failed} hardening rule(s) failed to apply. "
                                 "Review the errors and attempt to apply these rules manually."
                })

        # General recommendations
        if not recommendations:
            recommendations.append({
                "priority": "info",
                "title": "Maintain Security Posture",
                "description": "Continue to monitor your system regularly and apply security updates promptly."
            })

        return recommendations

    def _generate_html_report(self, report_data: Dict[str, Any]) -> str:
        """
        Generate HTML report.

        Args:
            report_data: Compiled report data

        Returns:
            Path to generated HTML file
        """
        if not self.jinja_env:
            raise RuntimeError("Jinja2 not available - cannot generate HTML report")

        logger.info("Generating HTML report")

        try:
            # Load template
            template = self.jinja_env.get_template("report_template.html")

            # Render report
            html_content = template.render(**report_data)

            # Generate filename
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"security_report_{timestamp}.html"
            filepath = self.output_dir / filename

            # Write report
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(html_content)

            logger.info(f"HTML report generated: {filepath}")
            return str(filepath)

        except Exception as e:
            logger.error(f"Error generating HTML report: {e}", exc_info=True)
            raise

    def _generate_pdf_report(self, report_data: Dict[str, Any]) -> str:
        """
        Generate PDF report from HTML.

        Args:
            report_data: Compiled report data

        Returns:
            Path to generated PDF file
        """
        logger.info("Generating PDF report")

        # First generate HTML
        html_path = self._generate_html_report(report_data)

        try:
            # Try using weasyprint
            try:
                from weasyprint import HTML

                pdf_path = html_path.replace('.html', '.pdf')
                HTML(html_path).write_pdf(pdf_path)

                logger.info(f"PDF report generated: {pdf_path}")
                return pdf_path

            except ImportError:
                logger.warning("weasyprint not installed")

            # Try using pdfkit as fallback
            try:
                import pdfkit

                pdf_path = html_path.replace('.html', '.pdf')
                pdfkit.from_file(html_path, pdf_path)

                logger.info(f"PDF report generated: {pdf_path}")
                return pdf_path

            except ImportError:
                logger.warning("pdfkit not installed")

            # If no PDF library available, return HTML path
            logger.warning("No PDF library available. Returning HTML report instead.")
            logger.warning("Install weasyprint or pdfkit to enable PDF generation:")
            logger.warning("  pip install weasyprint  OR  pip install pdfkit")
            return html_path

        except Exception as e:
            logger.error(f"Error generating PDF report: {e}", exc_info=True)
            # Return HTML as fallback
            return html_path

    def _generate_json_report(self, report_data: Dict[str, Any]) -> str:
        """
        Generate JSON report.

        Args:
            report_data: Compiled report data

        Returns:
            Path to generated JSON file
        """
        logger.info("Generating JSON report")

        try:
            # Generate filename
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"security_report_{timestamp}.json"
            filepath = self.output_dir / filename

            # Write report
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2, default=str)

            logger.info(f"JSON report generated: {filepath}")
            return str(filepath)

        except Exception as e:
            logger.error(f"Error generating JSON report: {e}", exc_info=True)
            raise


# Convenience functions
def generate_scan_report(scan_results: Dict[str, Any], format: str = "html") -> str:
    """
    Convenience function to generate a scan report.

    Args:
        scan_results: Scan results
        format: Output format

    Returns:
        Path to generated report
    """
    generator = ReportGenerator()
    return generator.generate_report(
        scan_results=scan_results,
        report_format=format,
        title="Security Scan Report"
    )


def generate_hardening_report(
    hardening_session: Dict[str, Any],
    before_scan: Optional[Dict[str, Any]] = None,
    after_scan: Optional[Dict[str, Any]] = None,
    format: str = "html"
) -> str:
    """
    Convenience function to generate a hardening report.

    Args:
        hardening_session: Hardening session data
        before_scan: Before scan results
        after_scan: After scan results
        format: Output format

    Returns:
        Path to generated report
    """
    generator = ReportGenerator()
    return generator.generate_report(
        hardening_session=hardening_session,
        before_scan=before_scan,
        after_scan=after_scan,
        report_format=format,
        title="System Hardening Report"
    )


# Example usage and testing
if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    print("=" * 70)
    print("Report Generator - Test Run")
    print("=" * 70)

    # Create sample data
    sample_scan = {
        "scan_id": "scan_test_001",
        "findings": [
            {
                "title": "Weak SSH Configuration",
                "severity": "critical",
                "description": "SSH allows root login",
                "category": "Network",
                "remediation": "Set PermitRootLogin to no"
            },
            {
                "title": "Password Expiration Not Set",
                "severity": "high",
                "description": "Password maximum age not configured",
                "category": "Authentication",
                "remediation": "Set PASS_MAX_DAYS to 90"
            },
            {
                "title": "Firewall Not Enabled",
                "severity": "medium",
                "description": "System firewall is disabled",
                "category": "Network",
                "remediation": "Enable and configure firewall"
            }
        ]
    }

    sample_hardening = {
        "session_id": "hardening_001",
        "start_time": "2025-11-06T10:00:00",
        "end_time": "2025-11-06T10:05:00",
        "total_rules": 3,
        "successful_rules": 2,
        "failed_rules": 1,
        "skipped_rules": 0,
        "checkpoint_id": "checkpoint_abc123",
        "results": [
            {
                "rule_id": "ssh_root_login",
                "rule_name": "Disable Root Login",
                "status": "success",
                "rule_severity": "critical",
                "before_value": "yes",
                "after_value": "no",
                "duration_seconds": 1.2
            },
            {
                "rule_id": "pass_max_days",
                "rule_name": "Set Password Max Age",
                "status": "success",
                "rule_severity": "high",
                "before_value": "99999",
                "after_value": "90",
                "duration_seconds": 0.8
            },
            {
                "rule_id": "enable_firewall",
                "rule_name": "Enable Firewall",
                "status": "failed",
                "rule_severity": "medium",
                "error_message": "Firewall service not found",
                "duration_seconds": 0.5
            }
        ]
    }

    # Initialize generator
    generator = ReportGenerator()

    # Test JSON report
    print("\n1. Generating JSON report...")
    json_path = generator.generate_report(
        scan_results=sample_scan,
        hardening_session=sample_hardening,
        report_format="json",
        title="Test Security Report"
    )
    print(f"   Generated: {json_path}")

    # Test HTML report (if template exists)
    print("\n2. Attempting HTML report generation...")
    try:
        html_path = generator.generate_report(
            scan_results=sample_scan,
            hardening_session=sample_hardening,
            report_format="html",
            title="Test Security Report"
        )
        print(f"   Generated: {html_path}")
    except Exception as e:
        print(f"   HTML generation failed: {e}")
        print("   (This is expected if template doesn't exist yet)")

    print("\n" + "=" * 70)
    print("Test completed!")
    print("=" * 70)
