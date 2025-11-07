#!/usr/bin/env python3
"""
Security Scanner Module
Orchestrates security scans based on operating system type.
Delegates to platform-specific checkers and aggregates results.
"""

import logging
from datetime import datetime
from typing import Dict, List, Optional, Any
from enum import Enum

logger = logging.getLogger(__name__)


class ScanType(Enum):
    """Enumeration of available scan types."""
    QUICK = "quick"
    FULL = "full"
    CUSTOM = "custom"
    COMPLIANCE = "compliance"


class Severity(Enum):
    """Enumeration of security finding severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ScanStatus(Enum):
    """Enumeration of scan statuses."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class Finding:
    """Represents a single security finding."""

    def __init__(
        self,
        title: str,
        description: str,
        severity: Severity,
        category: str,
        remediation: Optional[str] = None,
        references: Optional[List[str]] = None,
        affected_item: Optional[str] = None
    ):
        """
        Initialize a security finding.

        Args:
            title: Brief title of the finding
            description: Detailed description of the issue
            severity: Severity level of the finding
            category: Category (e.g., "User Accounts", "Network", "Filesystem")
            remediation: Recommended fix for the issue
            references: List of reference URLs or documentation
            affected_item: Specific system item affected (e.g., file path, registry key)
        """
        self.title = title
        self.description = description
        self.severity = severity if isinstance(severity, Severity) else Severity(severity)
        self.category = category
        self.remediation = remediation
        self.references = references or []
        self.affected_item = affected_item
        self.timestamp = datetime.now().isoformat()

    def to_dict(self) -> Dict:
        """Convert finding to dictionary format."""
        return {
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "category": self.category,
            "remediation": self.remediation,
            "references": self.references,
            "affected_item": self.affected_item,
            "timestamp": self.timestamp
        }


class ScanResult:
    """Represents the complete scan results."""

    def __init__(self, scan_id: str, os_type: str, scan_type: ScanType):
        """
        Initialize scan results.

        Args:
            scan_id: Unique identifier for this scan
            os_type: Operating system type
            scan_type: Type of scan performed
        """
        self.scan_id = scan_id
        self.os_type = os_type
        self.scan_type = scan_type
        self.status = ScanStatus.PENDING
        self.findings: List[Finding] = []
        self.start_time = datetime.now().isoformat()
        self.end_time: Optional[str] = None
        self.duration_seconds: Optional[float] = None
        self.error_message: Optional[str] = None

    def add_finding(self, finding: Finding):
        """Add a finding to the scan results."""
        self.findings.append(finding)
        logger.debug(f"Added {finding.severity.value} finding: {finding.title}")

    def complete(self):
        """Mark the scan as completed."""
        self.status = ScanStatus.COMPLETED
        self.end_time = datetime.now().isoformat()
        if self.start_time and self.end_time:
            start = datetime.fromisoformat(self.start_time)
            end = datetime.fromisoformat(self.end_time)
            self.duration_seconds = (end - start).total_seconds()

    def fail(self, error_message: str):
        """Mark the scan as failed."""
        self.status = ScanStatus.FAILED
        self.error_message = error_message
        self.end_time = datetime.now().isoformat()

    def get_summary(self) -> Dict:
        """Get a summary of findings by severity."""
        summary = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
            "total": len(self.findings)
        }
        for finding in self.findings:
            summary[finding.severity.value] += 1
        return summary

    def to_dict(self) -> Dict:
        """Convert scan results to dictionary format."""
        return {
            "scan_id": self.scan_id,
            "os_type": self.os_type,
            "scan_type": self.scan_type.value,
            "status": self.status.value,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration_seconds": self.duration_seconds,
            "summary": self.get_summary(),
            "findings": [f.to_dict() for f in self.findings],
            "error_message": self.error_message
        }


class Scanner:
    """
    Main scanner class that orchestrates security scans.
    Delegates to platform-specific checkers based on OS type.
    """

    def __init__(self, os_type: str):
        """
        Initialize the scanner.

        Args:
            os_type: Operating system type (Windows, Linux, Darwin)

        Raises:
            ValueError: If OS type is not supported
        """
        self.os_type = os_type.lower() if os_type else "unknown"
        self.checker = None
        self._load_checker()
        logger.info(f"Scanner initialized for OS type: {self.os_type}")

    def _load_checker(self):
        """
        Load the appropriate platform-specific checker module.

        Raises:
            ImportError: If checker module cannot be loaded
            ValueError: If OS type is not supported
        """
        try:
            if self.os_type == "windows":
                try:
                    from . import windows_checker
                    self.checker = windows_checker.WindowsChecker()
                    logger.info("Windows checker loaded successfully")
                except ImportError as e:
                    logger.warning(f"Windows checker not available: {e}")
                    self.checker = None

            elif self.os_type == "linux":
                try:
                    from . import linux_checker
                    self.checker = linux_checker.LinuxChecker()
                    logger.info("Linux checker loaded successfully")
                except ImportError as e:
                    logger.warning(f"Linux checker not available: {e}")
                    self.checker = None

            elif self.os_type == "darwin":
                try:
                    from . import macos_checker
                    self.checker = macos_checker.MacOSChecker()
                    logger.info("macOS checker loaded successfully")
                except ImportError as e:
                    logger.warning(f"macOS checker not available: {e}")
                    self.checker = None

            else:
                logger.error(f"Unsupported OS type: {self.os_type}")
                raise ValueError(f"Unsupported OS type: {self.os_type}")

        except Exception as e:
            logger.error(f"Error loading checker: {e}")
            raise

    def scan(
        self,
        scan_type: str = "quick",
        options: Optional[Dict[str, Any]] = None
    ) -> ScanResult:
        """
        Perform a security scan.

        Args:
            scan_type: Type of scan to perform (quick, full, custom, compliance)
            options: Additional scan options (categories, depth, etc.)

        Returns:
            ScanResult: Complete scan results with findings

        Raises:
            ValueError: If scan type is invalid
            RuntimeError: If scan fails
        """
        # Generate scan ID
        scan_id = f"scan_{self.os_type}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

        # Validate and convert scan type
        try:
            scan_type_enum = ScanType(scan_type.lower())
        except ValueError:
            logger.error(f"Invalid scan type: {scan_type}")
            raise ValueError(f"Invalid scan type: {scan_type}")

        # Initialize scan result
        result = ScanResult(scan_id, self.os_type, scan_type_enum)
        result.status = ScanStatus.RUNNING

        logger.info(f"Starting {scan_type} scan on {self.os_type} - Scan ID: {scan_id}")

        try:
            # Check if checker is available
            if self.checker is None:
                logger.warning(f"No checker available for {self.os_type}, using mock scan")
                self._perform_mock_scan(result, scan_type_enum, options)
            else:
                # Delegate to platform-specific checker
                self._perform_real_scan(result, scan_type_enum, options)

            # Complete the scan
            result.complete()
            logger.info(
                f"Scan {scan_id} completed successfully. "
                f"Found {len(result.findings)} issues. "
                f"Duration: {result.duration_seconds:.2f}s"
            )

        except Exception as e:
            logger.error(f"Scan {scan_id} failed: {str(e)}", exc_info=True)
            result.fail(str(e))
            raise RuntimeError(f"Scan failed: {str(e)}") from e

        return result

    def _perform_real_scan(
        self,
        result: ScanResult,
        scan_type: ScanType,
        options: Optional[Dict[str, Any]]
    ):
        """
        Perform actual scan using platform-specific checker.

        Args:
            result: ScanResult object to populate
            scan_type: Type of scan to perform
            options: Additional scan options
        """
        logger.info(f"Performing real scan using {self.os_type} checker")

        try:
            # Call the appropriate checker method based on scan type
            if scan_type == ScanType.QUICK:
                findings = self.checker.quick_scan(options)
            elif scan_type == ScanType.FULL:
                findings = self.checker.full_scan(options)
            elif scan_type == ScanType.COMPLIANCE:
                findings = self.checker.compliance_scan(options)
            else:
                findings = self.checker.custom_scan(options)

            # Add findings to result
            for finding_data in findings:
                finding = Finding(
                    title=finding_data.get("title", "Unknown Issue"),
                    description=finding_data.get("description", "No description"),
                    severity=Severity(finding_data.get("severity", "info")),
                    category=finding_data.get("category", "General"),
                    remediation=finding_data.get("remediation"),
                    references=finding_data.get("references"),
                    affected_item=finding_data.get("affected_item")
                )
                result.add_finding(finding)

        except AttributeError as e:
            logger.error(f"Checker method not implemented: {e}")
            raise RuntimeError(f"Checker method not available: {e}") from e

    def _perform_mock_scan(
        self,
        result: ScanResult,
        scan_type: ScanType,
        options: Optional[Dict[str, Any]]
    ):
        """
        Perform mock scan when no checker is available.
        Used for testing and development.

        Args:
            result: ScanResult object to populate
            scan_type: Type of scan to perform
            options: Additional scan options
        """
        logger.info(f"Performing mock scan for {self.os_type}")

        # Add sample findings based on scan type
        sample_findings = self._generate_sample_findings(scan_type)

        for finding_data in sample_findings:
            finding = Finding(**finding_data)
            result.add_finding(finding)

    def _generate_sample_findings(self, scan_type: ScanType) -> List[Dict]:
        """
        Generate sample findings for mock scans.

        Args:
            scan_type: Type of scan

        Returns:
            List of finding dictionaries
        """
        findings = [
            {
                "title": "Checker Module Not Implemented",
                "description": f"The {self.os_type} checker module is not yet implemented. "
                               "This is a placeholder scan result.",
                "severity": Severity.INFO,
                "category": "System",
                "remediation": f"Implement the {self.os_type}_checker.py module",
                "references": []
            }
        ]

        if scan_type == ScanType.FULL:
            findings.extend([
                {
                    "title": "Sample Security Finding",
                    "description": "This is a sample finding for demonstration purposes.",
                    "severity": Severity.MEDIUM,
                    "category": "Configuration",
                    "remediation": "Apply recommended security settings",
                    "references": ["https://example.com/security-guide"],
                    "affected_item": "/etc/sample.conf"
                },
                {
                    "title": "Sample Critical Finding",
                    "description": "This is a sample critical finding for demonstration.",
                    "severity": Severity.CRITICAL,
                    "category": "User Accounts",
                    "remediation": "Review and fix user account permissions",
                    "references": [],
                    "affected_item": "Administrator"
                }
            ])

        return findings

    def get_supported_scan_types(self) -> List[str]:
        """
        Get list of supported scan types.

        Returns:
            List of scan type names
        """
        return [scan_type.value for scan_type in ScanType]

    def validate_scan_options(self, options: Optional[Dict[str, Any]]) -> bool:
        """
        Validate scan options.

        Args:
            options: Scan options to validate

        Returns:
            True if valid, False otherwise
        """
        if options is None:
            return True

        # Add validation logic as needed
        valid_keys = ["categories", "depth", "timeout", "exclude_paths"]

        for key in options.keys():
            if key not in valid_keys:
                logger.warning(f"Unknown scan option: {key}")

        return True


# Convenience functions
def create_scanner(os_type: str) -> Scanner:
    """
    Create a scanner instance for the specified OS type.

    Args:
        os_type: Operating system type

    Returns:
        Scanner instance
    """
    return Scanner(os_type)


def quick_scan(os_type: str) -> Dict:
    """
    Perform a quick scan and return results as dictionary.

    Args:
        os_type: Operating system type

    Returns:
        Scan results dictionary
    """
    scanner = Scanner(os_type)
    result = scanner.scan(scan_type="quick")
    return result.to_dict()


def full_scan(os_type: str) -> Dict:
    """
    Perform a full scan and return results as dictionary.

    Args:
        os_type: Operating system type

    Returns:
        Scan results dictionary
    """
    scanner = Scanner(os_type)
    result = scanner.scan(scan_type="full")
    return result.to_dict()


# Example usage and testing
if __name__ == "__main__":
    # Configure logging for standalone testing
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    print("=" * 70)
    print("Security Scanner - Test Run")
    print("=" * 70)

    # Test with different OS types
    for os_type in ["linux", "windows", "darwin"]:
        print(f"\n{'='*70}")
        print(f"Testing {os_type.upper()} Scanner")
        print(f"{'='*70}")

        try:
            scanner = Scanner(os_type)

            # Perform quick scan
            print(f"\nPerforming quick scan...")
            result = scanner.scan(scan_type="quick")

            print(f"\nScan ID: {result.scan_id}")
            print(f"Status: {result.status.value}")
            print(f"Duration: {result.duration_seconds:.2f}s")
            print(f"\nFindings Summary:")
            summary = result.get_summary()
            for severity, count in summary.items():
                if severity != "total":
                    print(f"  {severity.capitalize()}: {count}")

            print(f"\nDetailed Findings:")
            for finding in result.findings:
                print(f"  [{finding.severity.value.upper()}] {finding.title}")
                print(f"    Category: {finding.category}")
                print(f"    Description: {finding.description}")

        except Exception as e:
            print(f"Error testing {os_type} scanner: {e}")

    print(f"\n{'='*70}")
