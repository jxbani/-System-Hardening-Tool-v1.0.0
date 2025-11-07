#!/usr/bin/env python3
"""
Backend Test Script
Tests all backend modules of the System Hardening Tool.
"""

import sys
import os
from pathlib import Path
import logging
import json
from datetime import datetime

# Add backend modules to path
backend_path = Path(__file__).parent.parent / 'src' / 'backend' / 'modules'
sys.path.insert(0, str(backend_path))

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)


def print_header(title: str, char: str = "="):
    """Print a formatted header."""
    width = 70
    print(f"\n{char * width}")
    print(f"{title.center(width)}")
    print(f"{char * width}\n")


def print_section(title: str):
    """Print a section divider."""
    print(f"\n{'─' * 70}")
    print(f"  {title}")
    print(f"{'─' * 70}\n")


def test_system_detector():
    """Test the system_detector module."""
    print_header("TESTING SYSTEM DETECTOR", "=")

    try:
        import system_detector

        print("✓ system_detector module imported successfully\n")

        # Create detector instance
        detector = system_detector.SystemDetector()
        print("✓ SystemDetector instance created\n")

        # Test individual detection methods
        print_section("Operating System Detection")
        os_type = detector.detect_os_type()
        print(f"OS Type: {os_type}")

        print_section("OS Version Information")
        os_version = detector.get_os_version()
        for key, value in os_version.items():
            print(f"  {key}: {value}")

        print_section("Architecture Information")
        arch_info = detector.get_architecture()
        for key, value in arch_info.items():
            print(f"  {key}: {value}")

        print_section("System Identity")
        print(f"  Hostname: {detector.get_hostname()}")
        print(f"  FQDN: {detector.get_fqdn()}")
        print(f"  Current User: {detector.get_current_user()}")
        print(f"  Is Admin/Root: {detector.is_admin()}")

        print_section("Complete System Information")
        system_info = detector.get_all_system_info()
        print(json.dumps(system_info, indent=2, default=str))

        print_section("System Summary")
        print(detector.get_summary())

        return os_type, detector

    except Exception as e:
        print(f"✗ Error testing system_detector: {e}")
        import traceback
        traceback.print_exc()
        return None, None


def test_config_loader():
    """Test the config_loader module."""
    print_header("TESTING CONFIG LOADER", "=")

    try:
        import config_loader

        print("✓ config_loader module imported successfully\n")

        # Create loader instance
        loader = config_loader.ConfigLoader()
        print(f"✓ ConfigLoader instance created")
        print(f"  Config base path: {loader.config_base_path}\n")

        # Load SSH config
        print_section("Loading SSH Configuration")
        ssh_profile = config_loader.load_ssh_config('linux')

        if ssh_profile:
            print(f"✓ SSH configuration loaded successfully")
            print(f"  Name: {ssh_profile.name}")
            print(f"  Description: {ssh_profile.description}")
            print(f"  Category: {ssh_profile.category}")
            print(f"  Total Rules: {len(ssh_profile.rules)}")

            print("\n  Rules by Severity:")
            for severity in ['critical', 'high', 'medium', 'low']:
                rules = ssh_profile.get_rules_by_severity(severity)
                print(f"    {severity.capitalize()}: {len(rules)}")

            print("\n  Sample Rules (first 3):")
            for rule in ssh_profile.rules[:3]:
                print(f"    • [{rule.severity.upper()}] {rule.name}")
                print(f"      {rule.parameter} = {rule.expected_value}")
        else:
            print("✗ Failed to load SSH configuration")

        # Get statistics
        print_section("Configuration Statistics")
        stats = loader.get_statistics()
        print(f"  Total Profiles: {stats['total_profiles']}")
        print(f"  Total Rules: {stats['total_rules']}")
        print(f"\n  Severity Breakdown:")
        for severity, count in stats['severity_breakdown'].items():
            print(f"    {severity.capitalize()}: {count}")

        return loader

    except Exception as e:
        print(f"✗ Error testing config_loader: {e}")
        import traceback
        traceback.print_exc()
        return None


def test_scanner(os_type: str):
    """Test the scanner module."""
    print_header("TESTING SCANNER", "=")

    try:
        import scanner

        print("✓ scanner module imported successfully\n")

        # Create scanner instance
        print_section("Creating Scanner")
        print(f"  OS Type: {os_type}")

        scan_engine = scanner.Scanner(os_type)
        print(f"✓ Scanner instance created")
        print(f"  Checker loaded: {scan_engine.checker is not None}\n")

        # Get supported scan types
        print_section("Supported Scan Types")
        scan_types = scan_engine.get_supported_scan_types()
        for scan_type in scan_types:
            print(f"  • {scan_type}")

        # Perform quick scan
        print_section("Running Quick Scan")
        print("Starting scan... This may take a moment.\n")

        start_time = datetime.now()
        scan_result = scan_engine.scan(scan_type="quick")
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()

        print(f"✓ Scan completed in {duration:.2f} seconds")
        print(f"  Scan ID: {scan_result.scan_id}")
        print(f"  Status: {scan_result.status.value}")
        print(f"  Duration: {scan_result.duration_seconds:.2f}s")

        # Print scan summary
        print_section("Scan Summary")
        summary = scan_result.get_summary()
        print(f"  Total Findings: {summary['total']}")
        print(f"  Critical: {summary['critical']}")
        print(f"  High: {summary['high']}")
        print(f"  Medium: {summary['medium']}")
        print(f"  Low: {summary['low']}")
        print(f"  Info: {summary['info']}")

        # Print findings
        print_section("Scan Findings")

        if scan_result.findings:
            # Group findings by severity
            severity_order = ['critical', 'high', 'medium', 'low', 'info']
            findings_by_severity = {sev: [] for sev in severity_order}

            for finding in scan_result.findings:
                findings_by_severity[finding.severity.value].append(finding)

            # Print findings by severity
            for severity in severity_order:
                findings_list = findings_by_severity[severity]
                if findings_list:
                    print(f"\n  {severity.upper()} ({len(findings_list)}):")
                    for finding in findings_list:
                        print(f"    • {finding.title}")
                        print(f"      Category: {finding.category}")
                        print(f"      {finding.description}")
                        if finding.remediation:
                            print(f"      Remediation: {finding.remediation}")
                        if finding.affected_item:
                            print(f"      Affected: {finding.affected_item}")
                        print()
        else:
            print("  No findings detected")

        # Export scan results to JSON
        print_section("Exporting Scan Results")
        results_dict = scan_result.to_dict()

        # Create output directory
        output_dir = Path(__file__).parent.parent / 'logs'
        output_dir.mkdir(exist_ok=True)

        output_file = output_dir / f"scan_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

        with open(output_file, 'w') as f:
            json.dump(results_dict, f, indent=2, default=str)

        print(f"✓ Scan results exported to: {output_file}")

        return scan_result

    except Exception as e:
        print(f"✗ Error testing scanner: {e}")
        import traceback
        traceback.print_exc()
        return None


def test_linux_checker():
    """Test the linux_checker module directly."""
    print_header("TESTING LINUX CHECKER (Direct)", "=")

    try:
        import linux_checker

        print("✓ linux_checker module imported successfully\n")

        # Create checker instance
        checker = linux_checker.LinuxChecker()
        print(f"✓ LinuxChecker instance created")
        print(f"  OS Type: {checker.os_type}\n")

        # Run a quick scan
        print_section("Running Linux-Specific Quick Scan")
        findings = checker.quick_scan()

        print(f"✓ Quick scan completed")
        print(f"  Total Findings: {len(findings)}")

        # Count by status
        status_counts = {}
        for finding in findings:
            status = finding.get('status', 'unknown')
            status_counts[status] = status_counts.get(status, 0) + 1

        print(f"\n  By Status:")
        for status, count in status_counts.items():
            print(f"    {status}: {count}")

        # Print first few findings
        if findings:
            print(f"\n  Sample Findings (first 3):")
            for finding in findings[:3]:
                print(f"    • [{finding.get('severity', 'unknown').upper()}] {finding.get('title', 'Unknown')}")
                print(f"      Status: {finding.get('status', 'unknown')}")
                print(f"      Current: {finding.get('current_value', 'N/A')}")
                print(f"      Expected: {finding.get('expected_value', 'N/A')}")

        return findings

    except ImportError:
        print("ℹ linux_checker not available (may not be on Linux system)")
        return None
    except Exception as e:
        print(f"✗ Error testing linux_checker: {e}")
        import traceback
        traceback.print_exc()
        return None


def test_windows_checker():
    """Test the windows_checker module directly."""
    print_header("TESTING WINDOWS CHECKER (Direct)", "=")

    try:
        import windows_checker

        print("✓ windows_checker module imported successfully\n")

        # Create checker instance
        checker = windows_checker.WindowsChecker()
        print(f"✓ WindowsChecker instance created")
        print(f"  OS Type: {checker.os_type}")
        print(f"  Is Admin: {checker.is_admin}\n")

        # Run a quick scan
        print_section("Running Windows-Specific Quick Scan")
        findings = checker.quick_scan()

        print(f"✓ Quick scan completed")
        print(f"  Total Findings: {len(findings)}")

        # Count by status
        status_counts = {}
        for finding in findings:
            status = finding.get('status', 'unknown')
            status_counts[status] = status_counts.get(status, 0) + 1

        print(f"\n  By Status:")
        for status, count in status_counts.items():
            print(f"    {status}: {count}")

        # Print first few findings
        if findings:
            print(f"\n  Sample Findings (first 3):")
            for finding in findings[:3]:
                print(f"    • [{finding.get('severity', 'unknown').upper()}] {finding.get('title', 'Unknown')}")
                print(f"      Status: {finding.get('status', 'unknown')}")
                print(f"      Current: {finding.get('current_value', 'N/A')}")
                print(f"      Expected: {finding.get('expected_value', 'N/A')}")

        return findings

    except ImportError:
        print("ℹ windows_checker not available (may not be on Windows system)")
        return None
    except Exception as e:
        print(f"✗ Error testing windows_checker: {e}")
        import traceback
        traceback.print_exc()
        return None


def main():
    """Main test function."""
    print_header("SYSTEM HARDENING TOOL - BACKEND TEST", "=")
    print(f"Test started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Python version: {sys.version}")
    print(f"Backend path: {backend_path}")

    results = {
        'system_detector': False,
        'config_loader': False,
        'scanner': False,
        'platform_checker': False
    }

    # Test 1: System Detector
    os_type, detector = test_system_detector()
    if detector:
        results['system_detector'] = True

    # Test 2: Config Loader
    loader = test_config_loader()
    if loader:
        results['config_loader'] = True

    # Test 3: Scanner
    if os_type:
        scan_result = test_scanner(os_type)
        if scan_result:
            results['scanner'] = True

    # Test 4: Platform-Specific Checkers
    if os_type and os_type.lower() == 'linux':
        findings = test_linux_checker()
        if findings is not None:
            results['platform_checker'] = True
    elif os_type and os_type.lower() == 'windows':
        findings = test_windows_checker()
        if findings is not None:
            results['platform_checker'] = True

    # Print final summary
    print_header("TEST SUMMARY", "=")

    print("Test Results:")
    for test_name, passed in results.items():
        status = "✓ PASS" if passed else "✗ FAIL"
        print(f"  {test_name.replace('_', ' ').title()}: {status}")

    passed_count = sum(results.values())
    total_count = len(results)

    print(f"\nOverall: {passed_count}/{total_count} tests passed")

    if passed_count == total_count:
        print("\n🎉 All tests passed! Backend is ready.")
        return 0
    else:
        print("\n⚠️  Some tests failed. Please review the output above.")
        return 1


if __name__ == "__main__":
    try:
        exit_code = main()
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\n\nTest interrupted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\n\nUnexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
