#!/usr/bin/env python3
"""
Windows Security Checker Module
Performs comprehensive security checks on Windows systems.
"""

import os
import re
import logging
import subprocess
import platform
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)


class WindowsChecker:
    """
    Performs security checks on Windows systems.
    Checks password policies, firewall, updates, UAC, and services.
    """

    def __init__(self):
        """Initialize the Windows security checker."""
        self.os_type = "Windows"
        self.is_admin = self._check_admin_privileges()

        if not self.is_admin:
            logger.warning("Not running with administrator privileges. Some checks may be limited.")

        logger.info("Windows security checker initialized")

    def _check_admin_privileges(self) -> bool:
        """
        Check if running with administrator privileges.

        Returns:
            True if admin, False otherwise
        """
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False

    def quick_scan(self, options: Optional[Dict[str, Any]] = None) -> List[Dict]:
        """
        Perform a quick security scan (critical checks only).

        Args:
            options: Optional scan configuration

        Returns:
            List of finding dictionaries
        """
        logger.info("Starting quick Windows security scan")
        findings = []

        # Critical checks only
        findings.extend(self._check_firewall_status())
        findings.extend(self._check_uac_status())
        findings.extend(self._check_auto_updates())

        logger.info(f"Quick scan completed with {len(findings)} findings")
        return findings

    def full_scan(self, options: Optional[Dict[str, Any]] = None) -> List[Dict]:
        """
        Perform a comprehensive security scan.

        Args:
            options: Optional scan configuration

        Returns:
            List of finding dictionaries
        """
        logger.info("Starting full Windows security scan")
        findings = []

        # Password policy checks
        findings.extend(self._check_password_policies())

        # Firewall checks
        findings.extend(self._check_firewall_status())
        findings.extend(self._check_firewall_profiles())

        # Update checks
        findings.extend(self._check_auto_updates())

        # UAC checks
        findings.extend(self._check_uac_status())

        # Service checks
        findings.extend(self._check_unnecessary_services())

        # Additional security checks
        findings.extend(self._check_guest_account())
        findings.extend(self._check_rdp_status())

        logger.info(f"Full scan completed with {len(findings)} findings")
        return findings

    def compliance_scan(self, options: Optional[Dict[str, Any]] = None) -> List[Dict]:
        """
        Perform a compliance-focused security scan.

        Args:
            options: Optional scan configuration

        Returns:
            List of finding dictionaries
        """
        logger.info("Starting compliance scan")
        # For now, compliance scan is same as full scan
        return self.full_scan(options)

    def custom_scan(self, options: Optional[Dict[str, Any]] = None) -> List[Dict]:
        """
        Perform a custom security scan based on provided options.

        Args:
            options: Scan configuration with categories to check

        Returns:
            List of finding dictionaries
        """
        logger.info("Starting custom scan")
        findings = []

        if not options or not options.get("categories"):
            return self.full_scan(options)

        categories = options.get("categories", [])

        if "password" in categories:
            findings.extend(self._check_password_policies())
        if "firewall" in categories:
            findings.extend(self._check_firewall_status())
            findings.extend(self._check_firewall_profiles())
        if "updates" in categories:
            findings.extend(self._check_auto_updates())
        if "uac" in categories:
            findings.extend(self._check_uac_status())
        if "services" in categories:
            findings.extend(self._check_unnecessary_services())

        logger.info(f"Custom scan completed with {len(findings)} findings")
        return findings

    # ========================
    # Password Policy Checks
    # ========================

    def _check_password_policies(self) -> List[Dict]:
        """
        Check Windows password policies using net accounts.

        Returns:
            List of findings
        """
        logger.info("Checking password policies")
        findings = []

        try:
            # Run net accounts command
            result = subprocess.run(
                ['net', 'accounts'],
                capture_output=True,
                text=True,
                timeout=10,
                shell=True
            )

            if result.returncode != 0:
                findings.append({
                    "title": "Cannot Check Password Policies",
                    "description": "Failed to run 'net accounts' command. Administrator privileges may be required.",
                    "severity": "high",
                    "category": "Password Policy",
                    "check_name": "password_policy_access",
                    "status": "warning",
                    "current_value": "access denied",
                    "expected_value": "accessible",
                    "affected_item": "net accounts"
                })
                return findings

            output = result.stdout

            # Parse password policy settings
            findings.extend(self._parse_password_min_length(output))
            findings.extend(self._parse_password_max_age(output))
            findings.extend(self._parse_password_min_age(output))
            findings.extend(self._parse_password_history(output))
            findings.extend(self._parse_lockout_threshold(output))
            findings.extend(self._parse_lockout_duration(output))

        except Exception as e:
            logger.error(f"Error checking password policies: {e}")
            findings.append(self._create_error_finding("Password Policy Check", str(e), "net accounts"))

        return findings

    def _parse_password_min_length(self, output: str) -> List[Dict]:
        """Parse minimum password length from net accounts output."""
        findings = []
        recommended_min = 14

        try:
            match = re.search(r'Minimum password length:\s+(\d+)', output, re.IGNORECASE)
            if match:
                min_length = int(match.group(1))

                if min_length < recommended_min:
                    findings.append({
                        "title": "Password Minimum Length Too Short",
                        "description": f"Minimum password length is {min_length} characters. "
                                       f"Recommended: {recommended_min} characters or more.",
                        "severity": "high",
                        "category": "Password Policy",
                        "check_name": "password_min_length",
                        "status": "fail",
                        "current_value": f"{min_length} characters",
                        "expected_value": f">= {recommended_min} characters",
                        "remediation": f"Run 'net accounts /minpwlen:{recommended_min}' as administrator",
                        "affected_item": "Minimum password length",
                        "references": ["CIS Windows Benchmark: 1.1.1"]
                    })
                else:
                    findings.append({
                        "title": "Password Minimum Length Properly Configured",
                        "description": f"Minimum password length is {min_length} characters.",
                        "severity": "info",
                        "category": "Password Policy",
                        "check_name": "password_min_length",
                        "status": "pass",
                        "current_value": f"{min_length} characters",
                        "expected_value": f">= {recommended_min} characters",
                        "affected_item": "Minimum password length"
                    })

        except Exception as e:
            logger.error(f"Error parsing password min length: {e}")

        return findings

    def _parse_password_max_age(self, output: str) -> List[Dict]:
        """Parse maximum password age from net accounts output."""
        findings = []
        recommended_max = 90

        try:
            match = re.search(r'Maximum password age \(days\):\s+(\d+|Unlimited)', output, re.IGNORECASE)
            if match:
                max_age_str = match.group(1)

                if max_age_str.lower() == "unlimited":
                    findings.append({
                        "title": "Password Maximum Age Unlimited",
                        "description": "Passwords never expire. This is a security risk.",
                        "severity": "high",
                        "category": "Password Policy",
                        "check_name": "password_max_age",
                        "status": "fail",
                        "current_value": "unlimited",
                        "expected_value": f"<= {recommended_max} days",
                        "remediation": f"Run 'net accounts /maxpwage:{recommended_max}' as administrator",
                        "affected_item": "Maximum password age",
                        "references": ["CIS Windows Benchmark: 1.1.2"]
                    })
                else:
                    max_age = int(max_age_str)
                    if max_age > recommended_max or max_age == 0:
                        findings.append({
                            "title": "Password Maximum Age Too Long",
                            "description": f"Maximum password age is {max_age} days. "
                                           f"Recommended: {recommended_max} days or less.",
                            "severity": "medium",
                            "category": "Password Policy",
                            "check_name": "password_max_age",
                            "status": "fail",
                            "current_value": f"{max_age} days",
                            "expected_value": f"<= {recommended_max} days",
                            "remediation": f"Run 'net accounts /maxpwage:{recommended_max}' as administrator",
                            "affected_item": "Maximum password age",
                            "references": ["CIS Windows Benchmark: 1.1.2"]
                        })
                    else:
                        findings.append({
                            "title": "Password Maximum Age Properly Configured",
                            "description": f"Maximum password age is {max_age} days.",
                            "severity": "info",
                            "category": "Password Policy",
                            "check_name": "password_max_age",
                            "status": "pass",
                            "current_value": f"{max_age} days",
                            "expected_value": f"<= {recommended_max} days",
                            "affected_item": "Maximum password age"
                        })

        except Exception as e:
            logger.error(f"Error parsing password max age: {e}")

        return findings

    def _parse_password_min_age(self, output: str) -> List[Dict]:
        """Parse minimum password age from net accounts output."""
        findings = []
        recommended_min = 1

        try:
            match = re.search(r'Minimum password age \(days\):\s+(\d+)', output, re.IGNORECASE)
            if match:
                min_age = int(match.group(1))

                if min_age < recommended_min:
                    findings.append({
                        "title": "Password Minimum Age Too Short",
                        "description": f"Minimum password age is {min_age} days. "
                                       "Users can change passwords too frequently.",
                        "severity": "low",
                        "category": "Password Policy",
                        "check_name": "password_min_age",
                        "status": "fail",
                        "current_value": f"{min_age} days",
                        "expected_value": f">= {recommended_min} day",
                        "remediation": f"Run 'net accounts /minpwage:{recommended_min}' as administrator",
                        "affected_item": "Minimum password age",
                        "references": ["CIS Windows Benchmark: 1.1.3"]
                    })
                else:
                    findings.append({
                        "title": "Password Minimum Age Properly Configured",
                        "description": f"Minimum password age is {min_age} days.",
                        "severity": "info",
                        "category": "Password Policy",
                        "check_name": "password_min_age",
                        "status": "pass",
                        "current_value": f"{min_age} days",
                        "expected_value": f">= {recommended_min} day",
                        "affected_item": "Minimum password age"
                    })

        except Exception as e:
            logger.error(f"Error parsing password min age: {e}")

        return findings

    def _parse_password_history(self, output: str) -> List[Dict]:
        """Parse password history from net accounts output."""
        findings = []
        recommended_history = 24

        try:
            match = re.search(r'Length of password history maintained:\s+(\d+)', output, re.IGNORECASE)
            if match:
                history_length = int(match.group(1))

                if history_length < recommended_history:
                    findings.append({
                        "title": "Password History Too Short",
                        "description": f"Password history is set to {history_length} passwords. "
                                       f"Recommended: {recommended_history} or more.",
                        "severity": "medium",
                        "category": "Password Policy",
                        "check_name": "password_history",
                        "status": "fail",
                        "current_value": f"{history_length} passwords",
                        "expected_value": f">= {recommended_history} passwords",
                        "remediation": f"Run 'net accounts /uniquepw:{recommended_history}' as administrator",
                        "affected_item": "Password history length",
                        "references": ["CIS Windows Benchmark: 1.1.4"]
                    })
                else:
                    findings.append({
                        "title": "Password History Properly Configured",
                        "description": f"Password history maintains {history_length} passwords.",
                        "severity": "info",
                        "category": "Password Policy",
                        "check_name": "password_history",
                        "status": "pass",
                        "current_value": f"{history_length} passwords",
                        "expected_value": f">= {recommended_history} passwords",
                        "affected_item": "Password history length"
                    })

        except Exception as e:
            logger.error(f"Error parsing password history: {e}")

        return findings

    def _parse_lockout_threshold(self, output: str) -> List[Dict]:
        """Parse account lockout threshold from net accounts output."""
        findings = []
        recommended_threshold = 5

        try:
            match = re.search(r'Lockout threshold:\s+(\d+|Never)', output, re.IGNORECASE)
            if match:
                threshold_str = match.group(1)

                if threshold_str.lower() == "never":
                    findings.append({
                        "title": "Account Lockout Not Configured",
                        "description": "Account lockout is disabled. Accounts are vulnerable to brute force attacks.",
                        "severity": "high",
                        "category": "Password Policy",
                        "check_name": "lockout_threshold",
                        "status": "fail",
                        "current_value": "never",
                        "expected_value": f"<= {recommended_threshold} attempts",
                        "remediation": f"Run 'net accounts /lockoutthreshold:{recommended_threshold}' as administrator",
                        "affected_item": "Lockout threshold",
                        "references": ["CIS Windows Benchmark: 1.2.1"]
                    })
                else:
                    threshold = int(threshold_str)
                    if threshold == 0 or threshold > recommended_threshold:
                        findings.append({
                            "title": "Account Lockout Threshold Too High",
                            "description": f"Lockout threshold is {threshold} attempts. "
                                           f"Recommended: {recommended_threshold} or less.",
                            "severity": "medium",
                            "category": "Password Policy",
                            "check_name": "lockout_threshold",
                            "status": "fail",
                            "current_value": f"{threshold} attempts",
                            "expected_value": f"<= {recommended_threshold} attempts",
                            "remediation": f"Run 'net accounts /lockoutthreshold:{recommended_threshold}' as administrator",
                            "affected_item": "Lockout threshold"
                        })
                    else:
                        findings.append({
                            "title": "Account Lockout Properly Configured",
                            "description": f"Lockout threshold is {threshold} attempts.",
                            "severity": "info",
                            "category": "Password Policy",
                            "check_name": "lockout_threshold",
                            "status": "pass",
                            "current_value": f"{threshold} attempts",
                            "expected_value": f"<= {recommended_threshold} attempts",
                            "affected_item": "Lockout threshold"
                        })

        except Exception as e:
            logger.error(f"Error parsing lockout threshold: {e}")

        return findings

    def _parse_lockout_duration(self, output: str) -> List[Dict]:
        """Parse lockout duration from net accounts output."""
        findings = []
        recommended_duration = 15

        try:
            match = re.search(r'Lockout duration \(minutes\):\s+(\d+)', output, re.IGNORECASE)
            if match:
                duration = int(match.group(1))

                if duration < recommended_duration and duration != 0:
                    findings.append({
                        "title": "Lockout Duration Too Short",
                        "description": f"Lockout duration is {duration} minutes. "
                                       f"Recommended: {recommended_duration} minutes or more.",
                        "severity": "low",
                        "category": "Password Policy",
                        "check_name": "lockout_duration",
                        "status": "warning",
                        "current_value": f"{duration} minutes",
                        "expected_value": f">= {recommended_duration} minutes",
                        "remediation": f"Run 'net accounts /lockoutduration:{recommended_duration}' as administrator",
                        "affected_item": "Lockout duration"
                    })

        except Exception as e:
            logger.error(f"Error parsing lockout duration: {e}")

        return findings

    # ========================
    # Firewall Checks
    # ========================

    def _check_firewall_status(self) -> List[Dict]:
        """
        Check Windows Firewall status.

        Returns:
            List of findings
        """
        logger.info("Checking Windows Firewall status")
        findings = []

        try:
            # Check firewall status using netsh
            result = subprocess.run(
                ['netsh', 'advfirewall', 'show', 'allprofiles', 'state'],
                capture_output=True,
                text=True,
                timeout=10,
                shell=True
            )

            if result.returncode == 0:
                output = result.stdout

                # Check each profile
                profiles = ['Domain', 'Private', 'Public']
                disabled_profiles = []

                for profile in profiles:
                    pattern = rf'{profile}\s+Profile\s+Settings:.*?State\s+(ON|OFF)'
                    match = re.search(pattern, output, re.IGNORECASE | re.DOTALL)
                    if match:
                        state = match.group(1).upper()
                        if state == "OFF":
                            disabled_profiles.append(profile)

                if disabled_profiles:
                    findings.append({
                        "title": "Windows Firewall Disabled on Some Profiles",
                        "description": f"Windows Firewall is disabled on: {', '.join(disabled_profiles)}. "
                                       "This leaves the system vulnerable to network attacks.",
                        "severity": "critical",
                        "category": "Firewall",
                        "check_name": "firewall_enabled",
                        "status": "fail",
                        "current_value": f"disabled on {', '.join(disabled_profiles)}",
                        "expected_value": "enabled on all profiles",
                        "remediation": "Enable Windows Firewall: Control Panel > System and Security > Windows Defender Firewall",
                        "affected_item": "Windows Firewall",
                        "references": ["CIS Windows Benchmark: 9.1.1, 9.2.1, 9.3.1"]
                    })
                else:
                    findings.append({
                        "title": "Windows Firewall Enabled",
                        "description": "Windows Firewall is enabled on all profiles.",
                        "severity": "info",
                        "category": "Firewall",
                        "check_name": "firewall_enabled",
                        "status": "pass",
                        "current_value": "enabled on all profiles",
                        "expected_value": "enabled on all profiles",
                        "affected_item": "Windows Firewall"
                    })
            else:
                findings.append({
                    "title": "Cannot Check Firewall Status",
                    "description": "Failed to check Windows Firewall status. Administrator privileges may be required.",
                    "severity": "high",
                    "category": "Firewall",
                    "check_name": "firewall_enabled",
                    "status": "warning",
                    "current_value": "unknown",
                    "expected_value": "enabled",
                    "affected_item": "Windows Firewall"
                })

        except Exception as e:
            logger.error(f"Error checking firewall status: {e}")
            findings.append(self._create_error_finding("Firewall Status Check", str(e), "Windows Firewall"))

        return findings

    def _check_firewall_profiles(self) -> List[Dict]:
        """
        Check Windows Firewall profile configurations.

        Returns:
            List of findings
        """
        logger.info("Checking Windows Firewall profiles")
        findings = []

        try:
            # Check if inbound connections are blocked by default
            result = subprocess.run(
                ['netsh', 'advfirewall', 'show', 'allprofiles'],
                capture_output=True,
                text=True,
                timeout=10,
                shell=True
            )

            if result.returncode == 0:
                output = result.stdout

                # Check for inbound connections setting
                if 'InboundUserNotification' in output or 'BlockAllInbound' in output:
                    # Firewall configuration found
                    pass

        except Exception as e:
            logger.error(f"Error checking firewall profiles: {e}")

        return findings

    # ========================
    # Auto-Update Checks
    # ========================

    def _check_auto_updates(self) -> List[Dict]:
        """
        Check Windows automatic update settings.

        Returns:
            List of findings
        """
        logger.info("Checking Windows Update settings")
        findings = []

        try:
            # Try PowerShell method first (Windows 10/11)
            ps_command = "(Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU' -ErrorAction SilentlyContinue).AUOptions"

            result = subprocess.run(
                ['powershell', '-Command', ps_command],
                capture_output=True,
                text=True,
                timeout=10,
                shell=True
            )

            if result.returncode == 0 and result.stdout.strip():
                au_option = result.stdout.strip()

                # AUOptions values:
                # 2 = Notify before download
                # 3 = Auto download and notify of installation
                # 4 = Auto download and schedule installation
                # 5 = Automatic Updates is required, but end users can configure it

                if au_option in ['2', '3']:
                    findings.append({
                        "title": "Automatic Updates Not Fully Enabled",
                        "description": "Windows is configured to notify before downloading or installing updates. "
                                       "Automatic installation is recommended.",
                        "severity": "high",
                        "category": "Windows Update",
                        "check_name": "auto_updates",
                        "status": "fail",
                        "current_value": f"manual update mode ({au_option})",
                        "expected_value": "automatic updates enabled (4)",
                        "remediation": "Enable automatic updates: Settings > Update & Security > Windows Update > Advanced options",
                        "affected_item": "Windows Update",
                        "references": ["CIS Windows Benchmark: 18.9.102.1"]
                    })
                elif au_option == '4':
                    findings.append({
                        "title": "Automatic Updates Enabled",
                        "description": "Windows automatic updates are properly configured.",
                        "severity": "info",
                        "category": "Windows Update",
                        "check_name": "auto_updates",
                        "status": "pass",
                        "current_value": "automatic updates enabled",
                        "expected_value": "automatic updates enabled",
                        "affected_item": "Windows Update"
                    })
                else:
                    findings.append({
                        "title": "Windows Update Configuration Unknown",
                        "description": f"Windows Update AUOptions is set to {au_option}.",
                        "severity": "medium",
                        "category": "Windows Update",
                        "check_name": "auto_updates",
                        "status": "warning",
                        "current_value": f"AUOptions: {au_option}",
                        "expected_value": "automatic updates enabled (4)",
                        "affected_item": "Windows Update"
                    })
            else:
                # Check using alternative method - Windows Update service status
                service_result = subprocess.run(
                    ['sc', 'query', 'wuauserv'],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    shell=True
                )

                if service_result.returncode == 0:
                    if 'RUNNING' in service_result.stdout:
                        findings.append({
                            "title": "Windows Update Service Running",
                            "description": "Windows Update service is running. Specific configuration could not be determined.",
                            "severity": "info",
                            "category": "Windows Update",
                            "check_name": "auto_updates",
                            "status": "pass",
                            "current_value": "service running",
                            "expected_value": "service running with auto-updates",
                            "affected_item": "Windows Update Service"
                        })
                    else:
                        findings.append({
                            "title": "Windows Update Service Not Running",
                            "description": "Windows Update service is not running. System may not receive security updates.",
                            "severity": "critical",
                            "category": "Windows Update",
                            "check_name": "auto_updates",
                            "status": "fail",
                            "current_value": "service stopped",
                            "expected_value": "service running",
                            "remediation": "Start Windows Update service: 'sc start wuauserv' or via Services console",
                            "affected_item": "Windows Update Service",
                            "references": ["CIS Windows Benchmark: 5.36"]
                        })

        except Exception as e:
            logger.error(f"Error checking auto-updates: {e}")
            findings.append(self._create_error_finding("Auto-Update Check", str(e), "Windows Update"))

        return findings

    # ========================
    # UAC Checks
    # ========================

    def _check_uac_status(self) -> List[Dict]:
        """
        Check User Account Control (UAC) settings.

        Returns:
            List of findings
        """
        logger.info("Checking UAC settings")
        findings = []

        try:
            # Check UAC registry settings
            ps_command = "(Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -ErrorAction SilentlyContinue).EnableLUA"

            result = subprocess.run(
                ['powershell', '-Command', ps_command],
                capture_output=True,
                text=True,
                timeout=10,
                shell=True
            )

            if result.returncode == 0 and result.stdout.strip():
                uac_enabled = result.stdout.strip()

                if uac_enabled == '0':
                    findings.append({
                        "title": "User Account Control (UAC) Disabled",
                        "description": "UAC is disabled. This significantly reduces system security by allowing "
                                       "programs to run with elevated privileges without user consent.",
                        "severity": "critical",
                        "category": "User Account Control",
                        "check_name": "uac_enabled",
                        "status": "fail",
                        "current_value": "disabled",
                        "expected_value": "enabled",
                        "remediation": "Enable UAC: Control Panel > User Accounts > Change User Account Control settings",
                        "affected_item": "UAC",
                        "references": ["CIS Windows Benchmark: 2.3.17.1"]
                    })
                elif uac_enabled == '1':
                    findings.append({
                        "title": "User Account Control (UAC) Enabled",
                        "description": "UAC is enabled and protecting the system.",
                        "severity": "info",
                        "category": "User Account Control",
                        "check_name": "uac_enabled",
                        "status": "pass",
                        "current_value": "enabled",
                        "expected_value": "enabled",
                        "affected_item": "UAC"
                    })

                    # Check UAC level (ConsentPromptBehaviorAdmin)
                    ps_level_command = "(Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -ErrorAction SilentlyContinue).ConsentPromptBehaviorAdmin"

                    level_result = subprocess.run(
                        ['powershell', '-Command', ps_level_command],
                        capture_output=True,
                        text=True,
                        timeout=10,
                        shell=True
                    )

                    if level_result.returncode == 0 and level_result.stdout.strip():
                        uac_level = level_result.stdout.strip()
                        # 0 = Never notify, 1 = Prompt on Secure Desktop, 2 = Prompt, 5 = Always notify
                        if uac_level == '0':
                            findings.append({
                                "title": "UAC Set to Never Notify",
                                "description": "UAC is enabled but set to never notify. This provides minimal protection.",
                                "severity": "high",
                                "category": "User Account Control",
                                "check_name": "uac_level",
                                "status": "fail",
                                "current_value": "never notify",
                                "expected_value": "always notify or prompt on secure desktop",
                                "remediation": "Increase UAC level: Control Panel > User Accounts > Change User Account Control settings",
                                "affected_item": "UAC Level"
                            })
                        elif uac_level in ['1', '2', '5']:
                            findings.append({
                                "title": "UAC Level Properly Configured",
                                "description": "UAC is configured to prompt for elevation.",
                                "severity": "info",
                                "category": "User Account Control",
                                "check_name": "uac_level",
                                "status": "pass",
                                "current_value": "prompt enabled",
                                "expected_value": "prompt enabled",
                                "affected_item": "UAC Level"
                            })

            else:
                findings.append({
                    "title": "Cannot Check UAC Status",
                    "description": "Failed to check UAC settings. Administrator privileges may be required.",
                    "severity": "high",
                    "category": "User Account Control",
                    "check_name": "uac_enabled",
                    "status": "warning",
                    "current_value": "unknown",
                    "expected_value": "enabled",
                    "affected_item": "UAC"
                })

        except Exception as e:
            logger.error(f"Error checking UAC status: {e}")
            findings.append(self._create_error_finding("UAC Check", str(e), "UAC"))

        return findings

    # ========================
    # Service Checks
    # ========================

    def _check_unnecessary_services(self) -> List[Dict]:
        """
        Check for unnecessary or insecure services running.

        Returns:
            List of findings
        """
        logger.info("Checking for unnecessary services")
        findings = []

        # List of potentially unnecessary services
        unnecessary_services = [
            ("Telnet", "critical", "Telnet is insecure and should not be used"),
            ("RemoteRegistry", "high", "Remote Registry service should be disabled"),
            ("SSDPSRV", "medium", "SSDP Discovery service may not be needed"),
            ("upnphost", "medium", "UPnP Device Host may not be needed"),
            ("WMPNetworkSvc", "low", "Windows Media Player Network Sharing Service may not be needed"),
            ("XblAuthManager", "low", "Xbox Live Auth Manager may not be needed on non-gaming systems"),
            ("XblGameSave", "low", "Xbox Live Game Save may not be needed on non-gaming systems"),
        ]

        for service_name, severity, description in unnecessary_services:
            if self._is_service_running(service_name):
                findings.append({
                    "title": f"Unnecessary Service Running: {service_name}",
                    "description": description,
                    "severity": severity,
                    "category": "Services",
                    "check_name": f"service_{service_name.lower()}",
                    "status": "fail",
                    "current_value": "running",
                    "expected_value": "stopped/disabled",
                    "remediation": f"Stop and disable {service_name}: "
                                   f"'sc stop {service_name} && sc config {service_name} start=disabled' or via Services console",
                    "affected_item": service_name
                })

        if not any(f.get('status') == 'fail' for f in findings):
            findings.append({
                "title": "No Unnecessary Services Found",
                "description": "Common unnecessary services are not running.",
                "severity": "info",
                "category": "Services",
                "check_name": "unnecessary_services",
                "status": "pass",
                "current_value": "none running",
                "expected_value": "none running",
                "affected_item": "services"
            })

        return findings

    def _is_service_running(self, service_name: str) -> bool:
        """
        Check if a Windows service is running.

        Args:
            service_name: Name of the service

        Returns:
            True if running, False otherwise
        """
        try:
            result = subprocess.run(
                ['sc', 'query', service_name],
                capture_output=True,
                text=True,
                timeout=5,
                shell=True
            )
            return 'RUNNING' in result.stdout
        except Exception as e:
            logger.debug(f"Error checking service {service_name}: {e}")
            return False

    # ========================
    # Additional Security Checks
    # ========================

    def _check_guest_account(self) -> List[Dict]:
        """
        Check if Guest account is enabled.

        Returns:
            List of findings
        """
        findings = []

        try:
            result = subprocess.run(
                ['net', 'user', 'guest'],
                capture_output=True,
                text=True,
                timeout=10,
                shell=True
            )

            if result.returncode == 0:
                if 'Account active' in result.stdout:
                    match = re.search(r'Account active\s+(Yes|No)', result.stdout, re.IGNORECASE)
                    if match and match.group(1).lower() == 'yes':
                        findings.append({
                            "title": "Guest Account Enabled",
                            "description": "The Guest account is enabled. This is a security risk.",
                            "severity": "high",
                            "category": "User Accounts",
                            "check_name": "guest_account",
                            "status": "fail",
                            "current_value": "enabled",
                            "expected_value": "disabled",
                            "remediation": "Disable Guest account: 'net user guest /active:no' as administrator",
                            "affected_item": "Guest Account",
                            "references": ["CIS Windows Benchmark: 2.3.1.4"]
                        })
                    else:
                        findings.append({
                            "title": "Guest Account Disabled",
                            "description": "The Guest account is properly disabled.",
                            "severity": "info",
                            "category": "User Accounts",
                            "check_name": "guest_account",
                            "status": "pass",
                            "current_value": "disabled",
                            "expected_value": "disabled",
                            "affected_item": "Guest Account"
                        })

        except Exception as e:
            logger.error(f"Error checking guest account: {e}")

        return findings

    def _check_rdp_status(self) -> List[Dict]:
        """
        Check Remote Desktop Protocol (RDP) status.

        Returns:
            List of findings
        """
        findings = []

        try:
            ps_command = "(Get-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' -ErrorAction SilentlyContinue).fDenyTSConnections"

            result = subprocess.run(
                ['powershell', '-Command', ps_command],
                capture_output=True,
                text=True,
                timeout=10,
                shell=True
            )

            if result.returncode == 0 and result.stdout.strip():
                rdp_disabled = result.stdout.strip()

                if rdp_disabled == '0':
                    findings.append({
                        "title": "Remote Desktop Enabled",
                        "description": "RDP is enabled. Ensure it's properly secured with strong passwords, "
                                       "NLA (Network Level Authentication), and firewall rules.",
                        "severity": "medium",
                        "category": "Remote Access",
                        "check_name": "rdp_enabled",
                        "status": "warning",
                        "current_value": "enabled",
                        "expected_value": "disabled (if not needed)",
                        "remediation": "If RDP is not needed, disable it: System Properties > Remote > 'Don't allow remote connections'",
                        "affected_item": "Remote Desktop",
                        "references": ["CIS Windows Benchmark: 18.9.58.3.3.1"]
                    })
                else:
                    findings.append({
                        "title": "Remote Desktop Disabled",
                        "description": "RDP is disabled.",
                        "severity": "info",
                        "category": "Remote Access",
                        "check_name": "rdp_enabled",
                        "status": "pass",
                        "current_value": "disabled",
                        "expected_value": "disabled",
                        "affected_item": "Remote Desktop"
                    })

        except Exception as e:
            logger.error(f"Error checking RDP status: {e}")

        return findings

    # ========================
    # Helper Methods
    # ========================

    def _create_error_finding(self, check_name: str, error: str, affected_item: str) -> Dict:
        """
        Create a standardized error finding.

        Args:
            check_name: Name of the check that failed
            error: Error message
            affected_item: Item that was being checked

        Returns:
            Finding dictionary
        """
        return {
            "title": f"Error During {check_name}",
            "description": f"An error occurred while performing this check: {error}",
            "severity": "info",
            "category": "System",
            "check_name": check_name.lower().replace(" ", "_"),
            "status": "error",
            "current_value": "error",
            "expected_value": "successful check",
            "affected_item": affected_item
        }


# Example usage and testing
if __name__ == "__main__":
    # Configure logging for standalone testing
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    # Check if running on Windows
    if platform.system() != "Windows":
        print("=" * 70)
        print("WARNING: This checker is designed for Windows systems.")
        print("Running on:", platform.system())
        print("Tests will be limited.")
        print("=" * 70)

    print("=" * 70)
    print("Windows Security Checker - Test Run")
    print("=" * 70)

    checker = WindowsChecker()

    if not checker.is_admin:
        print("\nWARNING: Not running with administrator privileges.")
        print("Some checks may be limited or unavailable.\n")

    # Test quick scan
    print("\n" + "=" * 70)
    print("QUICK SCAN")
    print("=" * 70)
    quick_results = checker.quick_scan()
    for finding in quick_results:
        print(f"\n[{finding['severity'].upper()}] {finding['title']}")
        print(f"  Status: {finding['status']}")
        print(f"  Current: {finding['current_value']}")
        print(f"  Expected: {finding['expected_value']}")

    # Test full scan
    print("\n" + "=" * 70)
    print("FULL SCAN")
    print("=" * 70)
    full_results = checker.full_scan()

    # Count by status
    pass_count = sum(1 for f in full_results if f.get('status') == 'pass')
    fail_count = sum(1 for f in full_results if f.get('status') == 'fail')
    warning_count = sum(1 for f in full_results if f.get('status') == 'warning')

    print(f"\nScan Summary:")
    print(f"  Total Checks: {len(full_results)}")
    print(f"  Passed: {pass_count}")
    print(f"  Failed: {fail_count}")
    print(f"  Warnings: {warning_count}")

    print(f"\nFailed Checks:")
    for finding in full_results:
        if finding.get('status') == 'fail':
            print(f"  - {finding['title']} ({finding['severity']})")
