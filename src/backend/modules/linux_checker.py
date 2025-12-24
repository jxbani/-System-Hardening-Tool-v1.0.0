#!/usr/bin/env python3
"""
Linux Security Checker Module
Performs comprehensive security checks on Linux systems.
"""

import os
import re
import logging
import subprocess
from typing import Dict, List, Optional, Any
from pathlib import Path

logger = logging.getLogger(__name__)


class LinuxChecker:
    """
    Performs security checks on Linux systems.
    Checks SSH config, password policies, firewall, file permissions, and services.
    """

    def __init__(self):
        """Initialize the Linux security checker."""
        self.os_type = "Linux"
        logger.info("Linux security checker initialized")

    def quick_scan(self, options: Optional[Dict[str, Any]] = None) -> List[Dict]:
        """
        Perform a quick security scan (critical checks only).

        Args:
            options: Optional scan configuration

        Returns:
            List of finding dictionaries
        """
        logger.info("Starting quick Linux security scan")
        findings = []

        # Critical checks only
        findings.extend(self._check_ssh_root_login())
        findings.extend(self._check_shadow_permissions())
        findings.extend(self._check_firewall_status())

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
        logger.info("Starting full Linux security scan")
        findings = []

        # SSH Configuration checks
        findings.extend(self._check_ssh_configuration())

        # Password policy checks
        findings.extend(self._check_password_policies())

        # Firewall checks
        findings.extend(self._check_firewall_status())
        findings.extend(self._check_firewall_rules())

        # File permission checks
        findings.extend(self._check_critical_file_permissions())

        # Service checks
        findings.extend(self._check_unnecessary_services())

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

        if "ssh" in categories:
            findings.extend(self._check_ssh_configuration())
        if "password" in categories:
            findings.extend(self._check_password_policies())
        if "firewall" in categories:
            findings.extend(self._check_firewall_status())
            findings.extend(self._check_firewall_rules())
        if "permissions" in categories:
            findings.extend(self._check_critical_file_permissions())
        if "services" in categories:
            findings.extend(self._check_unnecessary_services())

        logger.info(f"Custom scan completed with {len(findings)} findings")
        return findings

    # ========================
    # SSH Configuration Checks
    # ========================

    def _check_ssh_configuration(self) -> List[Dict]:
        """
        Check SSH server configuration for security issues.

        Returns:
            List of findings
        """
        logger.info("Checking SSH configuration")
        findings = []

        sshd_config_path = "/etc/ssh/sshd_config"

        if not os.path.exists(sshd_config_path):
            findings.append({
                "title": "SSH Configuration File Not Found",
                "description": f"The SSH configuration file {sshd_config_path} was not found. "
                               "SSH may not be installed or configured.",
                "severity": "info",
                "category": "SSH Configuration",
                "check_name": "ssh_config_exists",
                "status": "warning",
                "current_value": "not found",
                "expected_value": "exists",
                "affected_item": sshd_config_path
            })
            return findings

        # Check individual SSH settings
        findings.extend(self._check_ssh_root_login())
        findings.extend(self._check_ssh_password_auth())
        findings.extend(self._check_ssh_port())
        findings.extend(self._check_ssh_protocol())
        findings.extend(self._check_ssh_empty_passwords())

        return findings

    def _check_ssh_root_login(self) -> List[Dict]:
        """Check if root login via SSH is disabled."""
        findings = []
        sshd_config_path = "/etc/ssh/sshd_config"

        try:
            permit_root = self._parse_ssh_config(sshd_config_path, "PermitRootLogin")

            if permit_root and permit_root.lower() in ["yes", "prohibit-password", "without-password"]:
                severity = "critical" if permit_root.lower() == "yes" else "high"
                findings.append({
                    "title": "SSH Root Login Enabled",
                    "description": f"Root login via SSH is currently set to '{permit_root}'. "
                                   "Direct root login should be disabled for security.",
                    "severity": severity,
                    "category": "SSH Configuration",
                    "check_name": "ssh_permit_root_login",
                    "status": "fail",
                    "current_value": permit_root,
                    "expected_value": "no",
                    "remediation": self._get_detailed_remediation("ssh_permit_root_login", sshd_config_path),
                    "affected_item": sshd_config_path,
                    "references": [
                        "https://www.ssh.com/academy/ssh/sshd_config",
                        "CIS Benchmark: 5.2.10"
                    ]
                })
            else:
                findings.append({
                    "title": "SSH Root Login Properly Configured",
                    "description": "Root login via SSH is disabled.",
                    "severity": "info",
                    "category": "SSH Configuration",
                    "check_name": "ssh_permit_root_login",
                    "status": "pass",
                    "current_value": permit_root or "no",
                    "expected_value": "no",
                    "affected_item": sshd_config_path
                })

        except Exception as e:
            logger.error(f"Error checking SSH root login: {e}")
            findings.append(self._create_error_finding("SSH Root Login Check", str(e), sshd_config_path))

        return findings

    def _check_ssh_password_auth(self) -> List[Dict]:
        """Check SSH password authentication setting."""
        findings = []
        sshd_config_path = "/etc/ssh/sshd_config"

        try:
            password_auth = self._parse_ssh_config(sshd_config_path, "PasswordAuthentication")

            if password_auth and password_auth.lower() == "yes":
                findings.append({
                    "title": "SSH Password Authentication Enabled",
                    "description": "SSH allows password authentication. Key-based authentication "
                                   "is more secure than password-based authentication.",
                    "severity": "medium",
                    "category": "SSH Configuration",
                    "check_name": "ssh_password_authentication",
                    "status": "warning",
                    "current_value": password_auth,
                    "expected_value": "no (use key-based auth)",
                    "remediation": self._get_detailed_remediation("ssh_password_authentication", sshd_config_path),
                    "affected_item": sshd_config_path,
                    "references": ["CIS Benchmark: 5.2.8"]
                })
            else:
                findings.append({
                    "title": "SSH Password Authentication Properly Configured",
                    "description": "SSH password authentication is disabled.",
                    "severity": "info",
                    "category": "SSH Configuration",
                    "check_name": "ssh_password_authentication",
                    "status": "pass",
                    "current_value": password_auth or "no",
                    "expected_value": "no",
                    "affected_item": sshd_config_path
                })

        except Exception as e:
            logger.error(f"Error checking SSH password auth: {e}")
            findings.append(self._create_error_finding("SSH Password Auth Check", str(e), sshd_config_path))

        return findings

    def _check_ssh_port(self) -> List[Dict]:
        """Check SSH port configuration."""
        findings = []
        sshd_config_path = "/etc/ssh/sshd_config"

        try:
            port = self._parse_ssh_config(sshd_config_path, "Port")
            current_port = port or "22"

            if current_port == "22":
                findings.append({
                    "title": "SSH Using Default Port",
                    "description": "SSH is running on the default port 22. Consider changing to a "
                                   "non-standard port to reduce automated attacks.",
                    "severity": "low",
                    "category": "SSH Configuration",
                    "check_name": "ssh_port",
                    "status": "warning",
                    "current_value": current_port,
                    "expected_value": "non-default port (e.g., 2222)",
                    "remediation": self._get_detailed_remediation("ssh_port", sshd_config_path),
                    "affected_item": sshd_config_path
                })
            else:
                findings.append({
                    "title": "SSH Port Configured",
                    "description": f"SSH is running on custom port {current_port}.",
                    "severity": "info",
                    "category": "SSH Configuration",
                    "check_name": "ssh_port",
                    "status": "pass",
                    "current_value": current_port,
                    "expected_value": "non-default port",
                    "affected_item": sshd_config_path
                })

        except Exception as e:
            logger.error(f"Error checking SSH port: {e}")
            findings.append(self._create_error_finding("SSH Port Check", str(e), sshd_config_path))

        return findings

    def _check_ssh_protocol(self) -> List[Dict]:
        """Check SSH protocol version."""
        findings = []
        sshd_config_path = "/etc/ssh/sshd_config"

        try:
            protocol = self._parse_ssh_config(sshd_config_path, "Protocol")

            if protocol and "1" in protocol:
                findings.append({
                    "title": "SSH Protocol 1 Enabled",
                    "description": "SSH Protocol 1 is insecure and should not be used.",
                    "severity": "critical",
                    "category": "SSH Configuration",
                    "check_name": "ssh_protocol",
                    "status": "fail",
                    "current_value": protocol,
                    "expected_value": "2",
                    "remediation": f"Edit {sshd_config_path} and set 'Protocol 2'",
                    "affected_item": sshd_config_path,
                    "references": ["CIS Benchmark: 5.2.4"]
                })

        except Exception as e:
            logger.error(f"Error checking SSH protocol: {e}")

        return findings

    def _check_ssh_empty_passwords(self) -> List[Dict]:
        """Check if SSH permits empty passwords."""
        findings = []
        sshd_config_path = "/etc/ssh/sshd_config"

        try:
            permit_empty = self._parse_ssh_config(sshd_config_path, "PermitEmptyPasswords")

            if permit_empty and permit_empty.lower() == "yes":
                findings.append({
                    "title": "SSH Permits Empty Passwords",
                    "description": "SSH is configured to allow empty passwords, which is a critical security risk.",
                    "severity": "critical",
                    "category": "SSH Configuration",
                    "check_name": "ssh_permit_empty_passwords",
                    "status": "fail",
                    "current_value": permit_empty,
                    "expected_value": "no",
                    "remediation": f"Edit {sshd_config_path} and set 'PermitEmptyPasswords no'",
                    "affected_item": sshd_config_path,
                    "references": ["CIS Benchmark: 5.2.9"]
                })

        except Exception as e:
            logger.error(f"Error checking SSH empty passwords: {e}")

        return findings

    def _parse_ssh_config(self, config_path: str, setting: str) -> Optional[str]:
        """
        Parse SSH configuration file for a specific setting.

        Args:
            config_path: Path to sshd_config
            setting: Setting name to find

        Returns:
            Setting value or None
        """
        try:
            with open(config_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    # Skip comments and empty lines
                    if not line or line.startswith('#'):
                        continue
                    # Check if line starts with the setting name
                    if line.lower().startswith(setting.lower()):
                        parts = line.split(None, 1)
                        if len(parts) == 2:
                            return parts[1].strip()
            return None
        except Exception as e:
            logger.error(f"Error parsing SSH config: {e}")
            raise

    # ========================
    # Password Policy Checks
    # ========================

    def _check_password_policies(self) -> List[Dict]:
        """
        Check password policies from /etc/login.defs.

        Returns:
            List of findings
        """
        logger.info("Checking password policies")
        findings = []

        login_defs_path = "/etc/login.defs"

        if not os.path.exists(login_defs_path):
            findings.append({
                "title": "Login Definitions File Not Found",
                "description": f"{login_defs_path} not found. Cannot verify password policies.",
                "severity": "high",
                "category": "Password Policy",
                "check_name": "login_defs_exists",
                "status": "fail",
                "current_value": "not found",
                "expected_value": "exists",
                "affected_item": login_defs_path
            })
            return findings

        findings.extend(self._check_pass_max_days(login_defs_path))
        findings.extend(self._check_pass_min_days(login_defs_path))
        findings.extend(self._check_pass_min_len(login_defs_path))
        findings.extend(self._check_pass_warn_age(login_defs_path))

        return findings

    def _check_pass_max_days(self, login_defs_path: str) -> List[Dict]:
        """Check maximum password age."""
        findings = []

        try:
            max_days = self._parse_login_defs(login_defs_path, "PASS_MAX_DAYS")
            recommended_max = 90

            if max_days is None:
                findings.append({
                    "title": "Password Maximum Age Not Set",
                    "description": "PASS_MAX_DAYS is not configured in login.defs.",
                    "severity": "medium",
                    "category": "Password Policy",
                    "check_name": "pass_max_days",
                    "status": "fail",
                    "current_value": "not set",
                    "expected_value": f"<= {recommended_max} days",
                    "remediation": f"Add 'PASS_MAX_DAYS {recommended_max}' to {login_defs_path}",
                    "affected_item": login_defs_path,
                    "references": ["CIS Benchmark: 5.4.1.1"]
                })
            elif int(max_days) > recommended_max or int(max_days) == 99999:
                findings.append({
                    "title": "Password Maximum Age Too Long",
                    "description": f"Password maximum age is set to {max_days} days. "
                                   f"Recommended: {recommended_max} days or less.",
                    "severity": "medium",
                    "category": "Password Policy",
                    "check_name": "pass_max_days",
                    "status": "fail",
                    "current_value": f"{max_days} days",
                    "expected_value": f"<= {recommended_max} days",
                    "remediation": self._get_detailed_remediation("pass_max_days", login_defs_path),
                    "affected_item": login_defs_path,
                    "references": ["CIS Benchmark: 5.4.1.1"]
                })
            else:
                findings.append({
                    "title": "Password Maximum Age Properly Configured",
                    "description": f"Password maximum age is set to {max_days} days.",
                    "severity": "info",
                    "category": "Password Policy",
                    "check_name": "pass_max_days",
                    "status": "pass",
                    "current_value": f"{max_days} days",
                    "expected_value": f"<= {recommended_max} days",
                    "affected_item": login_defs_path
                })

        except Exception as e:
            logger.error(f"Error checking PASS_MAX_DAYS: {e}")
            findings.append(self._create_error_finding("Password Max Age Check", str(e), login_defs_path))

        return findings

    def _check_pass_min_days(self, login_defs_path: str) -> List[Dict]:
        """Check minimum password age."""
        findings = []

        try:
            min_days = self._parse_login_defs(login_defs_path, "PASS_MIN_DAYS")
            recommended_min = 1

            if min_days is None:
                findings.append({
                    "title": "Password Minimum Age Not Set",
                    "description": "PASS_MIN_DAYS is not configured in login.defs.",
                    "severity": "low",
                    "category": "Password Policy",
                    "check_name": "pass_min_days",
                    "status": "warning",
                    "current_value": "not set",
                    "expected_value": f">= {recommended_min} day",
                    "remediation": f"Add 'PASS_MIN_DAYS {recommended_min}' to {login_defs_path}",
                    "affected_item": login_defs_path,
                    "references": ["CIS Benchmark: 5.4.1.2"]
                })
            elif int(min_days) < recommended_min:
                findings.append({
                    "title": "Password Minimum Age Too Short",
                    "description": f"Password minimum age is set to {min_days} days. "
                                   "Users can change passwords too frequently.",
                    "severity": "low",
                    "category": "Password Policy",
                    "check_name": "pass_min_days",
                    "status": "fail",
                    "current_value": f"{min_days} days",
                    "expected_value": f">= {recommended_min} day",
                    "remediation": self._get_detailed_remediation("pass_min_days", login_defs_path),
                    "affected_item": login_defs_path
                })
            else:
                findings.append({
                    "title": "Password Minimum Age Properly Configured",
                    "description": f"Password minimum age is set to {min_days} days.",
                    "severity": "info",
                    "category": "Password Policy",
                    "check_name": "pass_min_days",
                    "status": "pass",
                    "current_value": f"{min_days} days",
                    "expected_value": f">= {recommended_min} day",
                    "affected_item": login_defs_path
                })

        except Exception as e:
            logger.error(f"Error checking PASS_MIN_DAYS: {e}")
            findings.append(self._create_error_finding("Password Min Age Check", str(e), login_defs_path))

        return findings

    def _check_pass_min_len(self, login_defs_path: str) -> List[Dict]:
        """Check minimum password length."""
        findings = []

        try:
            min_len = self._parse_login_defs(login_defs_path, "PASS_MIN_LEN")
            recommended_min = 14

            if min_len is None:
                findings.append({
                    "title": "Password Minimum Length Not Set",
                    "description": "PASS_MIN_LEN is not configured in login.defs.",
                    "severity": "medium",
                    "category": "Password Policy",
                    "check_name": "pass_min_len",
                    "status": "warning",
                    "current_value": "not set",
                    "expected_value": f">= {recommended_min} characters",
                    "remediation": self._get_detailed_remediation("pass_min_len", login_defs_path),
                    "affected_item": login_defs_path
                })
            elif int(min_len) < recommended_min:
                findings.append({
                    "title": "Password Minimum Length Too Short",
                    "description": f"Password minimum length is set to {min_len} characters. "
                                   f"Recommended: {recommended_min} characters or more.",
                    "severity": "medium",
                    "category": "Password Policy",
                    "check_name": "pass_min_len",
                    "status": "fail",
                    "current_value": f"{min_len} characters",
                    "expected_value": f">= {recommended_min} characters",
                    "remediation": self._get_detailed_remediation("pass_min_len", login_defs_path),
                    "affected_item": login_defs_path
                })
            else:
                findings.append({
                    "title": "Password Minimum Length Properly Configured",
                    "description": f"Password minimum length is set to {min_len} characters.",
                    "severity": "info",
                    "category": "Password Policy",
                    "check_name": "pass_min_len",
                    "status": "pass",
                    "current_value": f"{min_len} characters",
                    "expected_value": f">= {recommended_min} characters",
                    "affected_item": login_defs_path
                })

        except Exception as e:
            logger.error(f"Error checking PASS_MIN_LEN: {e}")
            findings.append(self._create_error_finding("Password Min Length Check", str(e), login_defs_path))

        return findings

    def _check_pass_warn_age(self, login_defs_path: str) -> List[Dict]:
        """Check password expiration warning days."""
        findings = []

        try:
            warn_age = self._parse_login_defs(login_defs_path, "PASS_WARN_AGE")
            recommended_warn = 7

            if warn_age and int(warn_age) < recommended_warn:
                findings.append({
                    "title": "Password Expiration Warning Too Short",
                    "description": f"Password expiration warning is set to {warn_age} days. "
                                   f"Recommended: {recommended_warn} days or more.",
                    "severity": "low",
                    "category": "Password Policy",
                    "check_name": "pass_warn_age",
                    "status": "warning",
                    "current_value": f"{warn_age} days",
                    "expected_value": f">= {recommended_warn} days",
                    "remediation": f"Edit {login_defs_path} and set 'PASS_WARN_AGE {recommended_warn}'",
                    "affected_item": login_defs_path
                })

        except Exception as e:
            logger.error(f"Error checking PASS_WARN_AGE: {e}")

        return findings

    def _parse_login_defs(self, login_defs_path: str, setting: str) -> Optional[str]:
        """
        Parse /etc/login.defs for a specific setting.

        Args:
            login_defs_path: Path to login.defs
            setting: Setting name to find

        Returns:
            Setting value or None
        """
        try:
            with open(login_defs_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    if line.startswith(setting):
                        parts = line.split()
                        if len(parts) >= 2:
                            return parts[1]
            return None
        except Exception as e:
            logger.error(f"Error parsing login.defs: {e}")
            raise

    # ========================
    # Firewall Checks
    # ========================

    def _check_firewall_status(self) -> List[Dict]:
        """
        Check if firewall (ufw or iptables) is enabled.

        Returns:
            List of findings
        """
        logger.info("Checking firewall status")
        findings = []

        # Check UFW first
        ufw_status = self._check_ufw_status()
        if ufw_status is not None:
            if ufw_status:
                findings.append({
                    "title": "UFW Firewall Enabled",
                    "description": "UFW (Uncomplicated Firewall) is active.",
                    "severity": "info",
                    "category": "Firewall",
                    "check_name": "firewall_enabled",
                    "status": "pass",
                    "current_value": "active",
                    "expected_value": "active",
                    "affected_item": "ufw"
                })
            else:
                findings.append({
                    "title": "UFW Firewall Disabled",
                    "description": "UFW (Uncomplicated Firewall) is installed but not active. "
                                   "A firewall should be enabled to protect against network threats.",
                    "severity": "high",
                    "category": "Firewall",
                    "check_name": "firewall_enabled",
                    "status": "fail",
                    "current_value": "inactive",
                    "expected_value": "active",
                    "remediation": "Enable UFW with 'sudo ufw enable'",
                    "affected_item": "ufw",
                    "references": ["CIS Benchmark: 3.5.1.1"]
                })
            return findings

        # Check iptables as fallback
        iptables_rules = self._check_iptables_rules()
        if iptables_rules:
            findings.append({
                "title": "iptables Firewall Configured",
                "description": f"iptables has {iptables_rules} rules configured.",
                "severity": "info",
                "category": "Firewall",
                "check_name": "firewall_enabled",
                "status": "pass",
                "current_value": f"{iptables_rules} rules",
                "expected_value": "active with rules",
                "affected_item": "iptables"
            })
        else:
            findings.append({
                "title": "No Firewall Detected",
                "description": "Neither UFW nor iptables appears to be configured. "
                               "A firewall is essential for system security.",
                "severity": "critical",
                "category": "Firewall",
                "check_name": "firewall_enabled",
                "status": "fail",
                "current_value": "no firewall active",
                "expected_value": "active firewall",
                "remediation": self._get_detailed_remediation("firewall_not_configured", "firewall"),
                "affected_item": "firewall",
                "references": ["CIS Benchmark: 3.5"]
            })

        return findings

    def _check_ufw_status(self) -> Optional[bool]:
        """
        Check if UFW is installed and active.

        Returns:
            True if active, False if inactive, None if not installed
        """
        try:
            result = subprocess.run(
                ['ufw', 'status'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                return 'Status: active' in result.stdout
            return None
        except FileNotFoundError:
            return None
        except Exception as e:
            logger.error(f"Error checking UFW status: {e}")
            return None

    def _check_iptables_rules(self) -> int:
        """
        Count iptables rules (excluding default chains).

        Returns:
            Number of iptables rules
        """
        try:
            result = subprocess.run(
                ['iptables', '-L', '-n'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                # Count rules (excluding chain headers and policies)
                lines = [l for l in result.stdout.split('\n') if l and not l.startswith('Chain') and not l.startswith('target')]
                return len(lines)
            return 0
        except FileNotFoundError:
            return 0
        except Exception as e:
            logger.error(f"Error checking iptables: {e}")
            return 0

    def _check_firewall_rules(self) -> List[Dict]:
        """Check for specific firewall rule recommendations."""
        findings = []

        # This is a placeholder for more detailed firewall rule checks
        # Could check for open ports, allowed services, etc.

        return findings

    # ========================
    # File Permission Checks
    # ========================

    def _check_critical_file_permissions(self) -> List[Dict]:
        """
        Check permissions on critical system files.

        Returns:
            List of findings
        """
        logger.info("Checking critical file permissions")
        findings = []

        findings.extend(self._check_passwd_permissions())
        findings.extend(self._check_shadow_permissions())
        findings.extend(self._check_group_permissions())
        findings.extend(self._check_gshadow_permissions())

        return findings

    def _check_passwd_permissions(self) -> List[Dict]:
        """Check /etc/passwd permissions."""
        findings = []
        passwd_path = "/etc/passwd"

        try:
            if os.path.exists(passwd_path):
                stat_info = os.stat(passwd_path)
                permissions = oct(stat_info.st_mode)[-3:]

                if permissions != "644":
                    findings.append({
                        "title": "/etc/passwd Has Incorrect Permissions",
                        "description": f"/etc/passwd has permissions {permissions}. Should be 644.",
                        "severity": "high",
                        "category": "File Permissions",
                        "check_name": "passwd_permissions",
                        "status": "fail",
                        "current_value": permissions,
                        "expected_value": "644",
                        "remediation": f"Run 'sudo chmod 644 {passwd_path}'",
                        "affected_item": passwd_path,
                        "references": ["CIS Benchmark: 6.1.2"]
                    })
                else:
                    findings.append({
                        "title": "/etc/passwd Permissions Correct",
                        "description": "/etc/passwd has correct permissions (644).",
                        "severity": "info",
                        "category": "File Permissions",
                        "check_name": "passwd_permissions",
                        "status": "pass",
                        "current_value": permissions,
                        "expected_value": "644",
                        "affected_item": passwd_path
                    })

        except Exception as e:
            logger.error(f"Error checking /etc/passwd permissions: {e}")
            findings.append(self._create_error_finding("passwd Permissions Check", str(e), passwd_path))

        return findings

    def _check_shadow_permissions(self) -> List[Dict]:
        """Check /etc/shadow permissions."""
        findings = []
        shadow_path = "/etc/shadow"

        try:
            if os.path.exists(shadow_path):
                stat_info = os.stat(shadow_path)
                permissions = oct(stat_info.st_mode)[-3:]

                # shadow should be 000 or 640
                if permissions not in ["000", "640"]:
                    findings.append({
                        "title": "/etc/shadow Has Incorrect Permissions",
                        "description": f"/etc/shadow has permissions {permissions}. Should be 000 or 640.",
                        "severity": "critical",
                        "category": "File Permissions",
                        "check_name": "shadow_permissions",
                        "status": "fail",
                        "current_value": permissions,
                        "expected_value": "000 or 640",
                        "remediation": f"Run 'sudo chmod 000 {shadow_path}' or 'sudo chmod 640 {shadow_path}'",
                        "affected_item": shadow_path,
                        "references": ["CIS Benchmark: 6.1.3"]
                    })
                else:
                    findings.append({
                        "title": "/etc/shadow Permissions Correct",
                        "description": f"/etc/shadow has correct permissions ({permissions}).",
                        "severity": "info",
                        "category": "File Permissions",
                        "check_name": "shadow_permissions",
                        "status": "pass",
                        "current_value": permissions,
                        "expected_value": "000 or 640",
                        "affected_item": shadow_path
                    })

        except PermissionError:
            findings.append({
                "title": "Cannot Check /etc/shadow Permissions",
                "description": "Insufficient permissions to check /etc/shadow. Run with sudo.",
                "severity": "info",
                "category": "File Permissions",
                "check_name": "shadow_permissions",
                "status": "warning",
                "current_value": "unknown (permission denied)",
                "expected_value": "000 or 640",
                "affected_item": shadow_path
            })
        except Exception as e:
            logger.error(f"Error checking /etc/shadow permissions: {e}")
            findings.append(self._create_error_finding("shadow Permissions Check", str(e), shadow_path))

        return findings

    def _check_group_permissions(self) -> List[Dict]:
        """Check /etc/group permissions."""
        findings = []
        group_path = "/etc/group"

        try:
            if os.path.exists(group_path):
                stat_info = os.stat(group_path)
                permissions = oct(stat_info.st_mode)[-3:]

                if permissions != "644":
                    findings.append({
                        "title": "/etc/group Has Incorrect Permissions",
                        "description": f"/etc/group has permissions {permissions}. Should be 644.",
                        "severity": "medium",
                        "category": "File Permissions",
                        "check_name": "group_permissions",
                        "status": "fail",
                        "current_value": permissions,
                        "expected_value": "644",
                        "remediation": f"Run 'sudo chmod 644 {group_path}'",
                        "affected_item": group_path,
                        "references": ["CIS Benchmark: 6.1.4"]
                    })

        except Exception as e:
            logger.error(f"Error checking /etc/group permissions: {e}")

        return findings

    def _check_gshadow_permissions(self) -> List[Dict]:
        """Check /etc/gshadow permissions."""
        findings = []
        gshadow_path = "/etc/gshadow"

        try:
            if os.path.exists(gshadow_path):
                stat_info = os.stat(gshadow_path)
                permissions = oct(stat_info.st_mode)[-3:]

                if permissions not in ["000", "640"]:
                    findings.append({
                        "title": "/etc/gshadow Has Incorrect Permissions",
                        "description": f"/etc/gshadow has permissions {permissions}. Should be 000 or 640.",
                        "severity": "high",
                        "category": "File Permissions",
                        "check_name": "gshadow_permissions",
                        "status": "fail",
                        "current_value": permissions,
                        "expected_value": "000 or 640",
                        "remediation": f"Run 'sudo chmod 000 {gshadow_path}'",
                        "affected_item": gshadow_path,
                        "references": ["CIS Benchmark: 6.1.5"]
                    })

        except PermissionError:
            pass  # Expected if not running as root
        except Exception as e:
            logger.error(f"Error checking /etc/gshadow permissions: {e}")

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
            ("telnet", "critical", "Telnet is insecure and should not be used"),
            ("rsh", "critical", "RSH is insecure and should not be used"),
            ("rlogin", "critical", "Rlogin is insecure and should not be used"),
            ("ftp", "high", "FTP transmits credentials in plaintext"),
            ("tftp", "high", "TFTP has no authentication"),
            ("cups", "low", "Print service may not be needed on servers"),
            ("avahi-daemon", "low", "Avahi may not be needed on servers"),
        ]

        for service_name, severity, description in unnecessary_services:
            if self._is_service_running(service_name):
                findings.append({
                    "title": f"Unnecessary Service Running: {service_name}",
                    "description": description,
                    "severity": severity,
                    "category": "Services",
                    "check_name": f"service_{service_name}",
                    "status": "fail",
                    "current_value": "running",
                    "expected_value": "stopped/disabled",
                    "remediation": f"Stop and disable {service_name}: "
                                   f"'sudo systemctl stop {service_name} && "
                                   f"sudo systemctl disable {service_name}'",
                    "affected_item": service_name
                })

        if not findings:
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
        Check if a systemd service is running.

        Args:
            service_name: Name of the service

        Returns:
            True if running, False otherwise
        """
        try:
            result = subprocess.run(
                ['systemctl', 'is-active', service_name],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.stdout.strip() == 'active'
        except Exception as e:
            logger.debug(f"Error checking service {service_name}: {e}")
            return False

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

    def _get_detailed_remediation(self, check_name: str, affected_item: str = "", **kwargs) -> str:
        """
        Get detailed step-by-step remediation instructions for a specific check.

        Args:
            check_name: Name of the security check
            affected_item: The item that needs remediation
            **kwargs: Additional parameters specific to the check

        Returns:
            Detailed remediation instructions with commands
        """
        remediations = {
            "ssh_permit_root_login": """
STEP-BY-STEP FIX:
1. Backup the SSH configuration file:
   sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup

2. Edit the SSH configuration:
   sudo nano /etc/ssh/sshd_config

3. Find the line containing 'PermitRootLogin' and change it to:
   PermitRootLogin no

4. If the line doesn't exist, add it at the end of the file

5. Save and exit (Ctrl+X, then Y, then Enter in nano)

6. Test the configuration for syntax errors:
   sudo sshd -t

7. If no errors, restart SSH service:
   sudo systemctl restart sshd

8. Verify root login is disabled by checking:
   sudo grep "^PermitRootLogin" /etc/ssh/sshd_config

⚠️  IMPORTANT: Ensure you have a non-root user with sudo privileges before disabling root login!
""",
            "ssh_password_authentication": """
STEP-BY-STEP FIX:
1. First, set up SSH key authentication for your user:
   # On your local machine:
   ssh-keygen -t rsa -b 4096 -C "your_email@example.com"

   # Copy the key to the server:
   ssh-copy-id username@server_ip

2. Test SSH key login before disabling passwords:
   ssh username@server_ip

3. Once verified, backup SSH config:
   sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup

4. Edit the SSH configuration:
   sudo nano /etc/ssh/sshd_config

5. Find and modify these lines:
   PasswordAuthentication no
   ChallengeResponseAuthentication no
   PubkeyAuthentication yes

6. Save and exit (Ctrl+X, then Y, then Enter)

7. Test configuration:
   sudo sshd -t

8. Restart SSH:
   sudo systemctl restart sshd

⚠️  CRITICAL: Do NOT close your current SSH session until you verify key-based login works!
""",
            "ssh_port": """
STEP-BY-STEP FIX:
1. Choose a non-standard port (e.g., 2222, avoid ports below 1024 or commonly used ports)

2. Backup SSH config:
   sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup

3. Edit SSH configuration:
   sudo nano /etc/ssh/sshd_config

4. Find the line '#Port 22' or 'Port 22' and change to:
   Port 2222
   (Replace 2222 with your chosen port)

5. If using a firewall (UFW), allow the new port:
   sudo ufw allow 2222/tcp
   sudo ufw reload

6. For SELinux systems, allow the new port:
   sudo semanage port -a -t ssh_port_t -p tcp 2222

7. Test configuration:
   sudo sshd -t

8. Restart SSH:
   sudo systemctl restart sshd

9. Test connection on new port (keep current session open):
   ssh -p 2222 username@server_ip

⚠️  Keep your current SSH session open until you verify the new port works!
""",
            "pass_max_days": """
STEP-BY-STEP FIX:
1. Backup the login definitions file:
   sudo cp /etc/login.defs /etc/login.defs.backup

2. Edit the file:
   sudo nano /etc/login.defs

3. Find the line 'PASS_MAX_DAYS' and change to:
   PASS_MAX_DAYS 90

4. Save and exit (Ctrl+X, then Y, then Enter)

5. Apply to existing users (optional but recommended):
   # List users with UID >= 1000
   awk -F: '($3>=1000)&&($1!="nobody"){print $1}' /etc/passwd

   # Set max days for each user:
   sudo chage -M 90 username

6. Verify changes:
   grep PASS_MAX_DAYS /etc/login.defs

7. Check specific user:
   sudo chage -l username

📝 Note: This only affects NEW users. Existing users need manual update with 'chage' command.
""",
            "pass_min_days": """
STEP-BY-STEP FIX:
1. Backup configuration:
   sudo cp /etc/login.defs /etc/login.defs.backup

2. Edit the file:
   sudo nano /etc/login.defs

3. Find or add the line:
   PASS_MIN_DAYS 1

4. Save and exit (Ctrl+X, then Y, then Enter)

5. Apply to existing users:
   # For each user with UID >= 1000:
   sudo chage -m 1 username

6. Verify:
   grep PASS_MIN_DAYS /etc/login.defs
   sudo chage -l username

📝 This prevents users from changing passwords too frequently.
""",
            "pass_min_len": """
STEP-BY-STEP FIX:
1. Backup configuration:
   sudo cp /etc/login.defs /etc/login.defs.backup

2. Edit the file:
   sudo nano /etc/login.defs

3. Add or modify the line:
   PASS_MIN_LEN 14

4. For stronger enforcement, also configure PAM:
   sudo nano /etc/pam.d/common-password

5. Find the line with 'pam_unix.so' and add 'minlen=14':
   password [success=1 default=ignore] pam_unix.so obscure sha512 minlen=14

6. Or use pam_pwquality for more options:
   sudo apt install libpam-pwquality
   sudo nano /etc/security/pwquality.conf

   Add:
   minlen = 14
   dcredit = -1  # At least 1 digit
   ucredit = -1  # At least 1 uppercase
   lcredit = -1  # At least 1 lowercase
   ocredit = -1  # At least 1 special char

7. Save all files and exit

8. Test with a new user or password change:
   sudo passwd testuser

📝 Strong passwords are your first line of defense!
""",
            "firewall_not_configured": """
STEP-BY-STEP FIX (Using UFW - Recommended for beginners):

1. Install UFW if not present:
   sudo apt update
   sudo apt install ufw

2. Set default policies (deny incoming, allow outgoing):
   sudo ufw default deny incoming
   sudo ufw default allow outgoing

3. Allow SSH before enabling (CRITICAL - prevents lockout):
   sudo ufw allow ssh
   # Or if using custom SSH port:
   sudo ufw allow 2222/tcp

4. Allow other essential services:
   # Web server:
   sudo ufw allow 80/tcp
   sudo ufw allow 443/tcp

   # Custom applications:
   sudo ufw allow [port]/[protocol]

5. Enable the firewall:
   sudo ufw enable

6. Verify status:
   sudo ufw status verbose

7. To see numbered list of rules:
   sudo ufw status numbered

8. To delete a rule:
   sudo ufw delete [number]

ALTERNATIVE - Using iptables:

1. Create basic firewall rules:
   # Allow established connections:
   sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

   # Allow loopback:
   sudo iptables -A INPUT -i lo -j ACCEPT

   # Allow SSH:
   sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT

   # Drop everything else:
   sudo iptables -A INPUT -j DROP

2. Save rules (Ubuntu/Debian):
   sudo apt install iptables-persistent
   sudo netfilter-persistent save

3. View rules:
   sudo iptables -L -v -n

⚠️  CRITICAL: Always allow SSH before enabling the firewall to prevent lockout!
📝 Reference: CIS Benchmark 3.5
""",
            "shadow_permissions": """
STEP-BY-STEP FIX:
1. Check current permissions:
   ls -l /etc/shadow

2. Fix permissions:
   sudo chmod 640 /etc/shadow
   sudo chown root:shadow /etc/shadow

3. Verify the fix:
   ls -l /etc/shadow
   # Should show: -rw-r----- 1 root shadow

📝 The shadow file contains password hashes and must be protected.
""",
            "passwd_permissions": """
STEP-BY-STEP FIX:
1. Check current permissions:
   ls -l /etc/passwd

2. Fix permissions:
   sudo chmod 644 /etc/passwd
   sudo chown root:root /etc/passwd

3. Verify the fix:
   ls -l /etc/passwd
   # Should show: -rw-r--r-- 1 root root

📝 The passwd file must be world-readable for system functionality.
"""
        }

        # Return detailed remediation or a default message
        return remediations.get(check_name,
            f"No detailed remediation steps available for {check_name}. "
            f"Please refer to security best practices documentation."
        )


# Example usage and testing
if __name__ == "__main__":
    # Configure logging for standalone testing
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    print("=" * 70)
    print("Linux Security Checker - Test Run")
    print("=" * 70)

    checker = LinuxChecker()

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
