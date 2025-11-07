#!/usr/bin/env python3
"""
Linux Hardener Module
Implements specific hardening operations for Linux systems.
Handles SSH, password policies, firewall, permissions, and services.
"""

import os
import re
import pwd
import grp
import stat
import shutil
import subprocess
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from enum import Enum

logger = logging.getLogger(__name__)


class HardeningResult:
    """Result of a hardening operation."""

    def __init__(self, success: bool, message: str, details: Optional[Dict] = None):
        """
        Initialize hardening result.

        Args:
            success: Whether the operation succeeded
            message: Description of the result
            details: Additional details about the operation
        """
        self.success = success
        self.message = message
        self.details = details or {}

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "success": self.success,
            "message": self.message,
            "details": self.details
        }


class FirewallType(Enum):
    """Supported firewall types."""
    UFW = "ufw"
    IPTABLES = "iptables"
    FIREWALLD = "firewalld"
    NONE = "none"


class LinuxHardener:
    """
    Linux system hardener implementing various security configurations.
    """

    def __init__(self, dry_run: bool = False):
        """
        Initialize Linux hardener.

        Args:
            dry_run: If True, simulate changes without applying them
        """
        self.dry_run = dry_run
        self.firewall_type = self._detect_firewall()
        logger.info(f"LinuxHardener initialized (dry_run={dry_run}, firewall={self.firewall_type.value})")

    # ==================== SSH Configuration ====================

    def modify_ssh_config(
        self,
        parameter: str,
        value: str,
        config_file: str = "/etc/ssh/sshd_config"
    ) -> HardeningResult:
        """
        Modify SSH configuration parameter.

        Args:
            parameter: SSH parameter name (e.g., 'PermitRootLogin')
            value: New value for the parameter
            config_file: Path to SSH config file

        Returns:
            HardeningResult with operation status
        """
        logger.info(f"Modifying SSH config: {parameter} = {value}")

        try:
            # Check current state
            current_value = self._read_ssh_parameter(config_file, parameter)
            logger.debug(f"Current value of {parameter}: {current_value}")

            if current_value and current_value.lower() == value.lower():
                logger.info(f"SSH parameter {parameter} already set to {value}")
                return HardeningResult(
                    True,
                    f"Parameter {parameter} already configured correctly",
                    {"current_value": current_value, "desired_value": value}
                )

            # Make modification
            if self.dry_run:
                logger.info(f"DRY RUN: Would set {parameter} = {value} in {config_file}")
                return HardeningResult(
                    True,
                    f"[DRY RUN] Would set {parameter} = {value}",
                    {"before": current_value, "after": value}
                )

            success = self._write_ssh_parameter(config_file, parameter, value)

            if not success:
                return HardeningResult(False, f"Failed to write {parameter} to {config_file}")

            # Verify change
            new_value = self._read_ssh_parameter(config_file, parameter)

            if new_value and new_value.lower() == value.lower():
                logger.info(f"Successfully set {parameter} = {value}")
                return HardeningResult(
                    True,
                    f"Successfully configured {parameter} = {value}",
                    {"before": current_value, "after": new_value}
                )
            else:
                logger.error(f"Verification failed: {parameter} = {new_value} (expected {value})")
                return HardeningResult(
                    False,
                    f"Verification failed for {parameter}",
                    {"expected": value, "actual": new_value}
                )

        except Exception as e:
            logger.error(f"Error modifying SSH config: {e}", exc_info=True)
            return HardeningResult(False, f"Exception: {str(e)}")

    def _read_ssh_parameter(self, config_file: str, parameter: str) -> Optional[str]:
        """Read SSH parameter value from config file."""
        try:
            if not os.path.exists(config_file):
                logger.warning(f"SSH config file not found: {config_file}")
                return None

            with open(config_file, 'r') as f:
                for line in f:
                    # Skip comments and empty lines
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue

                    # Match parameter (case-insensitive)
                    match = re.match(rf'^{re.escape(parameter)}\s+(.+)$', line, re.IGNORECASE)
                    if match:
                        value = match.group(1).strip()
                        # Remove inline comments
                        value = re.sub(r'\s*#.*$', '', value).strip()
                        return value

            return None

        except Exception as e:
            logger.error(f"Error reading SSH parameter {parameter}: {e}")
            return None

    def _write_ssh_parameter(self, config_file: str, parameter: str, value: str) -> bool:
        """Write SSH parameter value to config file."""
        try:
            if not os.path.exists(config_file):
                logger.error(f"SSH config file not found: {config_file}")
                return False

            # Read all lines
            with open(config_file, 'r') as f:
                lines = f.readlines()

            # Find and replace or append
            modified = False
            new_lines = []

            for line in lines:
                stripped = line.strip()

                # Check if this line contains the parameter (not commented)
                if not stripped.startswith('#') and stripped:
                    match = re.match(rf'^{re.escape(parameter)}\s+', stripped, re.IGNORECASE)
                    if match:
                        # Replace this line
                        new_lines.append(f"{parameter} {value}\n")
                        modified = True
                        logger.debug(f"Replaced line: {parameter} {value}")
                        continue

                new_lines.append(line)

            # If not modified, append to end
            if not modified:
                new_lines.append(f"\n# Added by system hardening tool\n")
                new_lines.append(f"{parameter} {value}\n")
                logger.debug(f"Appended: {parameter} {value}")

            # Write back
            with open(config_file, 'w') as f:
                f.writelines(new_lines)

            logger.debug(f"Successfully wrote {parameter} to {config_file}")
            return True

        except PermissionError:
            logger.error(f"Permission denied writing to {config_file}")
            return False
        except Exception as e:
            logger.error(f"Error writing SSH parameter: {e}")
            return False

    def restart_ssh_service(self) -> HardeningResult:
        """
        Restart SSH service to apply configuration changes.

        Returns:
            HardeningResult with operation status
        """
        logger.info("Restarting SSH service")

        if self.dry_run:
            return HardeningResult(True, "[DRY RUN] Would restart SSH service")

        # Try different service names
        service_names = ['sshd', 'ssh']

        for service_name in service_names:
            try:
                result = subprocess.run(
                    ['systemctl', 'restart', service_name],
                    capture_output=True,
                    text=True,
                    timeout=10
                )

                if result.returncode == 0:
                    logger.info(f"SSH service ({service_name}) restarted successfully")
                    return HardeningResult(True, f"SSH service restarted successfully")

            except subprocess.TimeoutExpired:
                logger.error(f"Timeout restarting {service_name}")
            except FileNotFoundError:
                logger.debug("systemctl not found, trying service command")
                try:
                    result = subprocess.run(
                        ['service', service_name, 'restart'],
                        capture_output=True,
                        text=True,
                        timeout=10
                    )
                    if result.returncode == 0:
                        return HardeningResult(True, f"SSH service restarted successfully")
                except Exception:
                    pass
            except Exception as e:
                logger.debug(f"Failed to restart {service_name}: {e}")

        logger.error("Failed to restart SSH service")
        return HardeningResult(False, "Failed to restart SSH service")

    # ==================== Password Policies (/etc/login.defs) ====================

    def update_login_defs(
        self,
        parameter: str,
        value: str,
        config_file: str = "/etc/login.defs"
    ) -> HardeningResult:
        """
        Update password policy in /etc/login.defs.

        Args:
            parameter: Parameter name (e.g., 'PASS_MAX_DAYS')
            value: New value
            config_file: Path to login.defs file

        Returns:
            HardeningResult with operation status
        """
        logger.info(f"Updating login.defs: {parameter} = {value}")

        try:
            # Check current state
            current_value = self._read_login_defs_parameter(config_file, parameter)
            logger.debug(f"Current value of {parameter}: {current_value}")

            if current_value == value:
                logger.info(f"Parameter {parameter} already set to {value}")
                return HardeningResult(
                    True,
                    f"Parameter {parameter} already configured correctly",
                    {"current_value": current_value}
                )

            # Make modification
            if self.dry_run:
                logger.info(f"DRY RUN: Would set {parameter} = {value} in {config_file}")
                return HardeningResult(
                    True,
                    f"[DRY RUN] Would set {parameter} = {value}",
                    {"before": current_value, "after": value}
                )

            success = self._write_login_defs_parameter(config_file, parameter, value)

            if not success:
                return HardeningResult(False, f"Failed to write {parameter} to {config_file}")

            # Verify change
            new_value = self._read_login_defs_parameter(config_file, parameter)

            if new_value == value:
                logger.info(f"Successfully set {parameter} = {value}")
                return HardeningResult(
                    True,
                    f"Successfully configured {parameter} = {value}",
                    {"before": current_value, "after": new_value}
                )
            else:
                logger.error(f"Verification failed: {parameter} = {new_value} (expected {value})")
                return HardeningResult(
                    False,
                    f"Verification failed for {parameter}",
                    {"expected": value, "actual": new_value}
                )

        except Exception as e:
            logger.error(f"Error updating login.defs: {e}", exc_info=True)
            return HardeningResult(False, f"Exception: {str(e)}")

    def _read_login_defs_parameter(self, config_file: str, parameter: str) -> Optional[str]:
        """Read parameter from login.defs."""
        try:
            if not os.path.exists(config_file):
                logger.warning(f"login.defs file not found: {config_file}")
                return None

            with open(config_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue

                    parts = line.split()
                    if len(parts) >= 2 and parts[0] == parameter:
                        return parts[1]

            return None

        except Exception as e:
            logger.error(f"Error reading login.defs parameter {parameter}: {e}")
            return None

    def _write_login_defs_parameter(self, config_file: str, parameter: str, value: str) -> bool:
        """Write parameter to login.defs."""
        try:
            if not os.path.exists(config_file):
                logger.error(f"login.defs file not found: {config_file}")
                return False

            with open(config_file, 'r') as f:
                lines = f.readlines()

            modified = False
            new_lines = []

            for line in lines:
                stripped = line.strip()

                if not stripped.startswith('#') and stripped:
                    parts = stripped.split()
                    if len(parts) >= 2 and parts[0] == parameter:
                        # Replace this line
                        new_lines.append(f"{parameter}\t{value}\n")
                        modified = True
                        logger.debug(f"Replaced line: {parameter} {value}")
                        continue

                new_lines.append(line)

            if not modified:
                new_lines.append(f"\n# Added by system hardening tool\n")
                new_lines.append(f"{parameter}\t{value}\n")
                logger.debug(f"Appended: {parameter} {value}")

            with open(config_file, 'w') as f:
                f.writelines(new_lines)

            logger.debug(f"Successfully wrote {parameter} to {config_file}")
            return True

        except PermissionError:
            logger.error(f"Permission denied writing to {config_file}")
            return False
        except Exception as e:
            logger.error(f"Error writing login.defs parameter: {e}")
            return False

    def set_password_max_age(self, days: int) -> HardeningResult:
        """Set maximum password age."""
        return self.update_login_defs("PASS_MAX_DAYS", str(days))

    def set_password_min_age(self, days: int) -> HardeningResult:
        """Set minimum password age."""
        return self.update_login_defs("PASS_MIN_DAYS", str(days))

    def set_password_warn_age(self, days: int) -> HardeningResult:
        """Set password warning age."""
        return self.update_login_defs("PASS_WARN_AGE", str(days))

    def set_password_min_length(self, length: int) -> HardeningResult:
        """Set minimum password length."""
        return self.update_login_defs("PASS_MIN_LEN", str(length))

    # ==================== Firewall Configuration ====================

    def _detect_firewall(self) -> FirewallType:
        """Detect which firewall system is available."""
        try:
            # Check for UFW
            result = subprocess.run(['which', 'ufw'], capture_output=True)
            if result.returncode == 0:
                return FirewallType.UFW

            # Check for firewalld
            result = subprocess.run(['which', 'firewall-cmd'], capture_output=True)
            if result.returncode == 0:
                return FirewallType.FIREWALLD

            # Check for iptables
            result = subprocess.run(['which', 'iptables'], capture_output=True)
            if result.returncode == 0:
                return FirewallType.IPTABLES

            return FirewallType.NONE

        except Exception as e:
            logger.error(f"Error detecting firewall: {e}")
            return FirewallType.NONE

    def enable_firewall(self) -> HardeningResult:
        """
        Enable the system firewall.

        Returns:
            HardeningResult with operation status
        """
        logger.info(f"Enabling firewall ({self.firewall_type.value})")

        if self.firewall_type == FirewallType.NONE:
            return HardeningResult(False, "No firewall detected on system")

        if self.dry_run:
            return HardeningResult(True, f"[DRY RUN] Would enable {self.firewall_type.value}")

        try:
            if self.firewall_type == FirewallType.UFW:
                result = subprocess.run(
                    ['ufw', 'enable'],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    input='y\n'  # Auto-confirm
                )
                if result.returncode == 0:
                    logger.info("UFW firewall enabled")
                    return HardeningResult(True, "UFW firewall enabled successfully")

            elif self.firewall_type == FirewallType.FIREWALLD:
                result = subprocess.run(
                    ['systemctl', 'enable', 'firewalld'],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                subprocess.run(['systemctl', 'start', 'firewalld'], timeout=10)
                if result.returncode == 0:
                    logger.info("firewalld enabled")
                    return HardeningResult(True, "firewalld enabled successfully")

            return HardeningResult(False, f"Failed to enable {self.firewall_type.value}")

        except Exception as e:
            logger.error(f"Error enabling firewall: {e}")
            return HardeningResult(False, f"Exception: {str(e)}")

    def allow_port(self, port: int, protocol: str = "tcp") -> HardeningResult:
        """
        Allow traffic on a specific port.

        Args:
            port: Port number
            protocol: Protocol (tcp/udp)

        Returns:
            HardeningResult with operation status
        """
        logger.info(f"Allowing port {port}/{protocol}")

        if self.firewall_type == FirewallType.NONE:
            return HardeningResult(False, "No firewall detected")

        if self.dry_run:
            return HardeningResult(
                True,
                f"[DRY RUN] Would allow port {port}/{protocol}"
            )

        try:
            if self.firewall_type == FirewallType.UFW:
                result = subprocess.run(
                    ['ufw', 'allow', f'{port}/{protocol}'],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                if result.returncode == 0:
                    logger.info(f"Port {port}/{protocol} allowed via UFW")
                    return HardeningResult(True, f"Port {port}/{protocol} allowed")

            elif self.firewall_type == FirewallType.FIREWALLD:
                result = subprocess.run(
                    ['firewall-cmd', '--permanent', f'--add-port={port}/{protocol}'],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                subprocess.run(['firewall-cmd', '--reload'], timeout=10)
                if result.returncode == 0:
                    logger.info(f"Port {port}/{protocol} allowed via firewalld")
                    return HardeningResult(True, f"Port {port}/{protocol} allowed")

            return HardeningResult(False, f"Failed to allow port {port}/{protocol}")

        except Exception as e:
            logger.error(f"Error allowing port: {e}")
            return HardeningResult(False, f"Exception: {str(e)}")

    def deny_port(self, port: int, protocol: str = "tcp") -> HardeningResult:
        """
        Deny traffic on a specific port.

        Args:
            port: Port number
            protocol: Protocol (tcp/udp)

        Returns:
            HardeningResult with operation status
        """
        logger.info(f"Denying port {port}/{protocol}")

        if self.firewall_type == FirewallType.NONE:
            return HardeningResult(False, "No firewall detected")

        if self.dry_run:
            return HardeningResult(
                True,
                f"[DRY RUN] Would deny port {port}/{protocol}"
            )

        try:
            if self.firewall_type == FirewallType.UFW:
                result = subprocess.run(
                    ['ufw', 'deny', f'{port}/{protocol}'],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                if result.returncode == 0:
                    logger.info(f"Port {port}/{protocol} denied via UFW")
                    return HardeningResult(True, f"Port {port}/{protocol} denied")

            elif self.firewall_type == FirewallType.FIREWALLD:
                result = subprocess.run(
                    ['firewall-cmd', '--permanent', f'--remove-port={port}/{protocol}'],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                subprocess.run(['firewall-cmd', '--reload'], timeout=10)
                if result.returncode == 0:
                    logger.info(f"Port {port}/{protocol} denied via firewalld")
                    return HardeningResult(True, f"Port {port}/{protocol} denied")

            return HardeningResult(False, f"Failed to deny port {port}/{protocol}")

        except Exception as e:
            logger.error(f"Error denying port: {e}")
            return HardeningResult(False, f"Exception: {str(e)}")

    # ==================== File Permissions ====================

    def set_file_permissions(
        self,
        file_path: str,
        mode: int,
        owner: Optional[str] = None,
        group: Optional[str] = None
    ) -> HardeningResult:
        """
        Set file permissions and ownership.

        Args:
            file_path: Path to file or directory
            mode: Permission mode (octal, e.g., 0o600)
            owner: Owner username (optional)
            group: Group name (optional)

        Returns:
            HardeningResult with operation status
        """
        logger.info(f"Setting permissions for {file_path}: mode={oct(mode)}, owner={owner}, group={group}")

        try:
            # Check if file exists
            if not os.path.exists(file_path):
                return HardeningResult(False, f"File not found: {file_path}")

            # Get current state
            current_stat = os.stat(file_path)
            current_mode = stat.S_IMODE(current_stat.st_mode)
            current_owner = pwd.getpwuid(current_stat.st_uid).pw_name
            current_group = grp.getgrgid(current_stat.st_gid).gr_name

            logger.debug(
                f"Current: mode={oct(current_mode)}, "
                f"owner={current_owner}, group={current_group}"
            )

            if self.dry_run:
                return HardeningResult(
                    True,
                    f"[DRY RUN] Would set permissions on {file_path}",
                    {
                        "before": {
                            "mode": oct(current_mode),
                            "owner": current_owner,
                            "group": current_group
                        },
                        "after": {
                            "mode": oct(mode),
                            "owner": owner or current_owner,
                            "group": group or current_group
                        }
                    }
                )

            # Set permissions
            if current_mode != mode:
                os.chmod(file_path, mode)
                logger.info(f"Changed mode to {oct(mode)}")

            # Set ownership
            if owner or group:
                uid = pwd.getpwnam(owner).pw_uid if owner else -1
                gid = grp.getgrnam(group).gr_gid if group else -1

                if uid != -1 or gid != -1:
                    os.chown(file_path, uid, gid)
                    logger.info(f"Changed ownership to {owner}:{group}")

            # Verify changes
            new_stat = os.stat(file_path)
            new_mode = stat.S_IMODE(new_stat.st_mode)
            new_owner = pwd.getpwuid(new_stat.st_uid).pw_name
            new_group = grp.getgrgid(new_stat.st_gid).gr_name

            if new_mode == mode:
                logger.info(f"Successfully set permissions on {file_path}")
                return HardeningResult(
                    True,
                    f"Permissions updated successfully",
                    {
                        "before": {
                            "mode": oct(current_mode),
                            "owner": current_owner,
                            "group": current_group
                        },
                        "after": {
                            "mode": oct(new_mode),
                            "owner": new_owner,
                            "group": new_group
                        }
                    }
                )
            else:
                return HardeningResult(
                    False,
                    "Verification failed after setting permissions"
                )

        except PermissionError:
            logger.error(f"Permission denied modifying {file_path}")
            return HardeningResult(False, f"Permission denied: {file_path}")
        except KeyError as e:
            logger.error(f"Invalid user or group: {e}")
            return HardeningResult(False, f"Invalid user or group: {e}")
        except Exception as e:
            logger.error(f"Error setting permissions: {e}", exc_info=True)
            return HardeningResult(False, f"Exception: {str(e)}")

    def set_directory_permissions_recursive(
        self,
        directory: str,
        file_mode: int,
        dir_mode: int,
        owner: Optional[str] = None,
        group: Optional[str] = None
    ) -> HardeningResult:
        """
        Set permissions recursively on a directory.

        Args:
            directory: Directory path
            file_mode: Mode for files
            dir_mode: Mode for directories
            owner: Owner username (optional)
            group: Group name (optional)

        Returns:
            HardeningResult with operation status
        """
        logger.info(f"Setting recursive permissions for {directory}")

        if not os.path.isdir(directory):
            return HardeningResult(False, f"Not a directory: {directory}")

        if self.dry_run:
            return HardeningResult(
                True,
                f"[DRY RUN] Would set recursive permissions on {directory}"
            )

        try:
            files_modified = 0
            dirs_modified = 0

            for root, dirs, files in os.walk(directory):
                # Set directory permissions
                for d in dirs:
                    dir_path = os.path.join(root, d)
                    result = self.set_file_permissions(dir_path, dir_mode, owner, group)
                    if result.success:
                        dirs_modified += 1

                # Set file permissions
                for f in files:
                    file_path = os.path.join(root, f)
                    result = self.set_file_permissions(file_path, file_mode, owner, group)
                    if result.success:
                        files_modified += 1

            logger.info(
                f"Recursive permissions set: "
                f"{files_modified} files, {dirs_modified} directories"
            )

            return HardeningResult(
                True,
                f"Recursive permissions updated",
                {"files_modified": files_modified, "dirs_modified": dirs_modified}
            )

        except Exception as e:
            logger.error(f"Error setting recursive permissions: {e}")
            return HardeningResult(False, f"Exception: {str(e)}")

    # ==================== Systemd Service Management ====================

    def enable_service(self, service_name: str) -> HardeningResult:
        """
        Enable a systemd service.

        Args:
            service_name: Name of the service

        Returns:
            HardeningResult with operation status
        """
        logger.info(f"Enabling service: {service_name}")

        try:
            # Check current state
            is_enabled = self._is_service_enabled(service_name)

            if is_enabled:
                logger.info(f"Service {service_name} is already enabled")
                return HardeningResult(True, f"Service {service_name} already enabled")

            if self.dry_run:
                return HardeningResult(
                    True,
                    f"[DRY RUN] Would enable service {service_name}"
                )

            # Enable the service
            result = subprocess.run(
                ['systemctl', 'enable', service_name],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode != 0:
                logger.error(f"Failed to enable service: {result.stderr}")
                return HardeningResult(False, f"Failed to enable service: {result.stderr}")

            # Verify
            is_enabled = self._is_service_enabled(service_name)

            if is_enabled:
                logger.info(f"Service {service_name} enabled successfully")
                return HardeningResult(True, f"Service {service_name} enabled successfully")
            else:
                return HardeningResult(False, "Verification failed after enabling service")

        except FileNotFoundError:
            logger.error("systemctl command not found")
            return HardeningResult(False, "systemctl not found - systemd not available")
        except subprocess.TimeoutExpired:
            logger.error("Timeout enabling service")
            return HardeningResult(False, "Timeout enabling service")
        except Exception as e:
            logger.error(f"Error enabling service: {e}")
            return HardeningResult(False, f"Exception: {str(e)}")

    def disable_service(self, service_name: str) -> HardeningResult:
        """
        Disable a systemd service.

        Args:
            service_name: Name of the service

        Returns:
            HardeningResult with operation status
        """
        logger.info(f"Disabling service: {service_name}")

        try:
            # Check current state
            is_enabled = self._is_service_enabled(service_name)

            if not is_enabled:
                logger.info(f"Service {service_name} is already disabled")
                return HardeningResult(True, f"Service {service_name} already disabled")

            if self.dry_run:
                return HardeningResult(
                    True,
                    f"[DRY RUN] Would disable service {service_name}"
                )

            # Disable the service
            result = subprocess.run(
                ['systemctl', 'disable', service_name],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode != 0:
                logger.error(f"Failed to disable service: {result.stderr}")
                return HardeningResult(False, f"Failed to disable service: {result.stderr}")

            # Verify
            is_enabled = self._is_service_enabled(service_name)

            if not is_enabled:
                logger.info(f"Service {service_name} disabled successfully")
                return HardeningResult(True, f"Service {service_name} disabled successfully")
            else:
                return HardeningResult(False, "Verification failed after disabling service")

        except FileNotFoundError:
            logger.error("systemctl command not found")
            return HardeningResult(False, "systemctl not found - systemd not available")
        except subprocess.TimeoutExpired:
            logger.error("Timeout disabling service")
            return HardeningResult(False, "Timeout disabling service")
        except Exception as e:
            logger.error(f"Error disabling service: {e}")
            return HardeningResult(False, f"Exception: {str(e)}")

    def stop_service(self, service_name: str) -> HardeningResult:
        """
        Stop a running service.

        Args:
            service_name: Name of the service

        Returns:
            HardeningResult with operation status
        """
        logger.info(f"Stopping service: {service_name}")

        try:
            # Check if running
            is_running = self._is_service_running(service_name)

            if not is_running:
                logger.info(f"Service {service_name} is already stopped")
                return HardeningResult(True, f"Service {service_name} already stopped")

            if self.dry_run:
                return HardeningResult(
                    True,
                    f"[DRY RUN] Would stop service {service_name}"
                )

            # Stop the service
            result = subprocess.run(
                ['systemctl', 'stop', service_name],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode != 0:
                logger.error(f"Failed to stop service: {result.stderr}")
                return HardeningResult(False, f"Failed to stop service: {result.stderr}")

            # Verify
            is_running = self._is_service_running(service_name)

            if not is_running:
                logger.info(f"Service {service_name} stopped successfully")
                return HardeningResult(True, f"Service {service_name} stopped successfully")
            else:
                return HardeningResult(False, "Verification failed after stopping service")

        except FileNotFoundError:
            logger.error("systemctl command not found")
            return HardeningResult(False, "systemctl not found - systemd not available")
        except subprocess.TimeoutExpired:
            logger.error("Timeout stopping service")
            return HardeningResult(False, "Timeout stopping service")
        except Exception as e:
            logger.error(f"Error stopping service: {e}")
            return HardeningResult(False, f"Exception: {str(e)}")

    def start_service(self, service_name: str) -> HardeningResult:
        """
        Start a service.

        Args:
            service_name: Name of the service

        Returns:
            HardeningResult with operation status
        """
        logger.info(f"Starting service: {service_name}")

        try:
            # Check if already running
            is_running = self._is_service_running(service_name)

            if is_running:
                logger.info(f"Service {service_name} is already running")
                return HardeningResult(True, f"Service {service_name} already running")

            if self.dry_run:
                return HardeningResult(
                    True,
                    f"[DRY RUN] Would start service {service_name}"
                )

            # Start the service
            result = subprocess.run(
                ['systemctl', 'start', service_name],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode != 0:
                logger.error(f"Failed to start service: {result.stderr}")
                return HardeningResult(False, f"Failed to start service: {result.stderr}")

            # Verify
            is_running = self._is_service_running(service_name)

            if is_running:
                logger.info(f"Service {service_name} started successfully")
                return HardeningResult(True, f"Service {service_name} started successfully")
            else:
                return HardeningResult(False, "Verification failed after starting service")

        except FileNotFoundError:
            logger.error("systemctl command not found")
            return HardeningResult(False, "systemctl not found - systemd not available")
        except subprocess.TimeoutExpired:
            logger.error("Timeout starting service")
            return HardeningResult(False, "Timeout starting service")
        except Exception as e:
            logger.error(f"Error starting service: {e}")
            return HardeningResult(False, f"Exception: {str(e)}")

    def _is_service_enabled(self, service_name: str) -> bool:
        """Check if a service is enabled."""
        try:
            result = subprocess.run(
                ['systemctl', 'is-enabled', service_name],
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.returncode == 0 and 'enabled' in result.stdout.lower()
        except Exception:
            return False

    def _is_service_running(self, service_name: str) -> bool:
        """Check if a service is running."""
        try:
            result = subprocess.run(
                ['systemctl', 'is-active', service_name],
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.returncode == 0 and 'active' in result.stdout.lower()
        except Exception:
            return False

    def get_service_status(self, service_name: str) -> Dict[str, Any]:
        """
        Get detailed status of a service.

        Args:
            service_name: Name of the service

        Returns:
            Dictionary with service status information
        """
        return {
            "service": service_name,
            "enabled": self._is_service_enabled(service_name),
            "running": self._is_service_running(service_name)
        }


# Convenience functions
def harden_ssh_config(config_changes: Dict[str, str], dry_run: bool = False) -> Dict[str, HardeningResult]:
    """
    Apply multiple SSH configuration changes.

    Args:
        config_changes: Dictionary of parameter: value pairs
        dry_run: If True, simulate changes

    Returns:
        Dictionary of parameter: HardeningResult pairs
    """
    hardener = LinuxHardener(dry_run=dry_run)
    results = {}

    for parameter, value in config_changes.items():
        result = hardener.modify_ssh_config(parameter, value)
        results[parameter] = result

    return results


def harden_password_policy(policy_changes: Dict[str, str], dry_run: bool = False) -> Dict[str, HardeningResult]:
    """
    Apply multiple password policy changes.

    Args:
        policy_changes: Dictionary of parameter: value pairs
        dry_run: If True, simulate changes

    Returns:
        Dictionary of parameter: HardeningResult pairs
    """
    hardener = LinuxHardener(dry_run=dry_run)
    results = {}

    for parameter, value in policy_changes.items():
        result = hardener.update_login_defs(parameter, value)
        results[parameter] = result

    return results


# Example usage and testing
if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    print("=" * 70)
    print("Linux Hardener - Test Run (DRY RUN MODE)")
    print("=" * 70)

    # Initialize hardener in dry run mode
    hardener = LinuxHardener(dry_run=True)

    # Test SSH configuration
    print("\n1. Testing SSH Configuration")
    print("-" * 70)

    ssh_result = hardener.modify_ssh_config("PermitRootLogin", "no")
    print(f"Result: {ssh_result.message}")

    # Test password policy
    print("\n2. Testing Password Policy")
    print("-" * 70)

    pass_result = hardener.set_password_max_age(90)
    print(f"Result: {pass_result.message}")

    # Test firewall
    print("\n3. Testing Firewall")
    print("-" * 70)

    print(f"Detected firewall: {hardener.firewall_type.value}")
    fw_result = hardener.allow_port(22, "tcp")
    print(f"Result: {fw_result.message}")

    # Test file permissions
    print("\n4. Testing File Permissions")
    print("-" * 70)

    perm_result = hardener.set_file_permissions("/etc/hosts", 0o644, "root", "root")
    print(f"Result: {perm_result.message}")
    if perm_result.details:
        print(f"Details: {perm_result.details}")

    # Test service management
    print("\n5. Testing Service Management")
    print("-" * 70)

    svc_status = hardener.get_service_status("sshd")
    print(f"SSH Service Status: {svc_status}")

    svc_result = hardener.disable_service("telnet")
    print(f"Result: {svc_result.message}")

    print("\n" + "=" * 70)
    print("Test completed successfully!")
    print("=" * 70)
