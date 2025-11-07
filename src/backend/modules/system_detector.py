#!/usr/bin/env python3
"""
System Detector Module
Detects operating system information, architecture, hostname, and user details.
"""

import platform
import os
import socket
import logging
from typing import Dict, Optional

logger = logging.getLogger(__name__)


class SystemDetector:
    """Detects and retrieves system information."""

    def __init__(self):
        """Initialize the SystemDetector."""
        self._os_type = None
        self._os_info = None

    def detect_os_type(self) -> str:
        """
        Detect the operating system type.

        Returns:
            str: OS type - 'Windows', 'Linux', 'Darwin' (macOS), or 'Unknown'
        """
        try:
            os_type = platform.system()
            self._os_type = os_type
            logger.info(f"Detected OS type: {os_type}")
            return os_type
        except Exception as e:
            logger.error(f"Error detecting OS type: {str(e)}")
            return "Unknown"

    def get_os_version(self) -> Dict[str, str]:
        """
        Get detailed OS version information.

        Returns:
            dict: OS version details including release, version, and distribution
        """
        try:
            version_info = {
                "system": platform.system(),
                "release": platform.release(),
                "version": platform.version(),
                "platform": platform.platform(),
            }

            # Add Linux-specific distribution info
            if platform.system() == "Linux":
                try:
                    # Try to get distribution info (Python 3.8+)
                    if hasattr(platform, 'freedesktop_os_release'):
                        distro_info = platform.freedesktop_os_release()
                        version_info["distribution"] = distro_info.get("NAME", "Unknown")
                        version_info["distribution_version"] = distro_info.get("VERSION", "Unknown")
                        version_info["distribution_id"] = distro_info.get("ID", "Unknown")
                    else:
                        version_info["distribution"] = "Unknown"
                except Exception as e:
                    logger.warning(f"Could not detect Linux distribution: {str(e)}")
                    version_info["distribution"] = "Unknown"

            # Add macOS-specific info
            elif platform.system() == "Darwin":
                try:
                    mac_ver = platform.mac_ver()
                    version_info["macos_version"] = mac_ver[0]
                    version_info["macos_build"] = mac_ver[2]
                except Exception as e:
                    logger.warning(f"Could not detect macOS version details: {str(e)}")

            # Add Windows-specific info
            elif platform.system() == "Windows":
                try:
                    win_ver = platform.win32_ver()
                    version_info["windows_release"] = win_ver[0]
                    version_info["windows_version"] = win_ver[1]
                    version_info["windows_service_pack"] = win_ver[2]
                    version_info["windows_type"] = win_ver[3]
                except Exception as e:
                    logger.warning(f"Could not detect Windows version details: {str(e)}")

            logger.info(f"OS version detected: {version_info.get('platform', 'Unknown')}")
            return version_info

        except Exception as e:
            logger.error(f"Error getting OS version: {str(e)}")
            return {
                "system": "Unknown",
                "release": "Unknown",
                "version": "Unknown",
                "error": str(e)
            }

    def get_architecture(self) -> Dict[str, str]:
        """
        Get system architecture information.

        Returns:
            dict: Architecture details including machine type and processor
        """
        try:
            arch_info = {
                "machine": platform.machine(),
                "processor": platform.processor(),
                "architecture": platform.architecture()[0],
                "linkage": platform.architecture()[1],
            }

            # Normalize architecture names
            machine = arch_info["machine"].lower()
            if machine in ["amd64", "x86_64"]:
                arch_info["normalized"] = "x64"
            elif machine in ["i386", "i686", "x86"]:
                arch_info["normalized"] = "x86"
            elif machine.startswith("arm") or machine.startswith("aarch"):
                arch_info["normalized"] = "ARM"
            else:
                arch_info["normalized"] = machine

            logger.info(f"Architecture detected: {arch_info['machine']}")
            return arch_info

        except Exception as e:
            logger.error(f"Error getting architecture: {str(e)}")
            return {
                "machine": "Unknown",
                "processor": "Unknown",
                "architecture": "Unknown",
                "error": str(e)
            }

    def get_hostname(self) -> str:
        """
        Get the system hostname.

        Returns:
            str: Hostname of the system
        """
        try:
            # Try socket method first (more reliable)
            hostname = socket.gethostname()
            logger.info(f"Hostname detected: {hostname}")
            return hostname
        except Exception as e:
            logger.warning(f"Socket hostname detection failed: {str(e)}")
            try:
                # Fallback to platform method
                hostname = platform.node()
                logger.info(f"Hostname detected (fallback): {hostname}")
                return hostname
            except Exception as e2:
                logger.error(f"Error getting hostname: {str(e2)}")
                return "Unknown"

    def get_current_user(self) -> str:
        """
        Get the current username.

        Returns:
            str: Current username
        """
        try:
            # Try multiple methods to get username
            username = None

            # Method 1: os.getlogin() - most reliable when available
            try:
                username = os.getlogin()
            except Exception:
                pass

            # Method 2: Environment variables
            if not username:
                username = (
                    os.getenv("USER") or
                    os.getenv("USERNAME") or
                    os.getenv("LOGNAME")
                )

            # Method 3: pwd module (Unix-like systems)
            if not username:
                try:
                    import pwd
                    username = pwd.getpwuid(os.getuid()).pw_name
                except Exception:
                    pass

            if username:
                logger.info(f"Current user detected: {username}")
                return username
            else:
                logger.warning("Could not detect current user")
                return "Unknown"

        except Exception as e:
            logger.error(f"Error getting current user: {str(e)}")
            return "Unknown"

    def get_fqdn(self) -> str:
        """
        Get the fully qualified domain name.

        Returns:
            str: Fully qualified domain name
        """
        try:
            fqdn = socket.getfqdn()
            logger.info(f"FQDN detected: {fqdn}")
            return fqdn
        except Exception as e:
            logger.error(f"Error getting FQDN: {str(e)}")
            return "Unknown"

    def get_all_system_info(self) -> Dict:
        """
        Gather all system information in one call.

        Returns:
            dict: Complete system information including OS, architecture, hostname, and user
        """
        try:
            system_info = {
                "os_type": self.detect_os_type(),
                "os_version": self.get_os_version(),
                "architecture": self.get_architecture(),
                "hostname": self.get_hostname(),
                "fqdn": self.get_fqdn(),
                "current_user": self.get_current_user(),
                "python_version": platform.python_version(),
                "python_implementation": platform.python_implementation(),
            }

            # Add privilege detection
            system_info["is_admin"] = self.is_admin()

            logger.info("Complete system information gathered successfully")
            return system_info

        except Exception as e:
            logger.error(f"Error gathering complete system info: {str(e)}")
            return {"error": str(e)}

    def is_admin(self) -> bool:
        """
        Check if the current user has administrator/root privileges.

        Returns:
            bool: True if running with elevated privileges, False otherwise
        """
        try:
            if platform.system() == "Windows":
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            else:
                # Unix-like systems (Linux, macOS)
                return os.geteuid() == 0
        except Exception as e:
            logger.error(f"Error checking admin privileges: {str(e)}")
            return False

    def get_summary(self) -> str:
        """
        Get a human-readable summary of the system.

        Returns:
            str: Formatted system summary
        """
        try:
            info = self.get_all_system_info()
            os_type = info.get("os_type", "Unknown")
            hostname = info.get("hostname", "Unknown")
            user = info.get("current_user", "Unknown")
            arch = info.get("architecture", {}).get("normalized", "Unknown")
            is_admin = "Yes" if info.get("is_admin", False) else "No"

            summary = f"""
System Summary:
  OS: {os_type}
  Hostname: {hostname}
  User: {user}
  Architecture: {arch}
  Administrator: {is_admin}
  Platform: {info.get('os_version', {}).get('platform', 'Unknown')}
            """.strip()

            return summary

        except Exception as e:
            logger.error(f"Error generating system summary: {str(e)}")
            return f"Error generating summary: {str(e)}"


# Convenience functions for direct use
def detect_os() -> str:
    """Convenience function to detect OS type."""
    detector = SystemDetector()
    return detector.detect_os_type()


def get_system_info() -> Dict:
    """Convenience function to get all system information."""
    detector = SystemDetector()
    return detector.get_all_system_info()


def is_windows() -> bool:
    """Check if running on Windows."""
    return platform.system() == "Windows"


def is_linux() -> bool:
    """Check if running on Linux."""
    return platform.system() == "Linux"


def is_macos() -> bool:
    """Check if running on macOS."""
    return platform.system() == "Darwin"


# Example usage and testing
if __name__ == "__main__":
    # Configure logging for standalone testing
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    print("=" * 60)
    print("System Detector - Test Run")
    print("=" * 60)

    detector = SystemDetector()

    # Test individual methods
    print(f"\nOS Type: {detector.detect_os_type()}")
    print(f"\nOS Version: {detector.get_os_version()}")
    print(f"\nArchitecture: {detector.get_architecture()}")
    print(f"\nHostname: {detector.get_hostname()}")
    print(f"\nFQDN: {detector.get_fqdn()}")
    print(f"\nCurrent User: {detector.get_current_user()}")
    print(f"\nIs Admin: {detector.is_admin()}")

    # Test complete info gathering
    print("\n" + "=" * 60)
    print("Complete System Information:")
    print("=" * 60)
    import json
    print(json.dumps(detector.get_all_system_info(), indent=2))

    # Test summary
    print("\n" + "=" * 60)
    print(detector.get_summary())
    print("=" * 60)
