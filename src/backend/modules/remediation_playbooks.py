#!/usr/bin/env python3
"""
Remediation Playbook System for System Hardening Tool
Provides guided, step-by-step remediation workflows with validation
"""

import logging
import json
from typing import Dict, List, Any, Optional
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)


class PlaybookStatus(Enum):
    """Playbook execution status"""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    VALIDATION_FAILED = "validation_failed"
    ROLLED_BACK = "rolled_back"


class StepType(Enum):
    """Types of remediation steps"""
    COMMAND = "command"
    FILE_EDIT = "file_edit"
    SERVICE = "service"
    PACKAGE = "package"
    PERMISSION = "permission"
    VALIDATION = "validation"
    MANUAL = "manual"


class RemediationPlaybookEngine:
    """
    Engine for executing remediation playbooks with guided workflows.

    Playbooks define step-by-step procedures for fixing vulnerabilities,
    including pre-flight checks, execution steps, and post-fix validation.
    """

    def __init__(self):
        """Initialize playbook engine."""
        self.playbooks = self._load_default_playbooks()
        logger.info("RemediationPlaybookEngine initialized with %d playbooks", len(self.playbooks))

    def _load_default_playbooks(self) -> Dict[str, Dict]:
        """Load default remediation playbooks."""
        return {
            "ssh_disable_password_auth": {
                "id": "ssh_disable_password_auth",
                "name": "Disable SSH Password Authentication",
                "description": "Disables password-based SSH authentication and enforces key-based authentication",
                "category": "Network Security",
                "severity": "Critical",
                "estimated_time": "5 minutes",
                "risk_level": "Low",
                "requires_restart": True,
                "affected_services": ["ssh", "sshd"],
                "prerequisites": [
                    {
                        "type": "check",
                        "description": "Verify SSH keys are configured",
                        "command": "test -f ~/.ssh/authorized_keys"
                    },
                    {
                        "type": "backup",
                        "description": "Backup SSH configuration",
                        "files": ["/etc/ssh/sshd_config"]
                    }
                ],
                "steps": [
                    {
                        "id": 1,
                        "type": StepType.FILE_EDIT.value,
                        "description": "Update SSH configuration to disable password authentication",
                        "file": "/etc/ssh/sshd_config",
                        "changes": [
                            {"find": "#PasswordAuthentication yes", "replace": "PasswordAuthentication no"},
                            {"find": "PasswordAuthentication yes", "replace": "PasswordAuthentication no"}
                        ],
                        "sudo_required": True
                    },
                    {
                        "id": 2,
                        "type": StepType.SERVICE.value,
                        "description": "Restart SSH service to apply changes",
                        "action": "restart",
                        "service": "sshd",
                        "sudo_required": True
                    }
                ],
                "validation": [
                    {
                        "type": "command",
                        "description": "Verify SSH configuration",
                        "command": "sshd -T | grep -i passwordauthentication",
                        "expected_output": "passwordauthentication no"
                    },
                    {
                        "type": "port_check",
                        "description": "Verify SSH service is running",
                        "port": 22
                    }
                ],
                "rollback": [
                    {
                        "description": "Restore SSH configuration from backup",
                        "action": "restore_backup",
                        "files": ["/etc/ssh/sshd_config"]
                    }
                ],
                "success_criteria": [
                    "SSH service is running",
                    "Password authentication is disabled",
                    "Key-based authentication is enforced"
                ]
            },
            "update_system_packages": {
                "id": "update_system_packages",
                "name": "Update System Packages",
                "description": "Updates all system packages to patch known vulnerabilities",
                "category": "System Updates",
                "severity": "Medium",
                "estimated_time": "10-30 minutes",
                "risk_level": "Medium",
                "requires_restart": False,
                "affected_services": [],
                "prerequisites": [
                    {
                        "type": "check",
                        "description": "Check available disk space",
                        "command": "df -h / | awk 'NR==2 {print $5}' | sed 's/%//'"
                    }
                ],
                "steps": [
                    {
                        "id": 1,
                        "type": StepType.COMMAND.value,
                        "description": "Update package lists",
                        "command": "apt-get update",
                        "sudo_required": True,
                        "timeout": 300
                    },
                    {
                        "id": 2,
                        "type": StepType.PACKAGE.value,
                        "description": "Upgrade all packages",
                        "command": "apt-get upgrade -y",
                        "sudo_required": True,
                        "timeout": 1800
                    }
                ],
                "validation": [
                    {
                        "type": "command",
                        "description": "Check for remaining updates",
                        "command": "apt list --upgradable 2>/dev/null | wc -l",
                        "expected_output": "1"  # Only the header line
                    }
                ],
                "rollback": [],
                "success_criteria": [
                    "All available updates installed",
                    "No pending security updates"
                ]
            },
            "fix_file_permissions": {
                "id": "fix_file_permissions",
                "name": "Fix Insecure File Permissions",
                "description": "Corrects overly permissive file permissions on sensitive files",
                "category": "File System",
                "severity": "Warning",
                "estimated_time": "2 minutes",
                "risk_level": "Low",
                "requires_restart": False,
                "affected_services": [],
                "prerequisites": [],
                "steps": [
                    {
                        "id": 1,
                        "type": StepType.PERMISSION.value,
                        "description": "Fix /tmp directory permissions",
                        "path": "/tmp",
                        "permissions": "1777",
                        "sudo_required": True
                    },
                    {
                        "id": 2,
                        "type": StepType.PERMISSION.value,
                        "description": "Fix /etc/shadow permissions",
                        "path": "/etc/shadow",
                        "permissions": "640",
                        "sudo_required": True
                    }
                ],
                "validation": [
                    {
                        "type": "command",
                        "description": "Verify /tmp permissions",
                        "command": "stat -c '%a' /tmp",
                        "expected_output": "1777"
                    },
                    {
                        "type": "command",
                        "description": "Verify /etc/shadow permissions",
                        "command": "stat -c '%a' /etc/shadow",
                        "expected_output": "640"
                    }
                ],
                "rollback": [],
                "success_criteria": [
                    "All sensitive file permissions corrected",
                    "No world-writable sensitive files"
                ]
            },
            "enable_firewall": {
                "id": "enable_firewall",
                "name": "Enable and Configure Firewall",
                "description": "Enables UFW firewall with secure default rules",
                "category": "Network Security",
                "severity": "High",
                "estimated_time": "3 minutes",
                "risk_level": "Low",
                "requires_restart": False,
                "affected_services": ["ufw"],
                "prerequisites": [
                    {
                        "type": "check",
                        "description": "Check if UFW is installed",
                        "command": "which ufw"
                    }
                ],
                "steps": [
                    {
                        "id": 1,
                        "type": StepType.COMMAND.value,
                        "description": "Set default deny incoming policy",
                        "command": "ufw default deny incoming",
                        "sudo_required": True
                    },
                    {
                        "id": 2,
                        "type": StepType.COMMAND.value,
                        "description": "Set default allow outgoing policy",
                        "command": "ufw default allow outgoing",
                        "sudo_required": True
                    },
                    {
                        "id": 3,
                        "type": StepType.COMMAND.value,
                        "description": "Allow SSH connections",
                        "command": "ufw allow 22/tcp",
                        "sudo_required": True
                    },
                    {
                        "id": 4,
                        "type": StepType.COMMAND.value,
                        "description": "Enable firewall",
                        "command": "ufw --force enable",
                        "sudo_required": True
                    }
                ],
                "validation": [
                    {
                        "type": "command",
                        "description": "Verify firewall is active",
                        "command": "ufw status | grep -i 'status: active'",
                        "expected_output": "Status: active"
                    }
                ],
                "rollback": [
                    {
                        "description": "Disable firewall",
                        "action": "command",
                        "command": "ufw disable"
                    }
                ],
                "success_criteria": [
                    "Firewall is active",
                    "Default deny incoming policy set",
                    "SSH access maintained"
                ]
            }
        }

    def get_playbook(self, playbook_id: str) -> Optional[Dict]:
        """Get a specific playbook by ID."""
        return self.playbooks.get(playbook_id)

    def list_playbooks(self, category: Optional[str] = None) -> List[Dict]:
        """List all available playbooks, optionally filtered by category."""
        playbooks = list(self.playbooks.values())

        if category:
            playbooks = [p for p in playbooks if p.get('category', '').lower() == category.lower()]

        return playbooks

    def get_playbook_for_vulnerability(self, vulnerability: Dict) -> Optional[Dict]:
        """Find the best playbook for a given vulnerability."""
        category = vulnerability.get('category', '').lower()
        description = vulnerability.get('description', '').lower()

        # Map vulnerability patterns to playbooks
        if 'ssh' in description and 'password' in description:
            return self.get_playbook('ssh_disable_password_auth')
        elif 'update' in description or 'package' in description:
            return self.get_playbook('update_system_packages')
        elif 'permission' in description or 'writable' in description:
            return self.get_playbook('fix_file_permissions')
        elif 'firewall' in description:
            return self.get_playbook('enable_firewall')

        return None

    def estimate_remediation_effort(self, vulnerabilities: List[Dict]) -> Dict:
        """Estimate total time and effort for remediating multiple vulnerabilities."""
        total_time_minutes = 0
        playbook_count = 0
        requires_restart = False
        risk_levels = {'Low': 0, 'Medium': 0, 'High': 0}

        for vuln in vulnerabilities:
            playbook = self.get_playbook_for_vulnerability(vuln)
            if playbook:
                # Parse estimated time (e.g., "5 minutes" or "10-30 minutes")
                time_str = playbook.get('estimated_time', '0 minutes')
                if '-' in time_str:
                    # Take the maximum time for estimation
                    max_time = int(time_str.split('-')[1].split()[0])
                    total_time_minutes += max_time
                else:
                    time = int(time_str.split()[0])
                    total_time_minutes += time

                playbook_count += 1
                if playbook.get('requires_restart'):
                    requires_restart = True

                risk_level = playbook.get('risk_level', 'Low')
                if risk_level in risk_levels:
                    risk_levels[risk_level] += 1

        return {
            'total_vulnerabilities': len(vulnerabilities),
            'remediable_count': playbook_count,
            'estimated_time_minutes': total_time_minutes,
            'estimated_time_human': f"{total_time_minutes // 60}h {total_time_minutes % 60}m" if total_time_minutes >= 60 else f"{total_time_minutes}m",
            'requires_restart': requires_restart,
            'risk_distribution': risk_levels
        }

    def create_remediation_plan(self, vulnerabilities: List[Dict]) -> Dict:
        """Create a prioritized remediation plan for multiple vulnerabilities."""
        plan = {
            'created_at': datetime.now().isoformat(),
            'total_vulnerabilities': len(vulnerabilities),
            'phases': []
        }

        # Group vulnerabilities by risk score
        critical = [v for v in vulnerabilities if v.get('risk_score', 0) >= 9.0]
        high = [v for v in vulnerabilities if 7.0 <= v.get('risk_score', 0) < 9.0]
        medium = [v for v in vulnerabilities if 4.0 <= v.get('risk_score', 0) < 7.0]
        low = [v for v in vulnerabilities if v.get('risk_score', 0) < 4.0]

        # Create phased plan
        if critical:
            plan['phases'].append({
                'phase': 1,
                'name': 'Critical Issues',
                'priority': 'immediate',
                'vulnerabilities': critical,
                'playbooks': [self.get_playbook_for_vulnerability(v) for v in critical if self.get_playbook_for_vulnerability(v)]
            })

        if high:
            plan['phases'].append({
                'phase': 2,
                'name': 'High Priority',
                'priority': 'urgent',
                'vulnerabilities': high,
                'playbooks': [self.get_playbook_for_vulnerability(v) for v in high if self.get_playbook_for_vulnerability(v)]
            })

        if medium:
            plan['phases'].append({
                'phase': 3,
                'name': 'Medium Priority',
                'priority': 'scheduled',
                'vulnerabilities': medium,
                'playbooks': [self.get_playbook_for_vulnerability(v) for v in medium if self.get_playbook_for_vulnerability(v)]
            })

        if low:
            plan['phases'].append({
                'phase': 4,
                'name': 'Low Priority',
                'priority': 'as_resources_permit',
                'vulnerabilities': low,
                'playbooks': [self.get_playbook_for_vulnerability(v) for v in low if self.get_playbook_for_vulnerability(v)]
            })

        # Add effort estimation
        plan['effort_estimate'] = self.estimate_remediation_effort(vulnerabilities)

        return plan

    def generate_execution_report(self, playbook_id: str, execution_result: Dict) -> Dict:
        """Generate a detailed execution report for a playbook."""
        playbook = self.get_playbook(playbook_id)
        if not playbook:
            return {}

        report = {
            'playbook_id': playbook_id,
            'playbook_name': playbook['name'],
            'execution_time': execution_result.get('execution_time'),
            'status': execution_result.get('status'),
            'steps_completed': execution_result.get('steps_completed', 0),
            'total_steps': len(playbook['steps']),
            'validation_passed': execution_result.get('validation_passed', False),
            'errors': execution_result.get('errors', []),
            'warnings': execution_result.get('warnings', []),
            'recommendations': []
        }

        # Add recommendations based on results
        if report['status'] == PlaybookStatus.COMPLETED.value:
            report['recommendations'].append("Consider running a full security scan to verify the fix")
            if playbook.get('requires_restart'):
                report['recommendations'].append("System restart recommended to fully apply changes")
        elif report['status'] == PlaybookStatus.VALIDATION_FAILED.value:
            report['recommendations'].append("Review validation errors and retry remediation")
            report['recommendations'].append("Consider manual remediation if automation continues to fail")

        return report
