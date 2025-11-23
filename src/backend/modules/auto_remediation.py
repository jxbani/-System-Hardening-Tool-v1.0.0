#!/usr/bin/env python3
"""
Automated Remediation Module
Auto-fix vulnerabilities with rollback capability and scheduling
"""

import logging
import subprocess
import json
import os
import shutil
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from pathlib import Path
from enum import Enum

logger = logging.getLogger(__name__)


class RemediationStatus(Enum):
    """Remediation status enum."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    SUCCESS = "success"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"
    AWAITING_APPROVAL = "awaiting_approval"


class ApprovalStatus(Enum):
    """Approval status enum."""
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"


class AutoRemediation:
    """
    Automated vulnerability remediation with rollback and approval workflows.
    """

    def __init__(self, checkpoint_dir: Optional[str] = None):
        """
        Initialize auto-remediation engine.

        Args:
            checkpoint_dir: Directory for storing checkpoints
        """
        if checkpoint_dir:
            self.checkpoint_dir = Path(checkpoint_dir)
        else:
            self.checkpoint_dir = Path.home() / '.system-hardening' / 'checkpoints'

        self.checkpoint_dir.mkdir(parents=True, exist_ok=True)

        self.remediation_history = []
        self.pending_approvals = []
        self.maintenance_windows = []

        logger.info(f"AutoRemediation initialized (checkpoints: {self.checkpoint_dir})")

    def create_checkpoint(self, description: str) -> Dict[str, Any]:
        """
        Create a system checkpoint before remediation.

        Args:
            description: Checkpoint description

        Returns:
            Checkpoint information
        """
        checkpoint_id = f"checkpoint_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        checkpoint_path = self.checkpoint_dir / checkpoint_id

        try:
            checkpoint_path.mkdir(parents=True, exist_ok=True)

            # Backup critical system files
            files_to_backup = [
                '/etc/ssh/sshd_config',
                '/etc/security/pwquality.conf',
                '/etc/pam.d/common-password',
                '/etc/sysctl.conf',
                '/etc/fstab'
            ]

            backed_up = []
            for file in files_to_backup:
                if os.path.exists(file):
                    backup_path = checkpoint_path / Path(file).name
                    shutil.copy2(file, backup_path)
                    backed_up.append(file)

            # Save system state
            state = {
                'checkpoint_id': checkpoint_id,
                'description': description,
                'timestamp': datetime.now().isoformat(),
                'backed_up_files': backed_up,
                'services': self._get_service_states()
            }

            # Save state to JSON
            with open(checkpoint_path / 'state.json', 'w') as f:
                json.dump(state, f, indent=2)

            logger.info(f"Checkpoint created: {checkpoint_id}")
            return state

        except Exception as e:
            logger.error(f"Failed to create checkpoint: {e}", exc_info=True)
            return {'error': str(e)}

    def rollback(self, checkpoint_id: str) -> Dict[str, Any]:
        """
        Rollback to a previous checkpoint.

        Args:
            checkpoint_id: ID of checkpoint to restore

        Returns:
            Rollback result
        """
        checkpoint_path = self.checkpoint_dir / checkpoint_id

        if not checkpoint_path.exists():
            error = f"Checkpoint not found: {checkpoint_id}"
            logger.error(error)
            return {'status': 'error', 'message': error}

        try:
            # Load checkpoint state
            with open(checkpoint_path / 'state.json', 'r') as f:
                state = json.load(f)

            # Restore backed up files
            restored = []
            for file in state['backed_up_files']:
                backup_file = checkpoint_path / Path(file).name
                if backup_file.exists():
                    shutil.copy2(backup_file, file)
                    restored.append(file)
                    logger.info(f"Restored: {file}")

            # Restore service states
            for service, was_active in state['services'].items():
                try:
                    if was_active:
                        subprocess.run(['systemctl', 'start', service], check=False)
                    else:
                        subprocess.run(['systemctl', 'stop', service], check=False)
                except Exception as e:
                    logger.warning(f"Could not restore service {service}: {e}")

            result = {
                'status': 'success',
                'checkpoint_id': checkpoint_id,
                'restored_files': restored,
                'timestamp': datetime.now().isoformat()
            }

            logger.info(f"Rollback completed: {checkpoint_id}")
            return result

        except Exception as e:
            logger.error(f"Rollback failed: {e}", exc_info=True)
            return {'status': 'error', 'message': str(e)}

    def auto_fix_vulnerability(
        self,
        vulnerability_id: str,
        severity: str,
        requires_approval: bool = True
    ) -> Dict[str, Any]:
        """
        Automatically fix a vulnerability.

        Args:
            vulnerability_id: Vulnerability identifier
            severity: Vulnerability severity (critical, high, medium, low)
            requires_approval: Whether approval is required before fixing

        Returns:
            Remediation result
        """
        logger.info(f"Auto-fixing vulnerability: {vulnerability_id} (severity: {severity})")

        remediation = {
            'id': f"remediation_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            'vulnerability_id': vulnerability_id,
            'severity': severity,
            'status': RemediationStatus.PENDING.value,
            'timestamp': datetime.now().isoformat(),
            'checkpoint_id': None,
            'requires_approval': requires_approval
        }

        # Check if approval is required for critical changes
        if requires_approval and severity in ['critical', 'high']:
            remediation['status'] = RemediationStatus.AWAITING_APPROVAL.value
            self.pending_approvals.append(remediation)
            logger.info(f"Remediation requires approval: {remediation['id']}")
            return remediation

        # Execute remediation
        return self._execute_remediation(remediation)

    def _execute_remediation(self, remediation: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute the remediation action.

        Args:
            remediation: Remediation details

        Returns:
            Execution result
        """
        try:
            # Create checkpoint before making changes
            checkpoint = self.create_checkpoint(
                f"Before fixing {remediation['vulnerability_id']}"
            )
            remediation['checkpoint_id'] = checkpoint.get('checkpoint_id')
            remediation['status'] = RemediationStatus.IN_PROGRESS.value

            # Apply the fix based on vulnerability type
            fix_result = self._apply_fix(remediation['vulnerability_id'])

            if fix_result['success']:
                remediation['status'] = RemediationStatus.SUCCESS.value
                remediation['fix_details'] = fix_result
                logger.info(f"Remediation successful: {remediation['id']}")
            else:
                remediation['status'] = RemediationStatus.FAILED.value
                remediation['error'] = fix_result.get('error')
                logger.error(f"Remediation failed: {remediation['id']}")

                # Auto-rollback on failure
                if remediation['checkpoint_id']:
                    logger.info("Auto-rolling back due to failure...")
                    rollback_result = self.rollback(remediation['checkpoint_id'])
                    remediation['rollback'] = rollback_result
                    if rollback_result['status'] == 'success':
                        remediation['status'] = RemediationStatus.ROLLED_BACK.value

        except Exception as e:
            logger.error(f"Remediation execution error: {e}", exc_info=True)
            remediation['status'] = RemediationStatus.FAILED.value
            remediation['error'] = str(e)

            # Attempt rollback
            if remediation.get('checkpoint_id'):
                self.rollback(remediation['checkpoint_id'])

        self.remediation_history.append(remediation)
        return remediation

    def _apply_fix(self, vulnerability_id: str) -> Dict[str, Any]:
        """
        Apply the actual fix for a vulnerability.

        Args:
            vulnerability_id: Vulnerability identifier

        Returns:
            Fix result
        """
        # Map vulnerability IDs to fix actions
        fix_actions = {
            'weak_ssh_config': self._fix_ssh_config,
            'weak_password_policy': self._fix_password_policy,
            'unpatched_system': self._fix_system_updates,
            'insecure_permissions': self._fix_file_permissions,
            'unnecessary_services': self._fix_disable_services,
            'ip_forwarding_enabled': self._fix_ip_forwarding,
            'missing_firewall': self._fix_firewall
        }

        fix_function = fix_actions.get(vulnerability_id)
        if fix_function:
            return fix_function()
        else:
            return {
                'success': False,
                'error': f'Unknown vulnerability: {vulnerability_id}'
            }

    def _fix_ssh_config(self) -> Dict[str, Any]:
        """Fix SSH configuration."""
        try:
            config_changes = [
                ('PermitRootLogin', 'no'),
                ('PasswordAuthentication', 'no'),
                ('X11Forwarding', 'no'),
                ('MaxAuthTries', '3')
            ]

            # Apply changes
            for key, value in config_changes:
                subprocess.run(
                    f"sed -i 's/^{key}.*/{key} {value}/' /etc/ssh/sshd_config",
                    shell=True,
                    check=True
                )

            # Restart SSH service
            subprocess.run(['systemctl', 'restart', 'sshd'], check=True)

            return {
                'success': True,
                'changes': config_changes,
                'message': 'SSH configuration hardened'
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def _fix_password_policy(self) -> Dict[str, Any]:
        """Fix password policy."""
        try:
            # Configure password quality requirements
            changes = [
                "minlen = 14",
                "dcredit = -1",
                "ucredit = -1",
                "ocredit = -1",
                "lcredit = -1"
            ]

            config_file = '/etc/security/pwquality.conf'
            if os.path.exists(config_file):
                with open(config_file, 'a') as f:
                    f.write('\n# Auto-hardening\n')
                    for change in changes:
                        f.write(f"{change}\n")

                return {
                    'success': True,
                    'changes': changes,
                    'message': 'Password policy strengthened'
                }
            else:
                return {
                    'success': False,
                    'error': 'pwquality.conf not found'
                }
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def _fix_system_updates(self) -> Dict[str, Any]:
        """Apply system updates."""
        try:
            # Update package list
            subprocess.run(['apt-get', 'update'], check=True, capture_output=True)

            # Upgrade packages (non-interactive)
            result = subprocess.run(
                ['apt-get', 'upgrade', '-y'],
                check=True,
                capture_output=True,
                text=True
            )

            return {
                'success': True,
                'message': 'System updates applied',
                'output': result.stdout[:500]
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def _fix_file_permissions(self) -> Dict[str, Any]:
        """Fix insecure file permissions."""
        try:
            fixes = [
                ('chmod 644 /etc/passwd', '/etc/passwd'),
                ('chmod 640 /etc/shadow', '/etc/shadow'),
                ('chmod 644 /etc/group', '/etc/group'),
                ('chmod 640 /etc/gshadow', '/etc/gshadow')
            ]

            applied = []
            for command, file in fixes:
                if os.path.exists(file):
                    subprocess.run(command, shell=True, check=True)
                    applied.append(file)

            return {
                'success': True,
                'fixes': applied,
                'message': f'Fixed permissions on {len(applied)} files'
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def _fix_disable_services(self) -> Dict[str, Any]:
        """Disable unnecessary services."""
        try:
            services_to_disable = ['avahi-daemon', 'cups', 'bluetooth']
            disabled = []

            for service in services_to_disable:
                try:
                    subprocess.run(['systemctl', 'stop', service], check=False)
                    subprocess.run(['systemctl', 'disable', service], check=False)
                    disabled.append(service)
                except:
                    pass

            return {
                'success': True,
                'disabled': disabled,
                'message': f'Disabled {len(disabled)} unnecessary services'
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def _fix_ip_forwarding(self) -> Dict[str, Any]:
        """Disable IP forwarding."""
        try:
            subprocess.run(['sysctl', '-w', 'net.ipv4.ip_forward=0'], check=True)
            subprocess.run(['sysctl', '-w', 'net.ipv6.conf.all.forwarding=0'], check=True)

            # Make permanent
            with open('/etc/sysctl.conf', 'a') as f:
                f.write('\n# Auto-hardening\n')
                f.write('net.ipv4.ip_forward=0\n')
                f.write('net.ipv6.conf.all.forwarding=0\n')

            return {
                'success': True,
                'message': 'IP forwarding disabled'
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def _fix_firewall(self) -> Dict[str, Any]:
        """Enable and configure firewall."""
        try:
            # Try UFW first
            try:
                subprocess.run(['ufw', 'enable'], check=True)
                subprocess.run(['ufw', 'default', 'deny', 'incoming'], check=True)
                subprocess.run(['ufw', 'default', 'allow', 'outgoing'], check=True)
                subprocess.run(['ufw', 'allow', 'ssh'], check=True)

                return {
                    'success': True,
                    'firewall': 'ufw',
                    'message': 'UFW firewall configured'
                }
            except:
                # Fall back to firewalld
                subprocess.run(['systemctl', 'start', 'firewalld'], check=True)
                subprocess.run(['systemctl', 'enable', 'firewalld'], check=True)

                return {
                    'success': True,
                    'firewall': 'firewalld',
                    'message': 'Firewalld enabled'
                }
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def approve_remediation(self, remediation_id: str) -> Dict[str, Any]:
        """
        Approve a pending remediation.

        Args:
            remediation_id: Remediation ID to approve

        Returns:
            Approval result
        """
        for remediation in self.pending_approvals:
            if remediation['id'] == remediation_id:
                self.pending_approvals.remove(remediation)
                remediation['approval_status'] = ApprovalStatus.APPROVED.value
                remediation['approval_timestamp'] = datetime.now().isoformat()

                # Execute the approved remediation
                return self._execute_remediation(remediation)

        return {'error': f'Remediation not found: {remediation_id}'}

    def reject_remediation(self, remediation_id: str, reason: str) -> Dict[str, Any]:
        """
        Reject a pending remediation.

        Args:
            remediation_id: Remediation ID to reject
            reason: Rejection reason

        Returns:
            Rejection result
        """
        for remediation in self.pending_approvals:
            if remediation['id'] == remediation_id:
                self.pending_approvals.remove(remediation)
                remediation['approval_status'] = ApprovalStatus.REJECTED.value
                remediation['rejection_reason'] = reason
                remediation['rejection_timestamp'] = datetime.now().isoformat()
                self.remediation_history.append(remediation)

                logger.info(f"Remediation rejected: {remediation_id}")
                return {'status': 'rejected', 'remediation': remediation}

        return {'error': f'Remediation not found: {remediation_id}'}

    def schedule_maintenance_window(
        self,
        start_time: datetime,
        duration_hours: int,
        description: str
    ) -> Dict[str, Any]:
        """
        Schedule a maintenance window for remediations.

        Args:
            start_time: Window start time
            duration_hours: Window duration in hours
            description: Window description

        Returns:
            Maintenance window details
        """
        end_time = start_time + timedelta(hours=duration_hours)

        window = {
            'id': f"window_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            'start_time': start_time.isoformat(),
            'end_time': end_time.isoformat(),
            'duration_hours': duration_hours,
            'description': description,
            'scheduled_remediations': []
        }

        self.maintenance_windows.append(window)
        logger.info(f"Maintenance window scheduled: {window['id']}")

        return window

    def get_pending_approvals(self) -> List[Dict[str, Any]]:
        """Get all pending approvals."""
        return self.pending_approvals

    def get_remediation_history(self, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """
        Get remediation history.

        Args:
            limit: Maximum number of records to return

        Returns:
            List of remediation records
        """
        history = self.remediation_history
        if limit:
            history = history[-limit:]
        return history

    def _get_service_states(self) -> Dict[str, bool]:
        """Get current state of system services."""
        services = ['ssh', 'sshd', 'firewalld', 'ufw', 'auditd']
        states = {}

        for service in services:
            try:
                result = subprocess.run(
                    ['systemctl', 'is-active', service],
                    capture_output=True,
                    text=True
                )
                states[service] = result.stdout.strip() == 'active'
            except:
                states[service] = False

        return states


# Example usage
if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    print("=" * 70)
    print("Automated Remediation Engine - Test")
    print("=" * 70)

    remediation = AutoRemediation()

    # Create a checkpoint
    print("\n📸 Creating checkpoint...")
    checkpoint = remediation.create_checkpoint("Test checkpoint")
    print(f"   Checkpoint ID: {checkpoint.get('checkpoint_id')}")
    print(f"   Backed up {len(checkpoint.get('backed_up_files', []))} files")

    # Test auto-fix (simulation - won't actually apply)
    print("\n🔧 Testing auto-fix workflow...")
    fix_result = remediation.auto_fix_vulnerability(
        'weak_password_policy',
        'high',
        requires_approval=True
    )
    print(f"   Status: {fix_result['status']}")
    print(f"   Requires approval: {fix_result.get('requires_approval')}")

    # Show pending approvals
    pending = remediation.get_pending_approvals()
    print(f"\n⏳ Pending approvals: {len(pending)}")

    print("\n" + "=" * 70)
    print("✓ Auto-remediation test complete")
    print("=" * 70)
