#!/usr/bin/env python3
"""
Backup Manager Module
Creates checkpoints before system modifications to enable safe rollback.
Supports both Linux and Windows file and configuration backups.
"""

import os
import json
import uuid
import shutil
import platform
import subprocess
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any

logger = logging.getLogger(__name__)


class BackupError(Exception):
    """Base exception for backup operations."""
    pass


class RestoreError(Exception):
    """Base exception for restore operations."""
    pass


class BackupManager:
    """
    Manages system configuration backups and checkpoints.
    Creates snapshots before modifications and provides restore capability.
    """

    # Common Linux files that need backup
    LINUX_CRITICAL_FILES = [
        "/etc/ssh/sshd_config",
        "/etc/login.defs",
        "/etc/pam.d/common-password",
        "/etc/pam.d/common-auth",
        "/etc/security/limits.conf",
        "/etc/sysctl.conf",
        "/etc/fstab",
        "/etc/sudoers",
        "/etc/hosts.allow",
        "/etc/hosts.deny",
        "/etc/sysconfig/iptables",
        "/etc/iptables/rules.v4",
        "/etc/iptables/rules.v6",
        "/etc/selinux/config",
        "/etc/apparmor.d/",
    ]

    # Common Windows registry keys and config files
    WINDOWS_CRITICAL_PATHS = [
        "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies",
        "HKLM\\SYSTEM\\CurrentControlSet\\Services",
        "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa",
        "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows",
    ]

    WINDOWS_CONFIG_FILES = [
        "C:\\Windows\\System32\\drivers\\etc\\hosts",
        "C:\\Windows\\System32\\GroupPolicy",
    ]

    def __init__(self, backup_root: Optional[str] = None):
        """
        Initialize the backup manager.

        Args:
            backup_root: Root directory for storing backups.
                        Defaults to 'backups' in project root.
        """
        if backup_root:
            self.backup_root = Path(backup_root)
        else:
            # Default to backups directory in project root
            project_root = Path(__file__).parent.parent.parent.parent
            self.backup_root = project_root / "backups"

        self.os_type = platform.system()
        self._ensure_backup_directory()
        logger.info(f"BackupManager initialized with root: {self.backup_root}")

    def _ensure_backup_directory(self):
        """Create the backup root directory if it doesn't exist."""
        try:
            self.backup_root.mkdir(parents=True, exist_ok=True)
            logger.debug(f"Backup directory ensured: {self.backup_root}")
        except Exception as e:
            logger.error(f"Failed to create backup directory: {e}")
            raise BackupError(f"Cannot create backup directory: {e}")

    def create_checkpoint(
        self,
        description: str = "",
        files_to_backup: Optional[List[str]] = None,
        registry_keys: Optional[List[str]] = None
    ) -> str:
        """
        Create a new checkpoint with a unique ID.

        Args:
            description: Human-readable description of the checkpoint
            files_to_backup: List of file paths to backup
            registry_keys: List of Windows registry keys to backup (Windows only)

        Returns:
            str: Checkpoint UUID

        Raises:
            BackupError: If checkpoint creation fails
        """
        checkpoint_id = str(uuid.uuid4())
        checkpoint_dir = self.backup_root / f"checkpoint_{checkpoint_id}"

        logger.info(f"Creating checkpoint {checkpoint_id}: {description}")

        try:
            # Create checkpoint directory
            checkpoint_dir.mkdir(parents=True, exist_ok=True)

            # Initialize metadata
            metadata = {
                "checkpoint_id": checkpoint_id,
                "description": description,
                "timestamp": datetime.now().isoformat(),
                "os_type": self.os_type,
                "os_version": platform.version(),
                "hostname": platform.node(),
                "backed_up_files": [],
                "backed_up_registry_keys": [],
                "status": "in_progress"
            }

            # Backup files
            if files_to_backup:
                for file_path in files_to_backup:
                    try:
                        if self._backup_file(file_path, checkpoint_dir):
                            metadata["backed_up_files"].append(file_path)
                            logger.info(f"Backed up file: {file_path}")
                    except Exception as e:
                        logger.warning(f"Failed to backup {file_path}: {e}")

            # Backup Windows registry keys
            if self.os_type == "Windows" and registry_keys:
                for reg_key in registry_keys:
                    try:
                        if self._backup_registry_key(reg_key, checkpoint_dir):
                            metadata["backed_up_registry_keys"].append(reg_key)
                            logger.info(f"Backed up registry key: {reg_key}")
                    except Exception as e:
                        logger.warning(f"Failed to backup registry key {reg_key}: {e}")

            # Mark as completed
            metadata["status"] = "completed"
            metadata["completion_time"] = datetime.now().isoformat()

            # Save metadata
            metadata_path = checkpoint_dir / "metadata.json"
            with open(metadata_path, 'w') as f:
                json.dump(metadata, f, indent=2)

            logger.info(f"Checkpoint {checkpoint_id} created successfully")
            return checkpoint_id

        except Exception as e:
            logger.error(f"Failed to create checkpoint: {e}")
            # Try to clean up partial checkpoint
            if checkpoint_dir.exists():
                try:
                    shutil.rmtree(checkpoint_dir)
                except Exception as cleanup_error:
                    logger.error(f"Failed to cleanup partial checkpoint: {cleanup_error}")
            raise BackupError(f"Checkpoint creation failed: {e}")

    def _backup_file(self, file_path: str, checkpoint_dir: Path) -> bool:
        """
        Backup a single file to the checkpoint directory.

        Args:
            file_path: Path to the file to backup
            checkpoint_dir: Checkpoint directory

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            source = Path(file_path)

            # Check if file exists
            if not source.exists():
                logger.warning(f"File does not exist: {file_path}")
                return False

            # Create relative directory structure in checkpoint
            if source.is_absolute():
                # Remove drive letter on Windows (e.g., C:/ -> /)
                relative_path = str(source).replace(":", "")
                if relative_path.startswith("/") or relative_path.startswith("\\"):
                    relative_path = relative_path[1:]
            else:
                relative_path = str(source)

            destination = checkpoint_dir / "files" / relative_path
            destination.parent.mkdir(parents=True, exist_ok=True)

            # Handle directories
            if source.is_dir():
                shutil.copytree(source, destination, dirs_exist_ok=True)
                logger.debug(f"Backed up directory: {file_path}")
            else:
                shutil.copy2(source, destination)
                logger.debug(f"Backed up file: {file_path}")

            return True

        except PermissionError:
            logger.warning(f"Permission denied backing up {file_path}")
            return False
        except Exception as e:
            logger.error(f"Error backing up {file_path}: {e}")
            return False

    def _backup_registry_key(self, reg_key: str, checkpoint_dir: Path) -> bool:
        """
        Backup a Windows registry key.

        Args:
            reg_key: Registry key path (e.g., HKLM\\SOFTWARE\\...)
            checkpoint_dir: Checkpoint directory

        Returns:
            bool: True if successful, False otherwise
        """
        if self.os_type != "Windows":
            logger.warning("Registry backup only available on Windows")
            return False

        try:
            # Create registry backup directory
            reg_backup_dir = checkpoint_dir / "registry"
            reg_backup_dir.mkdir(parents=True, exist_ok=True)

            # Generate safe filename from registry key
            safe_filename = reg_key.replace("\\", "_").replace(":", "") + ".reg"
            output_file = reg_backup_dir / safe_filename

            # Use reg export command
            cmd = ["reg", "export", reg_key, str(output_file), "/y"]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode == 0:
                logger.debug(f"Backed up registry key: {reg_key}")
                return True
            else:
                logger.warning(f"Failed to export registry key {reg_key}: {result.stderr}")
                return False

        except subprocess.TimeoutExpired:
            logger.error(f"Registry export timeout for {reg_key}")
            return False
        except Exception as e:
            logger.error(f"Error backing up registry key {reg_key}: {e}")
            return False

    def restore_checkpoint(self, checkpoint_id: str, verify: bool = True) -> bool:
        """
        Restore a checkpoint by its ID.

        Args:
            checkpoint_id: UUID of the checkpoint to restore
            verify: Whether to verify checkpoint before restoring

        Returns:
            bool: True if restore successful, False otherwise

        Raises:
            RestoreError: If restore operation fails
        """
        checkpoint_dir = self.backup_root / f"checkpoint_{checkpoint_id}"

        logger.info(f"Restoring checkpoint {checkpoint_id}")

        try:
            # Verify checkpoint exists
            if not checkpoint_dir.exists():
                raise RestoreError(f"Checkpoint {checkpoint_id} not found")

            # Load metadata
            metadata_path = checkpoint_dir / "metadata.json"
            if not metadata_path.exists():
                raise RestoreError(f"Checkpoint metadata not found")

            with open(metadata_path, 'r') as f:
                metadata = json.load(f)

            # Verify checkpoint is complete
            if verify and metadata.get("status") != "completed":
                raise RestoreError(f"Checkpoint is incomplete or corrupted")

            # Restore files
            restored_files = []
            failed_files = []

            for file_path in metadata.get("backed_up_files", []):
                try:
                    if self._restore_file(file_path, checkpoint_dir):
                        restored_files.append(file_path)
                        logger.info(f"Restored file: {file_path}")
                    else:
                        failed_files.append(file_path)
                except Exception as e:
                    logger.error(f"Failed to restore {file_path}: {e}")
                    failed_files.append(file_path)

            # Restore Windows registry keys
            if self.os_type == "Windows":
                for reg_key in metadata.get("backed_up_registry_keys", []):
                    try:
                        if self._restore_registry_key(reg_key, checkpoint_dir):
                            logger.info(f"Restored registry key: {reg_key}")
                    except Exception as e:
                        logger.error(f"Failed to restore registry key {reg_key}: {e}")

            # Log results
            logger.info(
                f"Restore completed: {len(restored_files)} files restored, "
                f"{len(failed_files)} files failed"
            )

            if failed_files:
                logger.warning(f"Failed to restore files: {failed_files}")
                return False

            return True

        except Exception as e:
            logger.error(f"Restore failed: {e}")
            raise RestoreError(f"Failed to restore checkpoint: {e}")

    def _restore_file(self, file_path: str, checkpoint_dir: Path) -> bool:
        """
        Restore a single file from checkpoint.

        Args:
            file_path: Original path where file should be restored
            checkpoint_dir: Checkpoint directory containing backup

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            destination = Path(file_path)

            # Calculate source path in checkpoint
            if destination.is_absolute():
                relative_path = str(destination).replace(":", "")
                if relative_path.startswith("/") or relative_path.startswith("\\"):
                    relative_path = relative_path[1:]
            else:
                relative_path = str(destination)

            source = checkpoint_dir / "files" / relative_path

            if not source.exists():
                logger.warning(f"Backup file not found: {source}")
                return False

            # Create destination directory if needed
            destination.parent.mkdir(parents=True, exist_ok=True)

            # Restore file or directory
            if source.is_dir():
                if destination.exists():
                    shutil.rmtree(destination)
                shutil.copytree(source, destination)
            else:
                shutil.copy2(source, destination)

            logger.debug(f"Restored: {file_path}")
            return True

        except PermissionError:
            logger.error(f"Permission denied restoring {file_path}")
            return False
        except Exception as e:
            logger.error(f"Error restoring {file_path}: {e}")
            return False

    def _restore_registry_key(self, reg_key: str, checkpoint_dir: Path) -> bool:
        """
        Restore a Windows registry key from backup.

        Args:
            reg_key: Registry key path
            checkpoint_dir: Checkpoint directory

        Returns:
            bool: True if successful, False otherwise
        """
        if self.os_type != "Windows":
            logger.warning("Registry restore only available on Windows")
            return False

        try:
            # Find the registry backup file
            safe_filename = reg_key.replace("\\", "_").replace(":", "") + ".reg"
            reg_file = checkpoint_dir / "registry" / safe_filename

            if not reg_file.exists():
                logger.warning(f"Registry backup not found: {reg_file}")
                return False

            # Use reg import command
            cmd = ["reg", "import", str(reg_file)]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode == 0:
                logger.debug(f"Restored registry key: {reg_key}")
                return True
            else:
                logger.error(f"Failed to import registry key: {result.stderr}")
                return False

        except subprocess.TimeoutExpired:
            logger.error(f"Registry import timeout for {reg_key}")
            return False
        except Exception as e:
            logger.error(f"Error restoring registry key {reg_key}: {e}")
            return False

    def list_checkpoints(self, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """
        List all available checkpoints.

        Args:
            limit: Maximum number of checkpoints to return (newest first)

        Returns:
            List of checkpoint information dictionaries
        """
        checkpoints = []

        try:
            # Find all checkpoint directories
            checkpoint_dirs = sorted(
                [d for d in self.backup_root.glob("checkpoint_*") if d.is_dir()],
                key=lambda x: x.stat().st_mtime,
                reverse=True  # Newest first
            )

            if limit:
                checkpoint_dirs = checkpoint_dirs[:limit]

            for checkpoint_dir in checkpoint_dirs:
                metadata_path = checkpoint_dir / "metadata.json"

                if metadata_path.exists():
                    try:
                        with open(metadata_path, 'r') as f:
                            metadata = json.load(f)

                        # Add size information
                        metadata["size_bytes"] = self._get_directory_size(checkpoint_dir)
                        metadata["checkpoint_path"] = str(checkpoint_dir)

                        checkpoints.append(metadata)
                    except Exception as e:
                        logger.warning(f"Failed to read checkpoint metadata {checkpoint_dir}: {e}")
                else:
                    # Checkpoint without metadata (incomplete)
                    checkpoint_id = checkpoint_dir.name.replace("checkpoint_", "")
                    checkpoints.append({
                        "checkpoint_id": checkpoint_id,
                        "status": "incomplete",
                        "checkpoint_path": str(checkpoint_dir),
                        "warning": "Metadata file missing"
                    })

            logger.info(f"Found {len(checkpoints)} checkpoints")
            return checkpoints

        except Exception as e:
            logger.error(f"Failed to list checkpoints: {e}")
            return []

    def get_checkpoint_info(self, checkpoint_id: str) -> Optional[Dict[str, Any]]:
        """
        Get detailed information about a specific checkpoint.

        Args:
            checkpoint_id: UUID of the checkpoint

        Returns:
            Checkpoint metadata dictionary or None if not found
        """
        checkpoint_dir = self.backup_root / f"checkpoint_{checkpoint_id}"
        metadata_path = checkpoint_dir / "metadata.json"

        try:
            if not metadata_path.exists():
                logger.warning(f"Checkpoint {checkpoint_id} not found")
                return None

            with open(metadata_path, 'r') as f:
                metadata = json.load(f)

            # Add additional details
            metadata["size_bytes"] = self._get_directory_size(checkpoint_dir)
            metadata["checkpoint_path"] = str(checkpoint_dir)

            return metadata

        except Exception as e:
            logger.error(f"Failed to get checkpoint info: {e}")
            return None

    def delete_checkpoint(self, checkpoint_id: str) -> bool:
        """
        Delete a checkpoint and all its files.

        Args:
            checkpoint_id: UUID of the checkpoint to delete

        Returns:
            bool: True if successful, False otherwise
        """
        checkpoint_dir = self.backup_root / f"checkpoint_{checkpoint_id}"

        try:
            if not checkpoint_dir.exists():
                logger.warning(f"Checkpoint {checkpoint_id} not found")
                return False

            shutil.rmtree(checkpoint_dir)
            logger.info(f"Deleted checkpoint {checkpoint_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to delete checkpoint {checkpoint_id}: {e}")
            return False

    def _get_directory_size(self, directory: Path) -> int:
        """
        Calculate total size of a directory.

        Args:
            directory: Directory path

        Returns:
            Total size in bytes
        """
        total_size = 0
        try:
            for item in directory.rglob("*"):
                if item.is_file():
                    total_size += item.stat().st_size
        except Exception as e:
            logger.warning(f"Error calculating directory size: {e}")
        return total_size

    def cleanup_old_checkpoints(self, keep_count: int = 10) -> int:
        """
        Remove old checkpoints, keeping only the most recent ones.

        Args:
            keep_count: Number of recent checkpoints to keep

        Returns:
            Number of checkpoints deleted
        """
        try:
            checkpoints = self.list_checkpoints()

            if len(checkpoints) <= keep_count:
                logger.info(f"No cleanup needed. Current count: {len(checkpoints)}")
                return 0

            # Sort by timestamp (oldest first for deletion)
            checkpoints.sort(key=lambda x: x.get("timestamp", ""), reverse=False)

            to_delete = checkpoints[:-keep_count]
            deleted_count = 0

            for checkpoint in to_delete:
                checkpoint_id = checkpoint.get("checkpoint_id")
                if checkpoint_id and self.delete_checkpoint(checkpoint_id):
                    deleted_count += 1

            logger.info(f"Cleaned up {deleted_count} old checkpoints")
            return deleted_count

        except Exception as e:
            logger.error(f"Failed to cleanup old checkpoints: {e}")
            return 0


# Convenience functions
def create_backup(
    description: str = "",
    files: Optional[List[str]] = None,
    backup_root: Optional[str] = None
) -> str:
    """
    Convenience function to create a backup checkpoint.

    Args:
        description: Description of the checkpoint
        files: List of files to backup
        backup_root: Optional backup root directory

    Returns:
        Checkpoint ID
    """
    manager = BackupManager(backup_root)
    return manager.create_checkpoint(description, files)


def restore_backup(checkpoint_id: str, backup_root: Optional[str] = None) -> bool:
    """
    Convenience function to restore a checkpoint.

    Args:
        checkpoint_id: UUID of checkpoint to restore
        backup_root: Optional backup root directory

    Returns:
        True if successful
    """
    manager = BackupManager(backup_root)
    return manager.restore_checkpoint(checkpoint_id)


def list_backups(backup_root: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Convenience function to list all checkpoints.

    Args:
        backup_root: Optional backup root directory

    Returns:
        List of checkpoint information
    """
    manager = BackupManager(backup_root)
    return manager.list_checkpoints()


# Example usage and testing
if __name__ == "__main__":
    # Configure logging for standalone testing
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    print("=" * 70)
    print("Backup Manager - Test Run")
    print("=" * 70)

    # Initialize backup manager
    manager = BackupManager()

    # Test checkpoint creation
    print("\n1. Creating test checkpoint...")
    test_files = []

    # Add test files based on OS
    if platform.system() == "Linux":
        # Use common Linux files that likely exist
        test_files = ["/etc/hostname", "/etc/hosts"]
    elif platform.system() == "Windows":
        test_files = ["C:\\Windows\\System32\\drivers\\etc\\hosts"]

    checkpoint_id = manager.create_checkpoint(
        description="Test checkpoint for backup manager",
        files_to_backup=test_files
    )
    print(f"Created checkpoint: {checkpoint_id}")

    # Test listing checkpoints
    print("\n2. Listing all checkpoints...")
    checkpoints = manager.list_checkpoints()
    for cp in checkpoints:
        print(f"\nCheckpoint ID: {cp.get('checkpoint_id')}")
        print(f"  Description: {cp.get('description')}")
        print(f"  Timestamp: {cp.get('timestamp')}")
        print(f"  Status: {cp.get('status')}")
        print(f"  Files backed up: {len(cp.get('backed_up_files', []))}")
        size_mb = cp.get('size_bytes', 0) / (1024 * 1024)
        print(f"  Size: {size_mb:.2f} MB")

    # Test getting checkpoint info
    print(f"\n3. Getting info for checkpoint {checkpoint_id}...")
    info = manager.get_checkpoint_info(checkpoint_id)
    if info:
        print(f"Backed up files:")
        for file_path in info.get('backed_up_files', []):
            print(f"  - {file_path}")

    print("\n" + "=" * 70)
    print("Test completed successfully!")
    print("=" * 70)
