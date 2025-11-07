#!/usr/bin/env python3
"""
Hardening Engine Module
Applies security hardening rules with backup, validation, and rollback capabilities.
"""

import os
import re
import platform
import subprocess
import logging
from enum import Enum
from typing import Dict, List, Optional, Any, Callable
from datetime import datetime
from pathlib import Path

try:
    from .backup_manager import BackupManager, BackupError, RestoreError
    from .config_loader import ConfigurationRule
except ImportError:
    # Handle standalone execution
    import sys
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from backup_manager import BackupManager, BackupError, RestoreError
    from config_loader import ConfigurationRule

logger = logging.getLogger(__name__)


class RuleStatus(Enum):
    """Status of rule application."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"
    ROLLED_BACK = "rolled_back"


class ExecutionMode(Enum):
    """Execution mode for the hardening engine."""
    APPLY = "apply"  # Apply changes
    DRY_RUN = "dry_run"  # Simulate without making changes
    VALIDATE_ONLY = "validate_only"  # Only validate current state


class RuleResult:
    """Represents the result of applying a single rule."""

    def __init__(self, rule: ConfigurationRule):
        """
        Initialize a rule result.

        Args:
            rule: The configuration rule being applied
        """
        self.rule_id = rule.id
        self.rule_name = rule.name
        self.rule_severity = rule.severity
        self.status = RuleStatus.PENDING
        self.start_time: Optional[str] = None
        self.end_time: Optional[str] = None
        self.duration_seconds: Optional[float] = None
        self.error_message: Optional[str] = None
        self.warning_messages: List[str] = []
        self.changes_made: List[str] = []
        self.validation_result: Optional[bool] = None
        self.validation_message: Optional[str] = None
        self.before_value: Optional[str] = None
        self.after_value: Optional[str] = None

    def start(self):
        """Mark the rule application as started."""
        self.status = RuleStatus.IN_PROGRESS
        self.start_time = datetime.now().isoformat()

    def succeed(self, changes: Optional[List[str]] = None):
        """Mark the rule application as successful."""
        self.status = RuleStatus.SUCCESS
        self.end_time = datetime.now().isoformat()
        if changes:
            self.changes_made = changes
        self._calculate_duration()

    def fail(self, error_message: str):
        """Mark the rule application as failed."""
        self.status = RuleStatus.FAILED
        self.error_message = error_message
        self.end_time = datetime.now().isoformat()
        self._calculate_duration()

    def skip(self, reason: str):
        """Mark the rule as skipped."""
        self.status = RuleStatus.SKIPPED
        self.error_message = reason
        self.end_time = datetime.now().isoformat()
        self._calculate_duration()

    def rollback(self):
        """Mark the rule as rolled back."""
        self.status = RuleStatus.ROLLED_BACK
        self.end_time = datetime.now().isoformat()

    def add_warning(self, message: str):
        """Add a warning message."""
        self.warning_messages.append(message)

    def _calculate_duration(self):
        """Calculate the duration of rule application."""
        if self.start_time and self.end_time:
            start = datetime.fromisoformat(self.start_time)
            end = datetime.fromisoformat(self.end_time)
            self.duration_seconds = (end - start).total_seconds()

    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary format."""
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "rule_severity": self.rule_severity,
            "status": self.status.value,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration_seconds": self.duration_seconds,
            "error_message": self.error_message,
            "warning_messages": self.warning_messages,
            "changes_made": self.changes_made,
            "validation_result": self.validation_result,
            "validation_message": self.validation_message,
            "before_value": self.before_value,
            "after_value": self.after_value
        }


class HardeningSession:
    """Represents a complete hardening session with multiple rules."""

    def __init__(self, session_id: str, mode: ExecutionMode):
        """
        Initialize a hardening session.

        Args:
            session_id: Unique session identifier
            mode: Execution mode
        """
        self.session_id = session_id
        self.mode = mode
        self.start_time = datetime.now().isoformat()
        self.end_time: Optional[str] = None
        self.checkpoint_id: Optional[str] = None
        self.results: List[RuleResult] = []
        self.rollback_performed = False
        self.total_rules = 0
        self.successful_rules = 0
        self.failed_rules = 0
        self.skipped_rules = 0

    def add_result(self, result: RuleResult):
        """Add a rule result to the session."""
        self.results.append(result)
        self.total_rules = len(self.results)

        # Update counters
        if result.status == RuleStatus.SUCCESS:
            self.successful_rules += 1
        elif result.status == RuleStatus.FAILED:
            self.failed_rules += 1
        elif result.status == RuleStatus.SKIPPED:
            self.skipped_rules += 1

    def complete(self):
        """Mark the session as complete."""
        self.end_time = datetime.now().isoformat()

    def to_dict(self) -> Dict[str, Any]:
        """Convert session to dictionary format."""
        return {
            "session_id": self.session_id,
            "mode": self.mode.value,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "checkpoint_id": self.checkpoint_id,
            "rollback_performed": self.rollback_performed,
            "total_rules": self.total_rules,
            "successful_rules": self.successful_rules,
            "failed_rules": self.failed_rules,
            "skipped_rules": self.skipped_rules,
            "results": [r.to_dict() for r in self.results]
        }


class HardeningEngine:
    """
    Main hardening engine that applies security rules with backup and rollback.
    """

    def __init__(
        self,
        backup_manager: Optional[BackupManager] = None,
        auto_rollback: bool = True,
        stop_on_critical_error: bool = True
    ):
        """
        Initialize the hardening engine.

        Args:
            backup_manager: BackupManager instance (creates new if None)
            auto_rollback: Whether to automatically rollback on critical errors
            stop_on_critical_error: Whether to stop execution on critical errors
        """
        self.backup_manager = backup_manager or BackupManager()
        self.auto_rollback = auto_rollback
        self.stop_on_critical_error = stop_on_critical_error
        self.os_type = platform.system()

        logger.info(f"HardeningEngine initialized for {self.os_type}")

    def apply_rules(
        self,
        rules: List[ConfigurationRule],
        mode: ExecutionMode = ExecutionMode.APPLY,
        checkpoint_description: str = "Hardening session"
    ) -> HardeningSession:
        """
        Apply a list of hardening rules.

        Args:
            rules: List of ConfigurationRule objects to apply
            mode: Execution mode (apply, dry_run, validate_only)
            checkpoint_description: Description for the backup checkpoint

        Returns:
            HardeningSession with detailed results
        """
        # Create session
        session_id = f"hardening_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        session = HardeningSession(session_id, mode)

        logger.info(f"Starting hardening session {session_id} in {mode.value} mode")
        logger.info(f"Total rules to process: {len(rules)}")

        try:
            # Create checkpoint (unless in dry run or validate only mode)
            if mode == ExecutionMode.APPLY:
                session.checkpoint_id = self._create_checkpoint(
                    rules,
                    checkpoint_description
                )
                logger.info(f"Created checkpoint: {session.checkpoint_id}")

            # Apply each rule sequentially
            for i, rule in enumerate(rules, 1):
                logger.info(f"Processing rule {i}/{len(rules)}: {rule.name} (ID: {rule.id})")

                result = self._apply_single_rule(rule, mode)
                session.add_result(result)

                # Log result
                if result.status == RuleStatus.SUCCESS:
                    logger.info(f"✓ Rule {rule.id} applied successfully")
                elif result.status == RuleStatus.FAILED:
                    logger.error(f"✗ Rule {rule.id} failed: {result.error_message}")

                    # Handle critical errors
                    if rule.severity == "critical" and self.stop_on_critical_error:
                        logger.error("Critical rule failed - stopping execution")

                        if mode == ExecutionMode.APPLY and self.auto_rollback:
                            logger.warning("Initiating automatic rollback")
                            self._perform_rollback(session)

                        break
                elif result.status == RuleStatus.SKIPPED:
                    logger.warning(f"⊘ Rule {rule.id} skipped: {result.error_message}")

            # Complete session
            session.complete()
            logger.info(
                f"Session completed: {session.successful_rules} successful, "
                f"{session.failed_rules} failed, {session.skipped_rules} skipped"
            )

        except Exception as e:
            logger.error(f"Session failed with exception: {e}", exc_info=True)
            session.complete()

            # Attempt rollback on unexpected error
            if mode == ExecutionMode.APPLY and self.auto_rollback and session.checkpoint_id:
                logger.warning("Unexpected error - attempting rollback")
                self._perform_rollback(session)

        return session

    def _create_checkpoint(
        self,
        rules: List[ConfigurationRule],
        description: str
    ) -> str:
        """
        Create a backup checkpoint for the rules to be applied.

        Args:
            rules: List of rules
            description: Checkpoint description

        Returns:
            Checkpoint ID

        Raises:
            BackupError: If checkpoint creation fails
        """
        # Collect all files that will be modified
        files_to_backup = set()
        registry_keys = set()

        for rule in rules:
            if rule.file:
                files_to_backup.add(rule.file)

            # Extract registry keys for Windows rules
            if self.os_type == "Windows" and rule.file.startswith("HKLM\\"):
                registry_keys.add(rule.file)

        logger.info(f"Creating checkpoint for {len(files_to_backup)} files")

        try:
            checkpoint_id = self.backup_manager.create_checkpoint(
                description=description,
                files_to_backup=list(files_to_backup),
                registry_keys=list(registry_keys) if registry_keys else None
            )
            return checkpoint_id

        except BackupError as e:
            logger.error(f"Failed to create checkpoint: {e}")
            raise

    def _apply_single_rule(
        self,
        rule: ConfigurationRule,
        mode: ExecutionMode
    ) -> RuleResult:
        """
        Apply a single hardening rule.

        Args:
            rule: Configuration rule to apply
            mode: Execution mode

        Returns:
            RuleResult with execution details
        """
        result = RuleResult(rule)
        result.start()

        try:
            # Check if file exists
            if rule.file and not self._file_exists(rule.file):
                result.skip(f"Target file does not exist: {rule.file}")
                return result

            # Read current value
            current_value = self._read_current_value(rule)
            result.before_value = current_value

            # Validate only mode
            if mode == ExecutionMode.VALIDATE_ONLY:
                is_valid = self._validate_value(current_value, rule)
                result.validation_result = is_valid
                result.validation_message = (
                    "Configuration matches expected value"
                    if is_valid
                    else f"Expected '{rule.expected_value}', found '{current_value}'"
                )
                result.succeed()
                return result

            # Dry run mode
            if mode == ExecutionMode.DRY_RUN:
                changes = [
                    f"Would set {rule.parameter} = {rule.expected_value} in {rule.file}"
                ]
                result.succeed(changes)
                result.after_value = rule.expected_value
                return result

            # Apply mode - actually make the change
            if mode == ExecutionMode.APPLY:
                success = self._apply_configuration(rule)

                if success:
                    # Verify the change
                    new_value = self._read_current_value(rule)
                    result.after_value = new_value

                    is_valid = self._validate_value(new_value, rule)
                    result.validation_result = is_valid

                    if is_valid:
                        changes = [
                            f"Set {rule.parameter} = {rule.expected_value} in {rule.file}"
                        ]
                        result.succeed(changes)
                        result.validation_message = "Change validated successfully"
                    else:
                        result.fail(
                            f"Validation failed after applying rule. "
                            f"Expected '{rule.expected_value}', got '{new_value}'"
                        )
                else:
                    result.fail("Failed to apply configuration change")

        except Exception as e:
            logger.error(f"Error applying rule {rule.id}: {e}", exc_info=True)
            result.fail(str(e))

        return result

    def _file_exists(self, file_path: str) -> bool:
        """Check if a file exists."""
        try:
            return Path(file_path).exists()
        except Exception:
            return False

    def _read_current_value(self, rule: ConfigurationRule) -> Optional[str]:
        """
        Read the current value of a configuration parameter.

        Args:
            rule: Configuration rule

        Returns:
            Current value as string or None
        """
        try:
            if self.os_type == "Windows" and rule.file.startswith("HKLM\\"):
                return self._read_registry_value(rule.file, rule.parameter)
            else:
                return self._read_config_file_value(rule.file, rule.parameter)
        except Exception as e:
            logger.warning(f"Failed to read current value for {rule.parameter}: {e}")
            return None

    def _read_config_file_value(self, file_path: str, parameter: str) -> Optional[str]:
        """
        Read a parameter value from a configuration file.

        Args:
            file_path: Path to configuration file
            parameter: Parameter name

        Returns:
            Parameter value or None
        """
        try:
            with open(file_path, 'r') as f:
                content = f.read()

            # Try different patterns to find the parameter
            patterns = [
                rf'^\s*{re.escape(parameter)}\s+(.+?)$',  # Parameter value
                rf'^\s*{re.escape(parameter)}\s*=\s*(.+?)$',  # Parameter = value
                rf'^\s*{re.escape(parameter)}\s*:\s*(.+?)$',  # Parameter : value
            ]

            for pattern in patterns:
                match = re.search(pattern, content, re.MULTILINE | re.IGNORECASE)
                if match:
                    value = match.group(1).strip()
                    # Remove comments
                    value = re.sub(r'\s*#.*$', '', value)
                    value = re.sub(r'\s*;.*$', '', value)
                    return value.strip()

            return None

        except Exception as e:
            logger.error(f"Error reading file {file_path}: {e}")
            return None

    def _read_registry_value(self, key_path: str, value_name: str) -> Optional[str]:
        """
        Read a Windows registry value.

        Args:
            key_path: Registry key path
            value_name: Value name

        Returns:
            Registry value or None
        """
        if self.os_type != "Windows":
            return None

        try:
            cmd = ["reg", "query", key_path, "/v", value_name]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode == 0:
                # Parse reg query output
                match = re.search(rf'{value_name}\s+\w+\s+(.+)$', result.stdout, re.MULTILINE)
                if match:
                    return match.group(1).strip()

            return None

        except Exception as e:
            logger.error(f"Error reading registry {key_path}\\{value_name}: {e}")
            return None

    def _validate_value(self, actual_value: Optional[str], rule: ConfigurationRule) -> bool:
        """
        Validate if actual value matches expected value.

        Args:
            actual_value: Actual value
            rule: Configuration rule with expected value

        Returns:
            True if valid, False otherwise
        """
        if actual_value is None:
            return False

        expected = str(rule.expected_value).strip().lower()
        actual = str(actual_value).strip().lower()
        comparison = rule.comparison

        try:
            # Try numeric comparison
            if comparison in ['<', '>', '<=', '>=']:
                actual_num = float(actual)
                expected_num = float(expected)

                if comparison == '<':
                    return actual_num < expected_num
                elif comparison == '>':
                    return actual_num > expected_num
                elif comparison == '<=':
                    return actual_num <= expected_num
                elif comparison == '>=':
                    return actual_num >= expected_num

        except ValueError:
            # Not numeric, fall back to string comparison
            pass

        # String comparison
        if comparison == '==':
            return actual == expected
        elif comparison == '!=':
            return actual != expected
        else:
            # Default to equality
            return actual == expected

    def _apply_configuration(self, rule: ConfigurationRule) -> bool:
        """
        Apply a configuration change.

        Args:
            rule: Configuration rule

        Returns:
            True if successful, False otherwise
        """
        try:
            if self.os_type == "Windows" and rule.file.startswith("HKLM\\"):
                return self._write_registry_value(rule.file, rule.parameter, rule.expected_value)
            else:
                return self._write_config_file_value(rule.file, rule.parameter, rule.expected_value)

        except Exception as e:
            logger.error(f"Failed to apply configuration: {e}")
            return False

    def _write_config_file_value(
        self,
        file_path: str,
        parameter: str,
        value: str
    ) -> bool:
        """
        Write a parameter value to a configuration file.

        Args:
            file_path: Path to configuration file
            parameter: Parameter name
            value: New value

        Returns:
            True if successful, False otherwise
        """
        try:
            # Read current content
            with open(file_path, 'r') as f:
                lines = f.readlines()

            # Find and replace the parameter
            modified = False
            new_lines = []

            for line in lines:
                # Check if this line contains the parameter
                if re.match(rf'^\s*#', line):
                    # Skip commented lines
                    new_lines.append(line)
                    continue

                # Check for parameter match
                patterns = [
                    (rf'^\s*({re.escape(parameter)})\s+(.+?)$', f'{parameter} {value}'),
                    (rf'^\s*({re.escape(parameter)})\s*=\s*(.+?)$', f'{parameter} = {value}'),
                    (rf'^\s*({re.escape(parameter)})\s*:\s*(.+?)$', f'{parameter}: {value}'),
                ]

                matched = False
                for pattern, replacement in patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        # Replace the line
                        new_lines.append(replacement + '\n')
                        modified = True
                        matched = True
                        break

                if not matched:
                    new_lines.append(line)

            # If parameter not found, append it
            if not modified:
                new_lines.append(f'\n{parameter} {value}\n')
                modified = True

            # Write back
            if modified:
                with open(file_path, 'w') as f:
                    f.writelines(new_lines)
                logger.debug(f"Updated {parameter} in {file_path}")
                return True

            return False

        except PermissionError:
            logger.error(f"Permission denied writing to {file_path}")
            return False
        except Exception as e:
            logger.error(f"Error writing to {file_path}: {e}")
            return False

    def _write_registry_value(
        self,
        key_path: str,
        value_name: str,
        value: str
    ) -> bool:
        """
        Write a Windows registry value.

        Args:
            key_path: Registry key path
            value_name: Value name
            value: New value

        Returns:
            True if successful, False otherwise
        """
        if self.os_type != "Windows":
            return False

        try:
            # Determine registry value type (default to string)
            reg_type = "REG_SZ"

            # Try to detect numeric values
            try:
                int(value)
                reg_type = "REG_DWORD"
            except ValueError:
                pass

            cmd = ["reg", "add", key_path, "/v", value_name, "/t", reg_type, "/d", value, "/f"]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode == 0:
                logger.debug(f"Updated registry {key_path}\\{value_name}")
                return True
            else:
                logger.error(f"Registry update failed: {result.stderr}")
                return False

        except Exception as e:
            logger.error(f"Error writing registry value: {e}")
            return False

    def _perform_rollback(self, session: HardeningSession):
        """
        Perform rollback of changes using the checkpoint.

        Args:
            session: Hardening session
        """
        if not session.checkpoint_id:
            logger.error("Cannot rollback: no checkpoint ID")
            return

        try:
            logger.info(f"Rolling back changes using checkpoint {session.checkpoint_id}")

            success = self.backup_manager.restore_checkpoint(session.checkpoint_id)

            if success:
                logger.info("Rollback completed successfully")
                session.rollback_performed = True

                # Update all successful results to rolled_back
                for result in session.results:
                    if result.status == RuleStatus.SUCCESS:
                        result.rollback()
            else:
                logger.error("Rollback failed")

        except RestoreError as e:
            logger.error(f"Rollback error: {e}")
        except Exception as e:
            logger.error(f"Unexpected rollback error: {e}", exc_info=True)

    def validate_rules(self, rules: List[ConfigurationRule]) -> HardeningSession:
        """
        Validate current system state against rules without making changes.

        Args:
            rules: List of rules to validate

        Returns:
            HardeningSession with validation results
        """
        return self.apply_rules(rules, mode=ExecutionMode.VALIDATE_ONLY)

    def dry_run(self, rules: List[ConfigurationRule]) -> HardeningSession:
        """
        Perform a dry run to see what changes would be made.

        Args:
            rules: List of rules to dry run

        Returns:
            HardeningSession with dry run results
        """
        return self.apply_rules(rules, mode=ExecutionMode.DRY_RUN)


# Convenience functions
def apply_hardening_rules(
    rules: List[ConfigurationRule],
    checkpoint_description: str = "Security hardening"
) -> HardeningSession:
    """
    Convenience function to apply hardening rules.

    Args:
        rules: List of configuration rules
        checkpoint_description: Description for backup checkpoint

    Returns:
        HardeningSession with results
    """
    engine = HardeningEngine()
    return engine.apply_rules(rules, ExecutionMode.APPLY, checkpoint_description)


def validate_hardening(rules: List[ConfigurationRule]) -> HardeningSession:
    """
    Convenience function to validate system against rules.

    Args:
        rules: List of configuration rules

    Returns:
        HardeningSession with validation results
    """
    engine = HardeningEngine()
    return engine.validate_rules(rules)


# Example usage and testing
if __name__ == "__main__":
    # Configure logging for standalone testing
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    print("=" * 70)
    print("Hardening Engine - Test Run")
    print("=" * 70)

    # Create test rules
    try:
        from .config_loader import ConfigLoader
    except ImportError:
        from config_loader import ConfigLoader

    print("\n1. Loading configuration...")
    loader = ConfigLoader()
    profiles = loader.load_os_configs('linux')

    if profiles:
        ssh_profile = profiles[0]
        print(f"Loaded profile: {ssh_profile.name}")
        print(f"Total rules: {len(ssh_profile.rules)}")

        # Select a few safe rules for testing (dry run)
        test_rules = ssh_profile.rules[:3]

        print(f"\n2. Testing with {len(test_rules)} rules:")
        for rule in test_rules:
            print(f"  - {rule.name}")

        # Initialize engine
        engine = HardeningEngine(
            auto_rollback=True,
            stop_on_critical_error=True
        )

        # Dry run test
        print("\n3. Performing DRY RUN...")
        session = engine.dry_run(test_rules)

        print(f"\nDry Run Results:")
        print(f"  Session ID: {session.session_id}")
        print(f"  Total: {session.total_rules}")
        print(f"  Successful: {session.successful_rules}")
        print(f"  Failed: {session.failed_rules}")
        print(f"  Skipped: {session.skipped_rules}")

        print("\nRule Details:")
        for result in session.results:
            print(f"\n  Rule: {result.rule_name}")
            print(f"    Status: {result.status.value}")
            print(f"    Before: {result.before_value}")
            print(f"    After: {result.after_value}")
            if result.changes_made:
                for change in result.changes_made:
                    print(f"    Change: {change}")

        # Validation test
        print("\n4. Performing VALIDATION...")
        validation_session = engine.validate_rules(test_rules)

        print(f"\nValidation Results:")
        for result in validation_session.results:
            status_symbol = "✓" if result.validation_result else "✗"
            print(f"  {status_symbol} {result.rule_name}: {result.validation_message}")

    else:
        print("No configuration profiles found")

    print("\n" + "=" * 70)
    print("Test completed!")
    print("=" * 70)
