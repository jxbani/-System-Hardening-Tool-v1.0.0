#!/usr/bin/env python3
"""
Configuration Loader Module
Loads and manages hardening configuration rules from JSON files.
"""

import os
import json
import logging
from typing import Dict, List, Optional, Any
from pathlib import Path

logger = logging.getLogger(__name__)


class ConfigurationRule:
    """Represents a single security configuration rule."""

    def __init__(self, rule_data: Dict[str, Any]):
        """
        Initialize a configuration rule.

        Args:
            rule_data: Dictionary containing rule information
        """
        self.id = rule_data.get('id', '')
        self.name = rule_data.get('name', '')
        self.file = rule_data.get('file', '')
        self.parameter = rule_data.get('parameter', '')
        self.expected_value = rule_data.get('expected_value', '')
        self.comparison = rule_data.get('comparison', '==')  # ==, !=, <, >, <=, >=
        self.severity = rule_data.get('severity', 'medium')
        self.description = rule_data.get('description', '')
        self.remediation = rule_data.get('remediation', '')
        self.references = rule_data.get('references', [])
        self.enabled = rule_data.get('enabled', True)

    def to_dict(self) -> Dict[str, Any]:
        """Convert rule to dictionary format."""
        return {
            'id': self.id,
            'name': self.name,
            'file': self.file,
            'parameter': self.parameter,
            'expected_value': self.expected_value,
            'comparison': self.comparison,
            'severity': self.severity,
            'description': self.description,
            'remediation': self.remediation,
            'references': self.references,
            'enabled': self.enabled
        }

    def __repr__(self) -> str:
        return f"<ConfigurationRule id={self.id} name={self.name} severity={self.severity}>"


class ConfigurationProfile:
    """Represents a configuration profile with multiple rules."""

    def __init__(self, profile_data: Dict[str, Any], source_file: Optional[str] = None):
        """
        Initialize a configuration profile.

        Args:
            profile_data: Dictionary containing profile information
            source_file: Path to the source JSON file
        """
        self.name = profile_data.get('name', 'Unnamed Profile')
        self.description = profile_data.get('description', '')
        self.category = profile_data.get('category', 'General')
        self.applies_to = profile_data.get('applies_to', [])
        self.config_file = profile_data.get('config_file', '')
        self.source_file = source_file

        # Load rules
        self.rules: List[ConfigurationRule] = []
        for rule_data in profile_data.get('checks', []):
            self.rules.append(ConfigurationRule(rule_data))

        logger.debug(f"Loaded profile '{self.name}' with {len(self.rules)} rules")

    def get_rule_by_id(self, rule_id: str) -> Optional[ConfigurationRule]:
        """
        Get a specific rule by its ID.

        Args:
            rule_id: Rule identifier

        Returns:
            ConfigurationRule or None if not found
        """
        for rule in self.rules:
            if rule.id == rule_id:
                return rule
        return None

    def get_rules_by_severity(self, severity: str) -> List[ConfigurationRule]:
        """
        Get all rules matching a specific severity level.

        Args:
            severity: Severity level (critical, high, medium, low)

        Returns:
            List of matching rules
        """
        return [rule for rule in self.rules if rule.severity.lower() == severity.lower()]

    def get_enabled_rules(self) -> List[ConfigurationRule]:
        """
        Get all enabled rules.

        Returns:
            List of enabled rules
        """
        return [rule for rule in self.rules if rule.enabled]

    def to_dict(self) -> Dict[str, Any]:
        """Convert profile to dictionary format."""
        return {
            'name': self.name,
            'description': self.description,
            'category': self.category,
            'applies_to': self.applies_to,
            'config_file': self.config_file,
            'source_file': self.source_file,
            'rules_count': len(self.rules),
            'rules': [rule.to_dict() for rule in self.rules]
        }

    def __repr__(self) -> str:
        return f"<ConfigurationProfile name={self.name} rules={len(self.rules)}>"


class ConfigLoader:
    """
    Loads and manages configuration profiles from JSON files.
    """

    def __init__(self, config_base_path: Optional[str] = None):
        """
        Initialize the configuration loader.

        Args:
            config_base_path: Base path for configuration files.
                            If None, uses default path relative to this file.
        """
        if config_base_path:
            self.config_base_path = Path(config_base_path)
        else:
            # Default: project_root/config/
            module_dir = Path(__file__).parent
            self.config_base_path = module_dir.parent.parent.parent / 'config'

        self.profiles: Dict[str, ConfigurationProfile] = {}
        logger.info(f"ConfigLoader initialized with base path: {self.config_base_path}")

    def load_config_file(self, file_path: str) -> Optional[ConfigurationProfile]:
        """
        Load a single configuration file.

        Args:
            file_path: Path to JSON configuration file

        Returns:
            ConfigurationProfile or None if loading fails
        """
        try:
            file_path = Path(file_path)

            if not file_path.exists():
                logger.error(f"Configuration file not found: {file_path}")
                return None

            logger.info(f"Loading configuration file: {file_path}")

            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)

            profile = ConfigurationProfile(data, str(file_path))

            # Store profile with a key based on filename
            profile_key = file_path.stem
            self.profiles[profile_key] = profile

            logger.info(f"Successfully loaded profile '{profile.name}' from {file_path}")
            return profile

        except json.JSONDecodeError as e:
            logger.error(f"JSON decode error in {file_path}: {e}")
            return None
        except Exception as e:
            logger.error(f"Error loading configuration file {file_path}: {e}")
            return None

    def load_os_configs(self, os_type: str) -> List[ConfigurationProfile]:
        """
        Load all configuration files for a specific OS.

        Args:
            os_type: Operating system type (linux, windows, darwin)

        Returns:
            List of loaded profiles
        """
        os_type = os_type.lower()
        os_config_path = self.config_base_path / os_type

        logger.info(f"Loading configurations for OS: {os_type} from {os_config_path}")

        if not os_config_path.exists():
            logger.warning(f"Configuration directory not found: {os_config_path}")
            return []

        loaded_profiles = []

        # Find all JSON files in the OS config directory
        try:
            for json_file in os_config_path.glob('*.json'):
                profile = self.load_config_file(json_file)
                if profile:
                    loaded_profiles.append(profile)

            logger.info(f"Loaded {len(loaded_profiles)} profiles for {os_type}")

        except Exception as e:
            logger.error(f"Error scanning configuration directory {os_config_path}: {e}")

        return loaded_profiles

    def load_all_configs(self) -> Dict[str, List[ConfigurationProfile]]:
        """
        Load all configuration files for all operating systems.

        Returns:
            Dictionary mapping OS type to list of profiles
        """
        logger.info("Loading all configuration files")
        all_configs = {}

        # Scan for OS directories
        try:
            if not self.config_base_path.exists():
                logger.error(f"Config base path does not exist: {self.config_base_path}")
                return all_configs

            for os_dir in self.config_base_path.iterdir():
                if os_dir.is_dir():
                    os_type = os_dir.name
                    profiles = self.load_os_configs(os_type)
                    if profiles:
                        all_configs[os_type] = profiles

            logger.info(f"Loaded configurations for {len(all_configs)} operating systems")

        except Exception as e:
            logger.error(f"Error loading all configurations: {e}")

        return all_configs

    def get_profile(self, profile_key: str) -> Optional[ConfigurationProfile]:
        """
        Get a specific profile by key.

        Args:
            profile_key: Profile identifier (usually filename without extension)

        Returns:
            ConfigurationProfile or None if not found
        """
        return self.profiles.get(profile_key)

    def get_all_profiles(self) -> List[ConfigurationProfile]:
        """
        Get all loaded profiles.

        Returns:
            List of all profiles
        """
        return list(self.profiles.values())

    def get_profiles_by_category(self, category: str) -> List[ConfigurationProfile]:
        """
        Get all profiles matching a specific category.

        Args:
            category: Category name

        Returns:
            List of matching profiles
        """
        return [
            profile for profile in self.profiles.values()
            if profile.category.lower() == category.lower()
        ]

    def search_rules(self, query: str) -> List[tuple[ConfigurationProfile, ConfigurationRule]]:
        """
        Search for rules matching a query string.

        Args:
            query: Search query (matches against rule name, description, parameter)

        Returns:
            List of tuples (profile, rule) matching the query
        """
        results = []
        query_lower = query.lower()

        for profile in self.profiles.values():
            for rule in profile.rules:
                if (query_lower in rule.name.lower() or
                    query_lower in rule.description.lower() or
                    query_lower in rule.parameter.lower() or
                    query_lower in rule.id.lower()):
                    results.append((profile, rule))

        return results

    def export_profile_to_json(self, profile_key: str, output_path: str) -> bool:
        """
        Export a profile to a JSON file.

        Args:
            profile_key: Profile identifier
            output_path: Output file path

        Returns:
            True if successful, False otherwise
        """
        try:
            profile = self.get_profile(profile_key)
            if not profile:
                logger.error(f"Profile not found: {profile_key}")
                return False

            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(profile.to_dict(), f, indent=2)

            logger.info(f"Exported profile '{profile.name}' to {output_path}")
            return True

        except Exception as e:
            logger.error(f"Error exporting profile: {e}")
            return False

    def get_statistics(self) -> Dict[str, Any]:
        """
        Get statistics about loaded configurations.

        Returns:
            Dictionary with statistics
        """
        total_rules = sum(len(profile.rules) for profile in self.profiles.values())

        severity_counts = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0
        }

        for profile in self.profiles.values():
            for rule in profile.rules:
                severity = rule.severity.lower()
                if severity in severity_counts:
                    severity_counts[severity] += 1

        return {
            'total_profiles': len(self.profiles),
            'total_rules': total_rules,
            'severity_breakdown': severity_counts,
            'profiles': [
                {
                    'name': profile.name,
                    'rules_count': len(profile.rules),
                    'category': profile.category
                }
                for profile in self.profiles.values()
            ]
        }


# Convenience functions
def load_ssh_config(os_type: str = 'linux') -> Optional[ConfigurationProfile]:
    """
    Convenience function to load SSH configuration.

    Args:
        os_type: Operating system type

    Returns:
        SSH ConfigurationProfile or None
    """
    loader = ConfigLoader()
    profile = loader.load_config_file(loader.config_base_path / os_type / 'ssh_config.json')
    return profile


def load_os_configs(os_type: str) -> List[ConfigurationProfile]:
    """
    Convenience function to load all configs for an OS.

    Args:
        os_type: Operating system type

    Returns:
        List of ConfigurationProfile objects
    """
    loader = ConfigLoader()
    return loader.load_os_configs(os_type)


# Example usage and testing
if __name__ == "__main__":
    # Configure logging for standalone testing
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    print("=" * 70)
    print("Configuration Loader - Test Run")
    print("=" * 70)

    # Initialize loader
    loader = ConfigLoader()
    print(f"\nConfig base path: {loader.config_base_path}")

    # Test loading SSH config
    print("\n" + "=" * 70)
    print("Loading SSH Configuration")
    print("=" * 70)

    ssh_profile = load_ssh_config('linux')
    if ssh_profile:
        print(f"\nProfile: {ssh_profile.name}")
        print(f"Description: {ssh_profile.description}")
        print(f"Category: {ssh_profile.category}")
        print(f"Rules: {len(ssh_profile.rules)}")

        print("\nRules by Severity:")
        for severity in ['critical', 'high', 'medium', 'low']:
            rules = ssh_profile.get_rules_by_severity(severity)
            print(f"  {severity.capitalize()}: {len(rules)}")

        print("\nSample Rules:")
        for rule in ssh_profile.rules[:5]:
            print(f"  - [{rule.severity.upper()}] {rule.name}")
            print(f"    Parameter: {rule.parameter} = {rule.expected_value}")
            print(f"    Description: {rule.description}")
    else:
        print("Failed to load SSH configuration")

    # Test loading all Linux configs
    print("\n" + "=" * 70)
    print("Loading All Linux Configurations")
    print("=" * 70)

    linux_profiles = loader.load_os_configs('linux')
    print(f"\nLoaded {len(linux_profiles)} profile(s) for Linux:")
    for profile in linux_profiles:
        print(f"  - {profile.name} ({len(profile.rules)} rules)")

    # Test statistics
    print("\n" + "=" * 70)
    print("Configuration Statistics")
    print("=" * 70)

    stats = loader.get_statistics()
    print(f"\nTotal Profiles: {stats['total_profiles']}")
    print(f"Total Rules: {stats['total_rules']}")
    print("\nSeverity Breakdown:")
    for severity, count in stats['severity_breakdown'].items():
        print(f"  {severity.capitalize()}: {count}")

    # Test search
    print("\n" + "=" * 70)
    print("Search Test - Query: 'root'")
    print("=" * 70)

    results = loader.search_rules('root')
    print(f"\nFound {len(results)} matching rule(s):")
    for profile, rule in results[:3]:
        print(f"  - {rule.name} (in {profile.name})")

    # Test getting specific rule
    print("\n" + "=" * 70)
    print("Get Specific Rule Test")
    print("=" * 70)

    if ssh_profile:
        rule = ssh_profile.get_rule_by_id('ssh_root_login')
        if rule:
            print(f"\nRule Details:")
            print(f"  ID: {rule.id}")
            print(f"  Name: {rule.name}")
            print(f"  File: {rule.file}")
            print(f"  Parameter: {rule.parameter}")
            print(f"  Expected: {rule.expected_value}")
            print(f"  Severity: {rule.severity}")
            print(f"  Description: {rule.description}")
            print(f"  Remediation: {rule.remediation}")

    print("\n" + "=" * 70)
