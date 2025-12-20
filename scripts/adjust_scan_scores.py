#!/usr/bin/env python3
"""
Script to view and adjust stored scan scores in the database
"""

import sys
import os

# Add parent directory to path to import modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src', 'backend'))

from modules.database_models import DatabaseManager, Scan, Vulnerability
from datetime import datetime


def list_scans(db_manager):
    """List all scans in the database"""
    scans = db_manager.get_scan_history()

    if not scans:
        print("No scans found in database")
        return []

    print("\n" + "="*80)
    print("STORED SCANS")
    print("="*80)

    for i, scan in enumerate(scans, 1):
        print(f"\n{i}. Scan ID: {scan['scan_id']}")
        print(f"   Date: {scan['timestamp']}")
        print(f"   Type: {scan['scan_type']}")
        print(f"   Status: {scan['status']}")
        print(f"   Total Vulnerabilities: {scan['totalVulnerabilities']}")
        print(f"   Critical Issues: {scan['criticalIssues']}")
        print(f"   Compliance Score: {scan['complianceScore']:.2f}")
        print(f"   Overall Risk Score: {scan['overall_risk_score']:.2f}")
        print(f"   Risk Level: {scan['risk_level']}")

    print("\n" + "="*80)
    return scans


def update_scan_scores(db_manager, scan_id, updates):
    """Update scores for a specific scan"""
    session = db_manager.get_session()
    try:
        # Find the scan
        scan = session.query(Scan).filter_by(scan_id=scan_id).first()

        if not scan:
            print(f"Error: Scan {scan_id} not found")
            return False

        print(f"\nUpdating Scan: {scan_id}")
        print("Before:")
        print(f"  Compliance Score: {scan.compliance_score:.2f}")
        print(f"  Overall Risk Score: {scan.overall_risk_score:.2f}")
        print(f"  Risk Level: {scan.risk_level}")
        print(f"  Total Vulnerabilities: {scan.total_vulnerabilities}")
        print(f"  Critical Issues: {scan.critical_issues}")

        # Apply updates
        if 'compliance_score' in updates:
            scan.compliance_score = updates['compliance_score']

        if 'overall_risk_score' in updates:
            scan.overall_risk_score = updates['overall_risk_score']

        if 'risk_level' in updates:
            scan.risk_level = updates['risk_level']

        if 'total_vulnerabilities' in updates:
            scan.total_vulnerabilities = updates['total_vulnerabilities']

        if 'critical_issues' in updates:
            scan.critical_issues = updates['critical_issues']

        if 'warnings' in updates:
            scan.warnings = updates['warnings']

        if 'risk_distribution' in updates:
            scan.risk_distribution = updates['risk_distribution']

        session.commit()

        print("\nAfter:")
        print(f"  Compliance Score: {scan.compliance_score:.2f}")
        print(f"  Overall Risk Score: {scan.overall_risk_score:.2f}")
        print(f"  Risk Level: {scan.risk_level}")
        print(f"  Total Vulnerabilities: {scan.total_vulnerabilities}")
        print(f"  Critical Issues: {scan.critical_issues}")

        session.close()
        print("\n✓ Scan updated successfully!")
        return True

    except Exception as e:
        session.rollback()
        session.close()
        print(f"Error updating scan: {e}")
        return False


def interactive_mode(db_manager):
    """Interactive mode to adjust scan scores"""
    scans = list_scans(db_manager)

    if not scans:
        return

    print("\nSelect scan to modify (enter number, or 'q' to quit): ", end='')
    choice = input().strip()

    if choice.lower() == 'q':
        return

    try:
        index = int(choice) - 1
        if index < 0 or index >= len(scans):
            print("Invalid selection")
            return

        selected_scan = scans[index]
        scan_id = selected_scan['scan_id']

        print(f"\n--- Modifying Scan: {scan_id} ---")
        updates = {}

        # Compliance Score
        print(f"\nCurrent Compliance Score: {selected_scan['complianceScore']:.2f}")
        print("New Compliance Score (0-100, or press Enter to skip): ", end='')
        value = input().strip()
        if value:
            updates['compliance_score'] = float(value)

        # Overall Risk Score
        print(f"\nCurrent Overall Risk Score: {selected_scan['overall_risk_score']:.2f}")
        print("New Overall Risk Score (0-10, or press Enter to skip): ", end='')
        value = input().strip()
        if value:
            updates['overall_risk_score'] = float(value)

        # Risk Level
        print(f"\nCurrent Risk Level: {selected_scan['risk_level']}")
        print("New Risk Level (Critical/High/Medium/Low/None, or press Enter to skip): ", end='')
        value = input().strip()
        if value:
            updates['risk_level'] = value

        # Total Vulnerabilities
        print(f"\nCurrent Total Vulnerabilities: {selected_scan['totalVulnerabilities']}")
        print("New Total Vulnerabilities (or press Enter to skip): ", end='')
        value = input().strip()
        if value:
            updates['total_vulnerabilities'] = int(value)

        # Critical Issues
        print(f"\nCurrent Critical Issues: {selected_scan['criticalIssues']}")
        print("New Critical Issues (or press Enter to skip): ", end='')
        value = input().strip()
        if value:
            updates['critical_issues'] = int(value)

        if updates:
            confirm = input("\nApply these changes? (y/n): ").strip().lower()
            if confirm == 'y':
                update_scan_scores(db_manager, scan_id, updates)
        else:
            print("No changes specified")

    except ValueError as e:
        print(f"Invalid input: {e}")
    except Exception as e:
        print(f"Error: {e}")


def main():
    # Initialize database
    db_path = os.path.join(os.path.dirname(__file__), '..', 'src', 'data', 'hardening_tool.db')

    if not os.path.exists(db_path):
        print(f"Database not found at: {db_path}")
        return

    db_manager = DatabaseManager(db_path)

    if len(sys.argv) > 1:
        # Command line mode
        if sys.argv[1] == 'list':
            list_scans(db_manager)
        elif sys.argv[1] == 'update' and len(sys.argv) >= 3:
            scan_id = sys.argv[2]
            # Parse updates from command line arguments
            # Format: update SCAN_ID compliance_score=75.5 risk_score=6.5
            updates = {}
            for arg in sys.argv[3:]:
                if '=' in arg:
                    key, value = arg.split('=', 1)
                    if key in ['compliance_score', 'overall_risk_score']:
                        updates[key] = float(value)
                    elif key in ['total_vulnerabilities', 'critical_issues', 'warnings']:
                        updates[key] = int(value)
                    elif key == 'risk_level':
                        updates[key] = value

            if updates:
                update_scan_scores(db_manager, scan_id, updates)
            else:
                print("No valid updates provided")
        else:
            print("Usage:")
            print("  python adjust_scan_scores.py                    # Interactive mode")
            print("  python adjust_scan_scores.py list               # List all scans")
            print("  python adjust_scan_scores.py update SCAN_ID key=value key=value ...")
            print("\nExample:")
            print("  python adjust_scan_scores.py update scan-123 compliance_score=85.5 risk_score=4.2")
    else:
        # Interactive mode
        interactive_mode(db_manager)


if __name__ == '__main__':
    main()
