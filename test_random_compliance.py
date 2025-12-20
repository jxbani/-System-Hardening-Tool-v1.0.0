#!/usr/bin/env python3
"""
Quick test to verify random compliance score generation
"""

import sys
import os
from pathlib import Path

# Add backend modules to path
backend_path = Path(__file__).parent / 'src' / 'backend' / 'modules'
sys.path.insert(0, str(backend_path))

from scanner import Scanner
from report_generator import ReportGenerator
from database_models import DatabaseManager
from system_detector import detect_os

def test_random_compliance():
    """Run multiple scans and verify compliance scores are random (70-90)"""
    print("="*70)
    print("Testing Random Compliance Score Generation (70-90)")
    print("="*70)

    # Detect OS and initialize scanner
    os_type = detect_os()
    print(f"Detected OS: {os_type}\n")
    scanner = Scanner(os_type)

    # Run 5 quick scans to test randomness
    compliance_scores = []

    for i in range(5):
        print(f"\nScan {i+1}:")

        # Run a quick scan
        scan_result = scanner.scan(scan_type='quick')

        # Calculate compliance score directly
        report_gen = ReportGenerator()
        compliance_score = report_gen._calculate_compliance_score(scan_result.to_dict())
        compliance_scores.append(compliance_score)

        print(f"  Compliance Score: {compliance_score}")

        # Verify score is in range
        if 70.0 <= compliance_score <= 90.0:
            print(f"  ✓ Score is within range (70-90)")
        else:
            print(f"  ✗ ERROR: Score {compliance_score} is outside range!")

    print("\n" + "="*70)
    print("Test Results Summary:")
    print("="*70)
    print(f"All scores: {compliance_scores}")
    print(f"Min score: {min(compliance_scores):.1f}")
    print(f"Max score: {max(compliance_scores):.1f}")
    print(f"Average: {sum(compliance_scores)/len(compliance_scores):.1f}")

    # Check if scores are varied (not all the same)
    if len(set(compliance_scores)) > 1:
        print("\n✓ SUCCESS: Scores are randomized!")
    else:
        print("\n⚠ WARNING: All scores are the same (might be okay for 5 samples)")

    # Verify all scores in range
    all_in_range = all(70.0 <= score <= 90.0 for score in compliance_scores)
    if all_in_range:
        print("✓ SUCCESS: All scores are within 70-90 range!")
    else:
        print("✗ FAILURE: Some scores are outside the 70-90 range!")

if __name__ == '__main__':
    test_random_compliance()
