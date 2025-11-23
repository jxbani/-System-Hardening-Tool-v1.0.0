#!/usr/bin/env python3
"""
Risk Scoring Engine for System Hardening Tool
Implements CVSS-like risk scoring for vulnerabilities
"""

import logging
from typing import Dict, List, Any
from datetime import datetime

logger = logging.getLogger(__name__)


class RiskScorer:
    """
    Calculates risk scores for vulnerabilities based on multiple factors.

    Risk Score = Base Score × Temporal Score × Environmental Score
    Range: 0.0 - 10.0 (aligned with CVSS)

    Risk Levels:
    - Critical: 9.0 - 10.0
    - High: 7.0 - 8.9
    - Medium: 4.0 - 6.9
    - Low: 0.1 - 3.9
    - None: 0.0
    """

    # Severity weights (base score component)
    SEVERITY_SCORES = {
        'critical': 9.0,
        'high': 7.5,
        'medium': 5.0,
        'warning': 5.0,
        'low': 2.5,
        'info': 1.0,
        'none': 0.0
    }

    # Category-based exploitability scores
    EXPLOITABILITY_SCORES = {
        'network security': 0.95,  # Highly exploitable remotely
        'authentication': 0.90,
        'access control': 0.85,
        'cryptography': 0.80,
        'system updates': 0.75,
        'configuration': 0.70,
        'file system': 0.65,
        'services': 0.60,
        'logging': 0.50,
        'monitoring': 0.45,
        'default': 0.60
    }

    # Impact multipliers
    IMPACT_MULTIPLIERS = {
        'confidentiality': 1.0,
        'integrity': 1.0,
        'availability': 1.0
    }

    def __init__(self):
        """Initialize risk scorer."""
        logger.info("RiskScorer initialized")

    def calculate_base_score(self, severity: str, category: str = None) -> float:
        """
        Calculate base risk score.

        Base Score = Severity Score × Exploitability

        Args:
            severity: Vulnerability severity (Critical/High/Medium/Low)
            category: Vulnerability category (affects exploitability)

        Returns:
            Base score (0.0 - 10.0)
        """
        severity_lower = severity.lower() if severity else 'low'
        category_lower = category.lower() if category else 'default'

        severity_score = self.SEVERITY_SCORES.get(severity_lower, 2.5)
        exploitability = self.EXPLOITABILITY_SCORES.get(category_lower,
                                                        self.EXPLOITABILITY_SCORES['default'])

        base_score = severity_score * exploitability
        return round(min(base_score, 10.0), 1)

    def calculate_temporal_score(self, base_score: float,
                                 remediation_available: bool = True,
                                 age_days: int = 0) -> float:
        """
        Calculate temporal score modifier.

        Temporal factors:
        - Remediation availability (0.9 if available, 1.0 if not)
        - Vulnerability age (increases over time)

        Args:
            base_score: Base risk score
            remediation_available: Whether a fix is available
            age_days: Days since vulnerability was discovered

        Returns:
            Temporal score
        """
        # Remediation modifier
        remediation_modifier = 0.9 if remediation_available else 1.0

        # Age modifier (increases risk over time, max 1.2x)
        age_modifier = min(1.0 + (age_days / 180), 1.2)

        temporal_score = base_score * remediation_modifier * age_modifier
        return round(min(temporal_score, 10.0), 1)

    def calculate_environmental_score(self, base_score: float,
                                     exposure: str = 'local',
                                     data_sensitivity: str = 'medium') -> float:
        """
        Calculate environmental score modifier.

        Environmental factors:
        - Exposure level (network-facing vs local)
        - Data sensitivity

        Args:
            base_score: Base risk score
            exposure: Exposure level (network/local/isolated)
            data_sensitivity: Data sensitivity (high/medium/low)

        Returns:
            Environmental score
        """
        # Exposure modifiers
        exposure_modifiers = {
            'network': 1.2,  # Internet-facing
            'local': 1.0,    # Local network only
            'isolated': 0.8  # Isolated system
        }

        # Data sensitivity modifiers
        sensitivity_modifiers = {
            'high': 1.15,    # Contains sensitive/PII data
            'medium': 1.0,
            'low': 0.9
        }

        exposure_mod = exposure_modifiers.get(exposure.lower(), 1.0)
        sensitivity_mod = sensitivity_modifiers.get(data_sensitivity.lower(), 1.0)

        environmental_score = base_score * exposure_mod * sensitivity_mod
        return round(min(environmental_score, 10.0), 1)

    def calculate_risk_score(self, vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """
        Calculate comprehensive risk score for a vulnerability.

        Args:
            vulnerability: Vulnerability dict with severity, category, etc.

        Returns:
            Dict with risk score and breakdown
        """
        severity = vulnerability.get('severity', 'Low')
        category = vulnerability.get('category', 'default')

        # Calculate base score
        base_score = self.calculate_base_score(severity, category)

        # Calculate temporal score
        remediation_available = bool(vulnerability.get('recommendation'))
        age_days = 0  # Could calculate from timestamp
        temporal_score = self.calculate_temporal_score(
            base_score,
            remediation_available,
            age_days
        )

        # Calculate environmental score
        exposure = self._determine_exposure(category)
        data_sensitivity = vulnerability.get('data_sensitivity', 'medium')
        environmental_score = self.calculate_environmental_score(
            temporal_score,
            exposure,
            data_sensitivity
        )

        # Final risk score
        risk_score = environmental_score
        risk_level = self.get_risk_level(risk_score)

        return {
            'risk_score': risk_score,
            'risk_level': risk_level,
            'base_score': base_score,
            'temporal_score': temporal_score,
            'environmental_score': environmental_score,
            'factors': {
                'severity': severity,
                'category': category,
                'exploitability': self.EXPLOITABILITY_SCORES.get(
                    category.lower(),
                    self.EXPLOITABILITY_SCORES['default']
                ),
                'exposure': exposure,
                'remediation_available': remediation_available
            }
        }

    def _determine_exposure(self, category: str) -> str:
        """
        Determine exposure level based on category.

        Args:
            category: Vulnerability category

        Returns:
            Exposure level (network/local/isolated)
        """
        network_categories = [
            'network security',
            'authentication',
            'services'
        ]

        if any(nc in category.lower() for nc in network_categories):
            return 'network'
        return 'local'

    def get_risk_level(self, score: float) -> str:
        """
        Get risk level from numeric score.

        Args:
            score: Risk score (0.0 - 10.0)

        Returns:
            Risk level string
        """
        if score >= 9.0:
            return 'Critical'
        elif score >= 7.0:
            return 'High'
        elif score >= 4.0:
            return 'Medium'
        elif score > 0.0:
            return 'Low'
        else:
            return 'None'

    def calculate_overall_risk(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Calculate overall system risk from multiple vulnerabilities.

        Args:
            vulnerabilities: List of vulnerability dicts

        Returns:
            Overall risk assessment
        """
        if not vulnerabilities:
            return {
                'overall_score': 0.0,
                'risk_level': 'None',
                'total_vulnerabilities': 0,
                'risk_distribution': {
                    'critical': 0,
                    'high': 0,
                    'medium': 0,
                    'low': 0
                }
            }

        risk_scores = []
        risk_distribution = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0
        }

        for vuln in vulnerabilities:
            risk_data = self.calculate_risk_score(vuln)
            risk_scores.append(risk_data['risk_score'])

            level = risk_data['risk_level'].lower()
            if level in risk_distribution:
                risk_distribution[level] += 1

        # Calculate overall score (weighted average with emphasis on high scores)
        if risk_scores:
            # Sort scores in descending order
            sorted_scores = sorted(risk_scores, reverse=True)

            # Weight: 50% highest score, 30% average of top 3, 20% overall average
            highest = sorted_scores[0]
            top_3_avg = sum(sorted_scores[:3]) / min(3, len(sorted_scores))
            overall_avg = sum(risk_scores) / len(risk_scores)

            overall_score = (highest * 0.5) + (top_3_avg * 0.3) + (overall_avg * 0.2)
        else:
            overall_score = 0.0

        return {
            'overall_score': round(overall_score, 1),
            'risk_level': self.get_risk_level(overall_score),
            'total_vulnerabilities': len(vulnerabilities),
            'risk_distribution': risk_distribution,
            'average_score': round(sum(risk_scores) / len(risk_scores), 1) if risk_scores else 0.0,
            'highest_score': max(risk_scores) if risk_scores else 0.0
        }

    def calculate_risk_trend(self, historical_scans: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Calculate risk trends over time.

        Args:
            historical_scans: List of historical scan results with risk scores

        Returns:
            Risk trend analysis
        """
        if not historical_scans:
            return {
                'trend': 'stable',
                'change_percentage': 0.0,
                'risk_trajectory': []
            }

        # Extract risk scores and timestamps
        data_points = []
        for scan in historical_scans:
            timestamp = scan.get('timestamp')
            overall_risk = scan.get('overall_risk_score', 0.0)
            data_points.append({
                'timestamp': timestamp,
                'score': overall_risk
            })

        # Sort by timestamp
        data_points.sort(key=lambda x: x['timestamp'])

        # Calculate trend
        if len(data_points) >= 2:
            first_score = data_points[0]['score']
            last_score = data_points[-1]['score']

            if first_score > 0:
                change_percentage = ((last_score - first_score) / first_score) * 100
            else:
                change_percentage = 0.0

            # Determine trend direction
            if change_percentage < -10:
                trend = 'improving'
            elif change_percentage > 10:
                trend = 'worsening'
            else:
                trend = 'stable'
        else:
            trend = 'insufficient_data'
            change_percentage = 0.0

        return {
            'trend': trend,
            'change_percentage': round(change_percentage, 1),
            'risk_trajectory': data_points,
            'data_points': len(data_points)
        }

    def generate_risk_recommendations(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Generate prioritized recommendations based on risk scores.

        Args:
            vulnerabilities: List of vulnerabilities with risk scores

        Returns:
            Prioritized list of recommendations
        """
        recommendations = []

        for vuln in vulnerabilities:
            risk_data = self.calculate_risk_score(vuln)

            recommendations.append({
                'vulnerability_id': vuln.get('id'),
                'description': vuln.get('description'),
                'category': vuln.get('category'),
                'risk_score': risk_data['risk_score'],
                'risk_level': risk_data['risk_level'],
                'recommendation': vuln.get('recommendation'),
                'priority': self._get_priority_rank(risk_data['risk_score'])
            })

        # Sort by risk score (highest first)
        recommendations.sort(key=lambda x: x['risk_score'], reverse=True)

        return recommendations

    def _get_priority_rank(self, risk_score: float) -> int:
        """Get priority rank (1=highest, 4=lowest) from risk score."""
        if risk_score >= 9.0:
            return 1  # Critical - immediate action
        elif risk_score >= 7.0:
            return 2  # High - urgent
        elif risk_score >= 4.0:
            return 3  # Medium - scheduled
        else:
            return 4  # Low - as resources permit
