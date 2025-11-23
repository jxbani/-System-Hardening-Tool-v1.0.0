#!/usr/bin/env python3
"""
Database Models for System Hardening Tool
Stores scan history, vulnerabilities, and hardening sessions
"""

from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Text, ForeignKey, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from datetime import datetime
import os

Base = declarative_base()


class Scan(Base):
    """Model for storing security scan results"""
    __tablename__ = 'scans'

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(String(100), unique=True, nullable=False, index=True)
    scan_type = Column(String(50), default='full')
    timestamp = Column(DateTime, default=datetime.now, nullable=False, index=True)
    status = Column(String(20), default='completed')

    # Metrics
    total_vulnerabilities = Column(Integer, default=0)
    compliance_score = Column(Float, default=0.0)
    critical_issues = Column(Integer, default=0)
    warnings = Column(Integer, default=0)

    # Risk scoring metrics
    overall_risk_score = Column(Float, default=0.0)
    risk_level = Column(String(20), default='Low')
    risk_distribution = Column(JSON)  # Distribution of risk levels

    # System info at time of scan
    system_info = Column(JSON)

    # Relationships
    vulnerabilities = relationship("Vulnerability", back_populates="scan", cascade="all, delete-orphan")

    def to_dict(self):
        """Convert to dictionary"""
        return {
            'id': self.id,
            'scan_id': self.scan_id,
            'scan_type': self.scan_type,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'status': self.status,
            'totalVulnerabilities': self.total_vulnerabilities,
            'complianceScore': self.compliance_score,
            'criticalIssues': self.critical_issues,
            'warnings': self.warnings,
            'overall_risk_score': self.overall_risk_score,
            'risk_level': self.risk_level,
            'risk_distribution': self.risk_distribution,
            'system_info': self.system_info
        }


class Vulnerability(Base):
    """Model for storing individual vulnerabilities found in scans"""
    __tablename__ = 'vulnerabilities'

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(Integer, ForeignKey('scans.id'), nullable=False)

    category = Column(String(100))
    severity = Column(String(20), index=True)
    description = Column(Text)
    status = Column(String(20), default='Open')
    recommendation = Column(Text)
    timestamp = Column(DateTime, default=datetime.now)

    # Risk scoring
    risk_score = Column(Float, default=0.0)
    risk_level = Column(String(20), default='Low')
    risk_factors = Column(JSON)  # Detailed risk calculation factors

    # Relationships
    scan = relationship("Scan", back_populates="vulnerabilities")

    def to_dict(self):
        """Convert to dictionary"""
        return {
            'id': self.id,
            'scan_id': self.scan_id,
            'category': self.category,
            'severity': self.severity,
            'description': self.description,
            'status': self.status,
            'recommendation': self.recommendation,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'risk_score': self.risk_score,
            'risk_level': self.risk_level,
            'risk_factors': self.risk_factors
        }


class HardeningSession(Base):
    """Model for storing system hardening sessions"""
    __tablename__ = 'hardening_sessions'

    id = Column(Integer, primary_key=True, autoincrement=True)
    operation_id = Column(String(100), unique=True, nullable=False, index=True)
    policy = Column(String(50))
    dry_run = Column(Integer, default=1)  # SQLite doesn't have boolean
    timestamp = Column(DateTime, default=datetime.now, nullable=False, index=True)
    status = Column(String(20), default='completed')
    changes_applied = Column(Integer, default=0)

    # Store the changes as JSON
    changes = Column(JSON)

    # Link to scan if this was triggered by scan results
    related_scan_id = Column(Integer, ForeignKey('scans.id'), nullable=True)

    def to_dict(self):
        """Convert to dictionary"""
        return {
            'id': self.id,
            'operation_id': self.operation_id,
            'policy': self.policy,
            'dry_run': bool(self.dry_run),
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'status': self.status,
            'changes_applied': self.changes_applied,
            'changes': self.changes,
            'related_scan_id': self.related_scan_id
        }


class SystemSnapshot(Base):
    """Model for storing system state snapshots for before/after comparison"""
    __tablename__ = 'system_snapshots'

    id = Column(Integer, primary_key=True, autoincrement=True)
    snapshot_id = Column(String(100), unique=True, nullable=False)
    timestamp = Column(DateTime, default=datetime.now, nullable=False, index=True)
    snapshot_type = Column(String(20))  # 'before_hardening', 'after_hardening', 'scheduled'

    # System state
    compliance_score = Column(Float)
    total_vulnerabilities = Column(Integer)
    critical_issues = Column(Integer)

    # Full system state as JSON
    system_state = Column(JSON)

    # Link to scan and hardening session
    scan_id = Column(Integer, ForeignKey('scans.id'), nullable=True)
    hardening_session_id = Column(Integer, ForeignKey('hardening_sessions.id'), nullable=True)

    def to_dict(self):
        """Convert to dictionary"""
        return {
            'id': self.id,
            'snapshot_id': self.snapshot_id,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'snapshot_type': self.snapshot_type,
            'compliance_score': self.compliance_score,
            'total_vulnerabilities': self.total_vulnerabilities,
            'critical_issues': self.critical_issues,
            'system_state': self.system_state,
            'scan_id': self.scan_id,
            'hardening_session_id': self.hardening_session_id
        }


class RemediationExecution(Base):
    """Model for tracking guided remediation playbook executions"""
    __tablename__ = 'remediation_executions'

    id = Column(Integer, primary_key=True, autoincrement=True)
    execution_id = Column(String(100), unique=True, nullable=False, index=True)
    playbook_id = Column(String(100), nullable=False)
    playbook_name = Column(String(200))
    vulnerability_id = Column(Integer, ForeignKey('vulnerabilities.id'), nullable=True)
    timestamp = Column(DateTime, default=datetime.now, nullable=False, index=True)

    # Execution details
    status = Column(String(20), default='pending')  # pending, in_progress, completed, failed, validation_failed
    steps_completed = Column(Integer, default=0)
    total_steps = Column(Integer, default=0)
    execution_time_seconds = Column(Float)

    # Validation results
    validation_passed = Column(Integer, default=0)  # SQLite boolean
    validation_results = Column(JSON)

    # Results
    before_state = Column(JSON)  # System state before remediation
    after_state = Column(JSON)   # System state after remediation
    errors = Column(JSON)
    warnings = Column(JSON)

    # Metrics
    risk_score_before = Column(Float)
    risk_score_after = Column(Float)
    risk_reduction = Column(Float)

    def to_dict(self):
        """Convert to dictionary"""
        return {
            'id': self.id,
            'execution_id': self.execution_id,
            'playbook_id': self.playbook_id,
            'playbook_name': self.playbook_name,
            'vulnerability_id': self.vulnerability_id,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'status': self.status,
            'steps_completed': self.steps_completed,
            'total_steps': self.total_steps,
            'execution_time_seconds': self.execution_time_seconds,
            'validation_passed': bool(self.validation_passed),
            'validation_results': self.validation_results,
            'before_state': self.before_state,
            'after_state': self.after_state,
            'errors': self.errors,
            'warnings': self.warnings,
            'risk_score_before': self.risk_score_before,
            'risk_score_after': self.risk_score_after,
            'risk_reduction': self.risk_reduction
        }


# Database initialization and session management
class DatabaseManager:
    """Manages database connection and operations"""

    def __init__(self, db_path=None):
        """Initialize database manager"""
        if db_path is None:
            # Default to a data directory in the project
            data_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'data')
            os.makedirs(data_dir, exist_ok=True)
            db_path = os.path.join(data_dir, 'hardening_tool.db')

        self.db_path = db_path
        self.engine = create_engine(f'sqlite:///{db_path}', echo=False)
        self.Session = sessionmaker(bind=self.engine)

        # Create tables if they don't exist
        Base.metadata.create_all(self.engine)

    def get_session(self):
        """Get a new database session"""
        return self.Session()

    def add_scan(self, scan_data):
        """Add a new scan to the database"""
        session = self.get_session()
        try:
            # Import risk scorer here to avoid circular imports
            from modules.risk_scoring import RiskScorer
            risk_scorer = RiskScorer()

            # Calculate risk scores if findings are present
            findings = scan_data.get('findings', [])
            if findings:
                overall_risk = risk_scorer.calculate_overall_risk(findings)
            else:
                overall_risk = {
                    'overall_score': 0.0,
                    'risk_level': 'None',
                    'risk_distribution': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
                }

            scan = Scan(
                scan_id=scan_data.get('scan_id'),
                scan_type=scan_data.get('scan_type', 'full'),
                status=scan_data.get('status', 'completed'),
                total_vulnerabilities=scan_data.get('totalVulnerabilities', 0),
                compliance_score=scan_data.get('complianceScore', 0.0),
                critical_issues=scan_data.get('criticalIssues', 0),
                warnings=scan_data.get('warnings', 0),
                overall_risk_score=overall_risk['overall_score'],
                risk_level=overall_risk['risk_level'],
                risk_distribution=overall_risk['risk_distribution'],
                system_info=scan_data.get('system_info')
            )
            session.add(scan)
            session.commit()

            # Add vulnerabilities with risk scores
            if findings:
                for finding in findings:
                    # Calculate risk score for this vulnerability
                    risk_data = risk_scorer.calculate_risk_score(finding)

                    vuln = Vulnerability(
                        scan_id=scan.id,
                        category=finding.get('category'),
                        severity=finding.get('severity'),
                        description=finding.get('description'),
                        status=finding.get('status', 'Open'),
                        recommendation=finding.get('recommendation'),
                        risk_score=risk_data['risk_score'],
                        risk_level=risk_data['risk_level'],
                        risk_factors=risk_data['factors']
                    )
                    session.add(vuln)
                session.commit()

            scan_dict = scan.to_dict()
            session.close()
            return scan_dict
        except Exception as e:
            session.rollback()
            session.close()
            raise e

    def add_hardening_session(self, session_data):
        """Add a new hardening session to the database"""
        session = self.get_session()
        try:
            hardening = HardeningSession(
                operation_id=session_data.get('operation_id'),
                policy=session_data.get('policy'),
                dry_run=1 if session_data.get('dry_run', True) else 0,
                status=session_data.get('status', 'completed'),
                changes_applied=session_data.get('changes_applied', 0),
                changes=session_data.get('changes'),
                related_scan_id=session_data.get('related_scan_id')
            )
            session.add(hardening)
            session.commit()

            hardening_dict = hardening.to_dict()
            session.close()
            return hardening_dict
        except Exception as e:
            session.rollback()
            session.close()
            raise e

    def get_scan_history(self, limit=None, offset=0):
        """Get scan history"""
        session = self.get_session()
        try:
            query = session.query(Scan).order_by(Scan.timestamp.desc())
            if limit:
                query = query.limit(limit).offset(offset)
            scans = query.all()
            result = [scan.to_dict() for scan in scans]
            session.close()
            return result
        except Exception as e:
            session.close()
            raise e

    def get_scan_by_id(self, scan_id):
        """Get a specific scan with all vulnerabilities"""
        session = self.get_session()
        try:
            scan = session.query(Scan).filter_by(scan_id=scan_id).first()
            if scan:
                scan_dict = scan.to_dict()
                scan_dict['findings'] = [vuln.to_dict() for vuln in scan.vulnerabilities]
                session.close()
                return scan_dict
            session.close()
            return None
        except Exception as e:
            session.close()
            raise e

    def get_hardening_history(self, limit=None, offset=0):
        """Get hardening session history"""
        session = self.get_session()
        try:
            query = session.query(HardeningSession).order_by(HardeningSession.timestamp.desc())
            if limit:
                query = query.limit(limit).offset(offset)
            sessions = query.all()
            result = [s.to_dict() for s in sessions]
            session.close()
            return result
        except Exception as e:
            session.close()
            raise e

    def get_vulnerability_trends(self, days=30):
        """Get vulnerability trends over time"""
        session = self.get_session()
        try:
            from datetime import timedelta
            cutoff_date = datetime.now() - timedelta(days=days)

            scans = session.query(Scan).filter(Scan.timestamp >= cutoff_date).order_by(Scan.timestamp).all()

            trends = {
                'dates': [],
                'total_vulnerabilities': [],
                'critical_issues': [],
                'compliance_scores': []
            }

            for scan in scans:
                trends['dates'].append(scan.timestamp.isoformat())
                trends['total_vulnerabilities'].append(scan.total_vulnerabilities)
                trends['critical_issues'].append(scan.critical_issues)
                trends['compliance_scores'].append(scan.compliance_score)

            session.close()
            return trends
        except Exception as e:
            session.close()
            raise e

    def get_statistics(self):
        """Get overall statistics"""
        session = self.get_session()
        try:
            total_scans = session.query(Scan).count()
            total_hardening_sessions = session.query(HardeningSession).count()

            # Get latest scan
            latest_scan = session.query(Scan).order_by(Scan.timestamp.desc()).first()

            stats = {
                'total_scans': total_scans,
                'total_hardening_sessions': total_hardening_sessions,
                'latest_scan': latest_scan.to_dict() if latest_scan else None
            }

            session.close()
            return stats
        except Exception as e:
            session.close()
            raise e

    def get_risk_trends(self, days=30):
        """Get risk score trends over time"""
        session = self.get_session()
        try:
            from datetime import timedelta
            cutoff_date = datetime.now() - timedelta(days=days)

            scans = session.query(Scan).filter(Scan.timestamp >= cutoff_date).order_by(Scan.timestamp).all()

            trends = {
                'dates': [],
                'overall_risk_scores': [],
                'risk_levels': [],
                'risk_distributions': []
            }

            for scan in scans:
                trends['dates'].append(scan.timestamp.isoformat())
                trends['overall_risk_scores'].append(scan.overall_risk_score or 0.0)
                trends['risk_levels'].append(scan.risk_level or 'Low')
                trends['risk_distributions'].append(scan.risk_distribution or {})

            session.close()
            return trends
        except Exception as e:
            session.close()
            raise e

    def get_risk_distribution(self):
        """Get current risk distribution across all open vulnerabilities"""
        session = self.get_session()
        try:
            # Get latest scan
            latest_scan = session.query(Scan).order_by(Scan.timestamp.desc()).first()

            if latest_scan and latest_scan.risk_distribution:
                distribution = latest_scan.risk_distribution
            else:
                distribution = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}

            session.close()
            return distribution
        except Exception as e:
            session.close()
            raise e

    def get_high_risk_vulnerabilities(self, limit=10):
        """Get highest risk vulnerabilities from latest scan"""
        session = self.get_session()
        try:
            # Get latest scan
            latest_scan = session.query(Scan).order_by(Scan.timestamp.desc()).first()

            if not latest_scan:
                session.close()
                return []

            # Get vulnerabilities ordered by risk score
            vulns = session.query(Vulnerability).filter(
                Vulnerability.scan_id == latest_scan.id
            ).order_by(Vulnerability.risk_score.desc()).limit(limit).all()

            result = [v.to_dict() for v in vulns]
            session.close()
            return result
        except Exception as e:
            session.close()
            raise e

    def add_remediation_execution(self, execution_data):
        """Add a new remediation execution to the database"""
        session = self.get_session()
        try:
            execution = RemediationExecution(
                execution_id=execution_data.get('execution_id'),
                playbook_id=execution_data.get('playbook_id'),
                playbook_name=execution_data.get('playbook_name'),
                vulnerability_id=execution_data.get('vulnerability_id'),
                status=execution_data.get('status', 'pending'),
                steps_completed=execution_data.get('steps_completed', 0),
                total_steps=execution_data.get('total_steps', 0),
                execution_time_seconds=execution_data.get('execution_time_seconds'),
                validation_passed=1 if execution_data.get('validation_passed', False) else 0,
                validation_results=execution_data.get('validation_results'),
                before_state=execution_data.get('before_state'),
                after_state=execution_data.get('after_state'),
                errors=execution_data.get('errors'),
                warnings=execution_data.get('warnings'),
                risk_score_before=execution_data.get('risk_score_before'),
                risk_score_after=execution_data.get('risk_score_after'),
                risk_reduction=execution_data.get('risk_reduction')
            )
            session.add(execution)
            session.commit()

            execution_dict = execution.to_dict()
            session.close()
            return execution_dict
        except Exception as e:
            session.rollback()
            session.close()
            raise e

    def get_remediation_history(self, limit=None, offset=0):
        """Get remediation execution history"""
        session = self.get_session()
        try:
            query = session.query(RemediationExecution).order_by(RemediationExecution.timestamp.desc())
            if limit:
                query = query.limit(limit).offset(offset)
            executions = query.all()
            result = [ex.to_dict() for ex in executions]
            session.close()
            return result
        except Exception as e:
            session.close()
            raise e

    def get_remediation_metrics(self):
        """Get remediation success metrics and statistics"""
        session = self.get_session()
        try:
            total_executions = session.query(RemediationExecution).count()

            # Get completed executions
            completed = session.query(RemediationExecution).filter(
                RemediationExecution.status == 'completed'
            ).count()

            # Get failed executions
            failed = session.query(RemediationExecution).filter(
                RemediationExecution.status == 'failed'
            ).count()

            # Get validation passed
            validation_passed = session.query(RemediationExecution).filter(
                RemediationExecution.validation_passed == 1
            ).count()

            # Calculate success rate
            success_rate = (validation_passed / total_executions * 100) if total_executions > 0 else 0

            # Get average execution time
            avg_time_result = session.query(RemediationExecution).filter(
                RemediationExecution.execution_time_seconds.isnot(None)
            ).all()

            avg_execution_time = 0
            if avg_time_result:
                times = [ex.execution_time_seconds for ex in avg_time_result if ex.execution_time_seconds]
                avg_execution_time = sum(times) / len(times) if times else 0

            # Get total risk reduction
            risk_reduction_result = session.query(RemediationExecution).filter(
                RemediationExecution.risk_reduction.isnot(None)
            ).all()

            total_risk_reduction = 0
            if risk_reduction_result:
                reductions = [ex.risk_reduction for ex in risk_reduction_result if ex.risk_reduction]
                total_risk_reduction = sum(reductions) if reductions else 0

            # Get most used playbooks
            from sqlalchemy import func
            playbook_usage = session.query(
                RemediationExecution.playbook_id,
                RemediationExecution.playbook_name,
                func.count(RemediationExecution.id).label('count')
            ).group_by(
                RemediationExecution.playbook_id,
                RemediationExecution.playbook_name
            ).order_by(func.count(RemediationExecution.id).desc()).limit(5).all()

            most_used_playbooks = [
                {
                    'playbook_id': p[0],
                    'playbook_name': p[1],
                    'usage_count': p[2]
                } for p in playbook_usage
            ]

            # Get recent executions
            recent = session.query(RemediationExecution).order_by(
                RemediationExecution.timestamp.desc()
            ).limit(10).all()

            metrics = {
                'total_executions': total_executions,
                'completed': completed,
                'failed': failed,
                'validation_passed': validation_passed,
                'success_rate': round(success_rate, 1),
                'average_execution_time_seconds': round(avg_execution_time, 1),
                'total_risk_reduction': round(total_risk_reduction, 1),
                'most_used_playbooks': most_used_playbooks,
                'recent_executions': [ex.to_dict() for ex in recent]
            }

            session.close()
            return metrics
        except Exception as e:
            session.close()
            raise e
