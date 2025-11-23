# Advanced Features Documentation

## Overview

This document covers the advanced enterprise features added to the System Hardening Tool:

1. **Real-time Monitoring Dashboard**
2. **Automated Remediation Engine**
3. **Compliance Frameworks Support**

---

## 1. Real-time Monitoring Dashboard

### Features

- **Live System Health Metrics**: CPU, memory, disk, network monitoring
- **Threat Detection**: Automatic detection of security threats
- **Alert System**: Real-time alerts with customizable thresholds
- **Historical Data**: Track metrics over time

### Module: `realtime_monitor.py`

#### Key Classes

**`RealtimeMonitor`**
- Continuous system monitoring
- Threat detection based on configurable thresholds
- Alert callbacks for custom notification handling
- Metrics history storage

#### Usage Example

```python
from modules.realtime_monitor import RealtimeMonitor

# Initialize monitor
monitor = RealtimeMonitor()

# Register alert callback
def handle_alert(threat):
    print(f"ALERT: {threat['message']}")
    # Send notification, email, etc.

monitor.register_alert_callback(handle_alert)

# Start monitoring (every 5 seconds)
monitor.start_monitoring(interval=5)

# Get current metrics
metrics = monitor.get_current_metrics()
print(f"CPU: {metrics['cpu']['percent']}%")
print(f"Memory: {metrics['memory']['percent']}%")
print(f"Disk: {metrics['disk']['percent']}%")

# Get system status
status = monitor.get_system_status()
print(f"Overall status: {status['status']}")

# Stop monitoring
monitor.stop_monitoring()
```

#### Configurable Thresholds

```python
# Set custom thresholds for threat detection
monitor.set_threshold('cpu_percent', 85)
monitor.set_threshold('memory_percent', 80)
monitor.set_threshold('disk_percent', 90)
```

#### Metrics Structure

```json
{
  "timestamp": "2025-11-23T12:00:00",
  "cpu": {
    "percent": 45.2,
    "count": 8,
    "status": "normal"
  },
  "memory": {
    "total": 16777216000,
    "available": 8388608000,
    "percent": 50.0,
    "used": 8388608000,
    "status": "normal"
  },
  "disk": {
    "total": 500000000000,
    "used": 250000000000,
    "free": 250000000000,
    "percent": 50.0,
    "status": "normal"
  },
  "network": {
    "bytes_sent": 1000000,
    "bytes_recv": 2000000,
    "packets_sent": 5000,
    "packets_recv": 10000,
    "errors": 0,
    "drops": 0
  },
  "processes": {
    "count": 250,
    "open_ports": 25
  },
  "uptime": {
    "seconds": 86400,
    "formatted": "1d 0h 0m",
    "boot_time": "2025-11-22T12:00:00"
  }
}
```

---

## 2. Automated Remediation Engine

### Features

- **Auto-fix Common Vulnerabilities**: Automatically apply security fixes
- **Checkpoint System**: Create system snapshots before changes
- **Rollback on Failure**: Automatically revert failed changes
- **Approval Workflows**: Require approval for critical changes
- **Maintenance Windows**: Schedule fixes during off-hours

### Module: `auto_remediation.py`

#### Key Classes

**`AutoRemediation`**
- Automated vulnerability fixing
- Checkpoint creation and rollback
- Approval workflow management
- Maintenance window scheduling

#### Supported Auto-fixes

1. **SSH Configuration Hardening**
   - Disable root login
   - Disable password authentication
   - Reduce max auth tries
   - Disable X11 forwarding

2. **Password Policy Strengthening**
   - Minimum password length
   - Character complexity requirements

3. **System Updates**
   - Apply security patches
   - Update packages

4. **File Permissions**
   - Fix `/etc/passwd`, `/etc/shadow`
   - Secure critical system files

5. **Service Management**
   - Disable unnecessary services
   - Stop unused daemons

6. **Network Security**
   - Disable IP forwarding
   - Configure firewall

#### Usage Examples

**Basic Auto-fix:**

```python
from modules.auto_remediation import AutoRemediation

remediation = AutoRemediation()

# Auto-fix a vulnerability (requires approval for critical)
result = remediation.auto_fix_vulnerability(
    vulnerability_id='weak_ssh_config',
    severity='high',
    requires_approval=True
)

print(f"Status: {result['status']}")
print(f"Checkpoint ID: {result.get('checkpoint_id')}")
```

**Manual Checkpoint & Rollback:**

```python
# Create checkpoint before manual changes
checkpoint = remediation.create_checkpoint("Before manual config change")
print(f"Checkpoint ID: {checkpoint['checkpoint_id']}")

# ... make changes ...

# Rollback if needed
if something_went_wrong:
    rollback_result = remediation.rollback(checkpoint['checkpoint_id'])
    print(f"Rollback status: {rollback_result['status']}")
```

**Approval Workflow:**

```python
# Get pending approvals
pending = remediation.get_pending_approvals()
for approval in pending:
    print(f"ID: {approval['id']}")
    print(f"Vulnerability: {approval['vulnerability_id']}")
    print(f"Severity: {approval['severity']}")

# Approve a remediation
result = remediation.approve_remediation(remediation_id='remediation_20251123_120000')

# Reject a remediation
result = remediation.reject_remediation(
    remediation_id='remediation_20251123_120000',
    reason='Not during business hours'
)
```

**Maintenance Windows:**

```python
from datetime import datetime, timedelta

# Schedule maintenance window
start_time = datetime.now() + timedelta(days=1)  # Tomorrow
window = remediation.schedule_maintenance_window(
    start_time=start_time,
    duration_hours=4,
    description='Monthly security patching'
)

print(f"Window ID: {window['id']}")
print(f"Start: {window['start_time']}")
print(f"End: {window['end_time']}")
```

---

## 3. Compliance Frameworks

### Supported Frameworks

1. **CIS Benchmarks** (Center for Internet Security)
2. **NIST 800-53** (National Institute of Standards and Technology)
3. **PCI-DSS** (Payment Card Industry Data Security Standard)
4. **HIPAA** (Health Insurance Portability and Accountability Act)
5. **SOC 2** (Service Organization Control 2)

### Module: `compliance_frameworks.py`

#### Key Classes

**`ComplianceChecker`**
- Multi-framework compliance checking
- Automated control validation
- Scoring and reporting
- Compliance status tracking

#### Usage Examples

**CIS Benchmarks:**

```python
from modules.compliance_frameworks import ComplianceChecker

checker = ComplianceChecker()

# Check CIS Benchmarks Level 1
cis_result = checker.check_cis_benchmarks(level=1)

print(f"Score: {cis_result['score']}%")
print(f"Status: {cis_result['compliance_status']}")
print(f"Passed: {cis_result['passed']}/{cis_result['total_checks']}")

# View specific checks
for category, checks in cis_result['checks'].items():
    print(f"\n{category}:")
    for check in checks:
        print(f"  [{check['status']}] {check['description']}")
```

**NIST 800-53:**

```python
# Check NIST 800-53 compliance
nist_result = checker.check_nist_800_53()

print(f"Score: {nist_result['score']}%")
print(f"Total Controls: {nist_result['total_controls']}")

# View control families
for family, controls in nist_result['controls'].items():
    print(f"\n{family} Family:")
    for control in controls:
        print(f"  {control['description']}: {control['status']}")
```

**PCI-DSS:**

```python
# Check PCI-DSS compliance
pci_result = checker.check_pci_dss()

print(f"PCI-DSS Score: {pci_result['score']}%")
print(f"Compliance Status: {pci_result['compliance_status']}")

# PCI-DSS requires 90%+ for compliance
if pci_result['score'] >= 90:
    print("✓ PCI-DSS Compliant")
else:
    print("✗ Not Compliant - Remediation Required")
```

**HIPAA:**

```python
# Check HIPAA compliance
hipaa_result = checker.check_hipaa()

print(f"HIPAA Score: {hipaa_result['score']}%")

# View safeguards
for safeguard_type, safeguards in hipaa_result['safeguards'].items():
    print(f"\n{safeguard_type.capitalize()} Safeguards:")
    for safeguard in safeguards:
        print(f"  {safeguard['description']}: {safeguard['status']}")
```

**SOC 2:**

```python
# Check SOC 2 compliance
soc2_result = checker.check_soc2()

print(f"SOC 2 Score: {soc2_result['score']}%")

# View Trust Service Criteria
for criterion, checks in soc2_result['criteria'].items():
    print(f"\n{criterion.replace('_', ' ').title()}:")
    for check in checks:
        print(f"  {check['description']}: {check['status']}")
```

**All Frameworks:**

```python
# Check all frameworks at once
all_results = checker.check_all_frameworks()

summary = all_results['summary']
print(f"Average Score: {summary['average_score']}%")
print(f"Frameworks Checked: {summary['frameworks_checked']}")
print(f"Compliant: {summary['compliant_frameworks']}/{summary['frameworks_checked']}")

# Individual framework results
print(f"\nCIS: {all_results['cis']['score']}%")
print(f"NIST: {all_results['nist']['score']}%")
print(f"PCI-DSS: {all_results['pci_dss']['score']}%")
print(f"HIPAA: {all_results['hipaa']['score']}%")
print(f"SOC 2: {all_results['soc2']['score']}%")
```

---

## API Integration (Coming Next)

The following API endpoints will be added:

### Real-time Monitoring
- `GET /api/monitoring/status` - Get current system status
- `GET /api/monitoring/metrics` - Get current metrics
- `GET /api/monitoring/history` - Get metrics history
- `POST /api/monitoring/start` - Start monitoring
- `POST /api/monitoring/stop` - Stop monitoring
- `WebSocket /api/monitoring/stream` - Real-time metric stream

### Automated Remediation
- `POST /api/remediation/auto-fix` - Auto-fix vulnerability
- `POST /api/remediation/checkpoint` - Create checkpoint
- `POST /api/remediation/rollback` - Rollback to checkpoint
- `GET /api/remediation/pending` - Get pending approvals
- `POST /api/remediation/approve/{id}` - Approve remediation
- `POST /api/remediation/reject/{id}` - Reject remediation
- `GET /api/remediation/history` - Get remediation history

### Compliance
- `GET /api/compliance/cis` - Check CIS Benchmarks
- `GET /api/compliance/nist` - Check NIST 800-53
- `GET /api/compliance/pci-dss` - Check PCI-DSS
- `GET /api/compliance/hipaa` - Check HIPAA
- `GET /api/compliance/soc2` - Check SOC 2
- `GET /api/compliance/all` - Check all frameworks

---

## Security Considerations

### Permissions
- Automated remediation requires root/sudo access
- Some checks may require elevated privileges
- Implement proper authentication and authorization

### Rollback Safety
- Always create checkpoints before major changes
- Test rollback procedures in non-production
- Monitor for rollback failures

### Approval Workflows
- Require approval for critical severity fixes
- Log all approvals and rejections
- Implement multi-person approval for production

### Maintenance Windows
- Schedule fixes during low-traffic periods
- Notify stakeholders before changes
- Have rollback plan ready

---

## Testing

Each module includes a test section that can be run independently:

```bash
# Test real-time monitor
python modules/realtime_monitor.py

# Test compliance checker
python modules/compliance_frameworks.py

# Test auto-remediation
python modules/auto_remediation.py
```

---

## Future Enhancements

1. **Machine Learning Threat Detection**
   - Anomaly detection
   - Predictive alerts

2. **Integration with SIEM Systems**
   - Splunk, ELK Stack
   - Real-time log forwarding

3. **Automated Compliance Reporting**
   - Generate compliance reports
   - Track compliance over time

4. **Advanced Rollback**
   - Database rollback support
   - Application state rollback

5. **Multi-system Management**
   - Manage multiple servers
   - Centralized dashboard

---

## Support

For issues or questions:
- Check logs in `logs/app.log`
- Review module documentation
- Test individual modules with included examples

## License

See project LICENSE file for details.
