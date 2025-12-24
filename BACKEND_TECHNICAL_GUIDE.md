# Backend Technical Guide
## IronGuard OS Security Hardening Tool

**Version:** 2.0.0
**Last Updated:** December 2025
**Author:** Development Team

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Backend Components](#backend-components)
3. [API Endpoints Reference](#api-endpoints-reference)
4. [Security Scanning System](#security-scanning-system)
5. [Data Flow Diagrams](#data-flow-diagrams)
6. [Function Documentation](#function-documentation)
7. [Database Schema](#database-schema)
8. [Error Handling](#error-handling)
9. [Performance Considerations](#performance-considerations)

---

## Architecture Overview

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         FRONTEND (React)                         │
│                      Port 3000 (localhost)                       │
└────────────────────────────┬────────────────────────────────────┘
                             │ HTTP/JSON
                             │ REST API Calls
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                    FLASK API SERVER (app.py)                     │
│                      Port 5000 (localhost)                       │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ Request Router: @app.route decorators                    │   │
│  │ - /api/health, /api/scan, /api/report, etc.             │   │
│  └──────────────────────────────────────────────────────────┘   │
└────────────────────────────┬────────────────────────────────────┘
                             │
         ┌───────────────────┼───────────────────┐
         │                   │                   │
         ▼                   ▼                   ▼
┌──────────────────┐ ┌──────────────┐ ┌─────────────────┐
│  Scanner Module  │ │  Risk Scorer │ │ Report Generator│
│  (scanner.py)    │ │  Module      │ │   (report       │
│                  │ │              │ │   _generator.py)│
└────────┬─────────┘ └──────────────┘ └─────────────────┘
         │
         ▼
┌──────────────────────────────────────────┐
│   Platform-Specific Checkers             │
│  ┌────────────────────────────────────┐  │
│  │  LinuxChecker (linux_checker.py)   │  │
│  │  - SSH Configuration               │  │
│  │  - Password Policies               │  │
│  │  - Firewall Status                 │  │
│  │  - File Permissions                │  │
│  │  - Service Auditing                │  │
│  └────────────────────────────────────┘  │
│  ┌────────────────────────────────────┐  │
│  │  WindowsChecker (windows_checker)  │  │
│  └────────────────────────────────────┘  │
│  ┌────────────────────────────────────┐  │
│  │  MacOSChecker (macos_checker)      │  │
│  └────────────────────────────────────┘  │
└──────────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────┐
│     SQLite Database (hardening_tool.db)  │
│  - scans table                           │
│  - vulnerabilities table                 │
│  - hardening_sessions table              │
│  - remediation_executions table          │
└──────────────────────────────────────────┘
```

### Technology Stack

**Core Framework:**
- Flask 3.0.0 - Lightweight WSGI web application framework
- Flask-CORS 4.0.0 - Cross-Origin Resource Sharing support

**Database:**
- SQLAlchemy 2.0.23 - ORM for database operations
- SQLite - Embedded database (production can use PostgreSQL)

**System Interaction:**
- psutil 5.9.6 - System and process monitoring
- subprocess - Execute system commands

**Report Generation:**
- weasyprint 62.3 - PDF generation from HTML
- Jinja2 3.1.6 - Template engine
- pandas 2.1.3 - Data manipulation
- openpyxl 3.1.2 - Excel file generation
- python-docx 1.1.0 - Word document generation

---

## Backend Components

### 1. Main Application (app.py)

**Purpose:** Flask application entry point, API endpoint definitions

**Key Responsibilities:**
- Initialize Flask app with CORS
- Load environment configuration
- Initialize Scanner with OS detection
- Initialize database models
- Define 40+ API endpoints
- Handle request/response lifecycle
- Error handling and logging

**Initialization Flow:**
```python
# 1. Load environment variables
load_dotenv()

# 2. Create Flask app
app = Flask(__name__)
CORS(app)

# 3. Detect operating system
system_detector = SystemDetector()
os_type = system_detector.detect_os_type()  # Returns: 'Linux', 'Windows', or 'Darwin'

# 4. Initialize scanner with detected OS
scanner = Scanner(os_type)

# 5. Initialize database
init_db()  # Creates tables if not exist

# 6. Initialize report generator
report_generator = ReportGenerator()

# 7. Initialize risk scorer
risk_scorer = RiskScorer()

# 8. Start Flask server
app.run(host='0.0.0.0', port=5000, debug=False)
```

### 2. Scanner Module (scanner.py)

**Purpose:** Orchestrate security scans across different operating systems

**Class Hierarchy:**

```python
# Enumerations
class ScanType(Enum):
    QUICK = "quick"        # Critical checks only (~30 seconds)
    FULL = "full"          # Comprehensive scan (~60-120 seconds)
    CUSTOM = "custom"      # User-defined categories
    COMPLIANCE = "compliance"  # Compliance framework focused

class Severity(Enum):
    CRITICAL = "critical"  # Immediate action required
    HIGH = "high"         # Action required soon
    MEDIUM = "medium"     # Should be addressed
    LOW = "low"           # Minor issue
    INFO = "info"         # Informational only

class ScanStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

# Data Classes
class Finding:
    """Represents a single security vulnerability"""
    - title: str
    - description: str
    - severity: Severity
    - category: str
    - remediation: str (step-by-step instructions)
    - references: List[str]
    - affected_item: str (file path, service name, etc.)
    - timestamp: str (ISO format)

class ScanResult:
    """Aggregates all findings from a scan"""
    - scan_id: str (e.g., "scan_linux_20251223_140530")
    - os_type: str
    - scan_type: ScanType
    - status: ScanStatus
    - findings: List[Finding]
    - start_time: str
    - end_time: str
    - duration_seconds: float
    - error_message: Optional[str]

# Main Scanner Class
class Scanner:
    """Orchestrates scans using platform-specific checkers"""

    def __init__(self, os_type: str):
        """
        Loads appropriate checker based on OS:
        - Linux → LinuxChecker
        - Windows → WindowsChecker
        - Darwin (macOS) → MacOSChecker
        """

    def scan(self, scan_type: str, options: Dict) -> ScanResult:
        """
        Main scanning entry point
        1. Generate unique scan_id
        2. Create ScanResult object
        3. Delegate to platform checker
        4. Aggregate findings
        5. Calculate duration
        6. Return results
        """
```

**Scan Workflow:**

```
User Request → Scanner.scan() → Platform Checker → Findings → ScanResult
                    ↓                    ↓
              Generate ID        Execute Checks
              Set Status         (SSH, Firewall, etc.)
              Start Timer              ↓
                    ↓            Return Findings List
              Create ScanResult        ↓
                    ↓            Add to ScanResult
              Delegate to              ↓
              Checker          Calculate Summary
                    ↓                   ↓
              Receive Findings   Mark Completed
                    ↓                   ↓
              Complete Scan      Return ScanResult
                    ↓
              Return to API
```

### 3. Linux Checker Module (linux_checker.py)

**Purpose:** Perform actual security checks on Linux systems

**Class Structure:**

```python
class LinuxChecker:
    """Performs security checks on Linux systems"""

    # Scan Methods (Public API)
    def quick_scan(options) -> List[Dict]:
        """Critical checks only (~30 seconds)"""
        - SSH root login check
        - Shadow file permissions
        - Firewall status

    def full_scan(options) -> List[Dict]:
        """Comprehensive scan (~60-120 seconds)"""
        - All SSH configuration checks
        - All password policy checks
        - Firewall status and rules
        - Critical file permissions
        - Unnecessary services

    def compliance_scan(options) -> List[Dict]:
        """Compliance framework checks"""
        - Currently same as full_scan
        - Future: CIS Benchmark specific

    def custom_scan(options) -> List[Dict]:
        """User-defined category checks"""
        - Only check specified categories

    # Check Methods (Private - Internal Use)

    # SSH Configuration Checks
    def _check_ssh_configuration() -> List[Dict]:
        """Check /etc/ssh/sshd_config file"""
        - Root login disabled
        - Password authentication settings
        - Protocol version
        - Port configuration

    def _check_ssh_root_login() -> List[Dict]:
        """Critical: Verify PermitRootLogin no"""

    # Password Policy Checks
    def _check_password_policies() -> List[Dict]:
        """Check /etc/login.defs and PAM"""
        - Maximum password age (PASS_MAX_DAYS)
        - Minimum password age (PASS_MIN_DAYS)
        - Minimum password length (PASS_MIN_LEN)
        - Password complexity requirements

    # Firewall Checks
    def _check_firewall_status() -> List[Dict]:
        """Check UFW or iptables status"""
        - Firewall enabled/disabled
        - Default policies

    def _check_firewall_rules() -> List[Dict]:
        """Analyze firewall rules"""
        - Open ports
        - Allowed services
        - Dangerous rules

    # File Permission Checks
    def _check_critical_file_permissions() -> List[Dict]:
        """Verify permissions on critical files"""
        - /etc/passwd (should be 644)
        - /etc/shadow (should be 640 or 600)
        - /etc/gshadow (should be 640 or 600)
        - /etc/group (should be 644)

    def _check_shadow_permissions() -> List[Dict]:
        """Critical: /etc/shadow permissions"""

    # Service Checks
    def _check_unnecessary_services() -> List[Dict]:
        """Check for running unnecessary services"""
        - telnet (insecure, use SSH)
        - ftp (insecure, use SFTP)
        - rsh (insecure)
        - NFS (if not needed)

    # Remediation Instructions
    def _get_detailed_remediation(check_name, affected_item, **kwargs) -> str:
        """
        Returns step-by-step remediation instructions

        Format:
        STEP-BY-STEP FIX:
        1. Backup command
           Explanation
        2. Edit command
           Explanation
        3. Verification command
           Explanation

        ⚠️ WARNING: Potential impacts

        VERIFICATION:
        - How to verify fix worked

        ADDITIONAL NOTES:
        - Important considerations
        """
```

**Check Execution Example:**

```python
def _check_ssh_root_login(self) -> List[Dict]:
    """
    Check if root login via SSH is disabled.
    """
    findings = []
    config_file = "/etc/ssh/sshd_config"

    # 1. Check if file exists
    if not os.path.exists(config_file):
        findings.append({
            "category": "SSH Configuration",
            "severity": "Info",
            "title": "SSH Configuration File Not Found",
            "description": f"The SSH configuration file {config_file} was not found.",
            "recommendation": "Install and configure OpenSSH server.",
            "affected_item": config_file,
            "timestamp": datetime.now().isoformat(),
            "references": ["https://www.openssh.com/"]
        })
        return findings

    # 2. Read and parse file
    try:
        with open(config_file, 'r') as f:
            content = f.read()
    except PermissionError:
        findings.append({
            "category": "SSH Configuration",
            "severity": "Medium",
            "title": "Cannot Read SSH Configuration",
            "description": "Permission denied reading SSH config",
            "recommendation": "Run scan with sudo privileges",
            "affected_item": config_file,
            "timestamp": datetime.now().isoformat()
        })
        return findings

    # 3. Check for PermitRootLogin setting
    permit_root_pattern = r'^\s*PermitRootLogin\s+(\S+)'
    matches = re.findall(permit_root_pattern, content, re.MULTILINE)

    # 4. Analyze results
    if matches:
        last_value = matches[-1].lower()
        if last_value != "no":
            findings.append({
                "category": "SSH Configuration",
                "severity": "Critical",
                "title": "Root Login via SSH Enabled",
                "description": f"PermitRootLogin is set to '{last_value}'. Root login should be disabled.",
                "recommendation": self._get_detailed_remediation("ssh_permit_root_login", config_file),
                "affected_item": config_file,
                "timestamp": datetime.now().isoformat(),
                "references": [
                    "https://www.ssh.com/academy/ssh/sshd_config",
                    "https://nvd.nist.gov/"
                ]
            })
    else:
        # PermitRootLogin not explicitly set (default may vary)
        findings.append({
            "category": "SSH Configuration",
            "severity": "High",
            "title": "Root Login Setting Not Configured",
            "description": "PermitRootLogin is not explicitly configured.",
            "recommendation": self._get_detailed_remediation("ssh_permit_root_login", config_file),
            "affected_item": config_file,
            "timestamp": datetime.now().isoformat()
        })

    return findings
```

### 4. System Detector Module (system_detector.py)

**Purpose:** Detect operating system type

```python
class SystemDetector:
    """Detect the operating system type"""

    def detect_os_type(self) -> str:
        """
        Returns: 'Linux', 'Windows', or 'Darwin' (macOS)

        Uses platform.system():
        - 'Linux' → 'Linux'
        - 'Windows' → 'Windows'
        - 'Darwin' → 'Darwin'
        """
        import platform
        return platform.system()
```

### 5. Risk Scoring Module (risk_scoring.py)

**Purpose:** Calculate risk scores for vulnerabilities

**Scoring Formula:**

```python
Risk Score = Base Score × Temporal Factor × Environmental Factor

Base Score (0-10):
    - CRITICAL: 9.0-10.0
    - HIGH: 7.0-8.9
    - MEDIUM: 4.0-6.9
    - LOW: 0.1-3.9
    - INFO: 0.0

Temporal Factor (0.9-1.0):
    - Considers: exploit availability, patch availability, vulnerability age

Environmental Factor (0.8-1.0):
    - Considers: system criticality, exposure level, data sensitivity
```

### 6. Report Generator Module (report_generator.py)

**Purpose:** Generate security reports in multiple formats

**Supported Formats:**
- PDF (weasyprint)
- HTML (Jinja2 templates)
- JSON (native)
- Markdown (custom formatting)
- CSV (pandas)
- Excel/XLSX (openpyxl)
- Word/DOCX (python-docx)

**Generation Flow:**

```
1. Compile Data
   ├─ Scan results
   ├─ Vulnerability summary
   ├─ Compliance scores
   └─ Charts data

2. Format-Specific Processing
   ├─ PDF: HTML → weasyprint → PDF
   ├─ HTML: Jinja2 template → HTML
   ├─ Excel: pandas DataFrame → openpyxl
   ├─ Word: python-docx Document
   └─ JSON/CSV/MD: Custom formatters

3. Save to File
   └─ reports/security_report_YYYYMMDD_HHMMSS.{ext}

4. Return File Path
```

---

## API Endpoints Reference

### Health & System Information

#### GET /api/health
**Purpose:** Check backend server health
**Authentication:** None
**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2025-12-23T14:05:30",
  "version": "2.0.0"
}
```

#### GET /api/system-info
**Purpose:** Get system information
**Response:**
```json
{
  "os": "Linux",
  "version": "Ubuntu 22.04",
  "hostname": "server01",
  "architecture": "x86_64",
  "cpu_count": 4,
  "memory_total": "8 GB"
}
```

### Security Scanning

#### POST /api/scan
**Purpose:** Execute a security scan
**Request Body:**
```json
{
  "type": "full",  // Options: quick, full, custom, compliance
  "options": {
    "categories": ["ssh", "passwords", "firewall"],  // For custom scans
    "depth": "comprehensive"  // Optional
  }
}
```

**Response:**
```json
{
  "scan_id": "scan_linux_20251223_140530",
  "scan_type": "full",
  "timestamp": "2025-12-23T14:05:30",
  "status": "completed",
  "duration_seconds": 45.2,
  "totalVulnerabilities": 12,
  "complianceScore": 78.5,
  "criticalIssues": 2,
  "highIssues": 4,
  "mediumIssues": 5,
  "lowIssues": 1,
  "findings": [
    {
      "id": 1,
      "category": "User Accounts",
      "severity": "Critical",
      "title": "Weak password policy detected",
      "description": "System password policy does not meet security requirements...",
      "recommendation": "STEP-BY-STEP FIX:\n1. Edit /etc/security/pwquality.conf...",
      "affected_item": "/etc/security/pwquality.conf",
      "timestamp": "2025-12-23T14:05:35",
      "references": ["https://example.com/password-security"]
    }
  ]
}
```

**Processing Flow:**
```
1. API receives POST /api/scan
   ↓
2. app.py: @app.route('/api/scan') handler
   ↓
3. Extract scan_type and options from request.json
   ↓
4. scanner.scan(scan_type=scan_type, options=options)
   ↓
5. Scanner generates scan_id (e.g., "scan_linux_20251223_140530")
   ↓
6. Scanner creates ScanResult object
   ↓
7. Scanner delegates to LinuxChecker based on scan_type:
   - quick → quick_scan()
   - full → full_scan()
   - compliance → compliance_scan()
   - custom → custom_scan(options)
   ↓
8. LinuxChecker executes checks:
   - _check_ssh_configuration()
   - _check_password_policies()
   - _check_firewall_status()
   - _check_critical_file_permissions()
   - _check_unnecessary_services()
   ↓
9. Each check method:
   a. Reads config files or executes commands
   b. Analyzes results
   c. Creates Finding objects for issues
   d. Adds detailed remediation instructions
   e. Returns List[Dict] of findings
   ↓
10. Scanner aggregates all findings into ScanResult
   ↓
11. Scanner marks scan as completed, calculates duration
   ↓
12. app.py receives ScanResult
   ↓
13. RiskScorer calculates risk scores for findings
   ↓
14. Database saves scan to SQLite (scans + vulnerabilities tables)
   ↓
15. app.py converts ScanResult to JSON
   ↓
16. Return JSON response to frontend
```

### Report Generation

#### POST /api/report
**Purpose:** Generate security report with real-time scanning
**Request Body:**
```json
{
  "format": "pdf",  // pdf, html, json, markdown, csv, excel, docx
  "scan_type": "full",  // If no scan_results provided, auto-scan
  "scan_results": { /* Optional: use existing scan data */ },
  "title": "Security Compliance Report"
}
```

**Response:** Binary file download (PDF, Excel, etc.) or JSON

**Processing Flow:**
```
1. API receives POST /api/report
   ↓
2. Check if scan_results provided
   ↓
3. If NO scan data:
   a. Auto-execute scan: scanner.scan(scan_type)
   b. Use scan results
   ↓
4. report_generator.generate_report(
     scan_results=results,
     report_format=format,
     title=title
   )
   ↓
5. Report generator:
   a. Compiles data (findings, summary, charts)
   b. Format-specific generation:
      - PDF: HTML template → weasyprint
      - Excel: pandas DataFrame → openpyxl
      - Word: python-docx
   c. Saves to reports/ directory
   ↓
6. Return file as send_file() with proper MIME type
```

### Hardening & Remediation

#### POST /api/harden
**Purpose:** Apply security hardening
**Request Body:**
```json
{
  "rules": ["ssh_disable_root", "enable_firewall"],
  "auto_approve": false
}
```

#### POST /api/remediation/auto-fix
**Purpose:** Automatically fix vulnerabilities
**Request Body:**
```json
{
  "vulnerability_ids": [1, 2, 3],
  "create_checkpoint": true
}
```

### Historical Data

#### GET /api/history/scans
**Purpose:** Get scan history
**Query Parameters:** `?limit=20&offset=0`

#### GET /api/history/scans/{scan_id}
**Purpose:** Get specific scan details

#### GET /api/history/trends
**Purpose:** Get vulnerability trends over time
**Query Parameters:** `?days=30`

### Risk Analysis

#### GET /api/risk/trends
**Purpose:** Get risk score trends

#### GET /api/risk/distribution
**Purpose:** Get risk distribution by category

#### GET /api/risk/high-risk
**Purpose:** Get high-risk vulnerabilities
**Query Parameters:** `?limit=10`

### Compliance

#### GET /api/compliance/cis
**Purpose:** Check CIS Benchmark compliance

#### GET /api/compliance/pci-dss
**Purpose:** Check PCI-DSS compliance

#### GET /api/compliance/all
**Purpose:** Check all compliance frameworks

### Monitoring

#### GET /api/monitoring/metrics
**Purpose:** Get real-time system metrics
**Response:**
```json
{
  "cpu_percent": 45.2,
  "memory_percent": 62.8,
  "disk_percent": 38.5,
  "network_io": {
    "bytes_sent": 1024000,
    "bytes_recv": 2048000
  }
}
```

#### POST /api/monitoring/start
**Purpose:** Start real-time monitoring

#### POST /api/monitoring/stop
**Purpose:** Stop monitoring

---

## Security Scanning System

### Scan Types Explained

#### 1. Quick Scan (~30 seconds)
**Purpose:** Rapid assessment of critical vulnerabilities
**Checks:**
- SSH root login enabled
- Shadow file permissions
- Firewall status
- World-writable files (top 10)

**Use Case:** Daily security checks, CI/CD pipelines

#### 2. Full Scan (~60-120 seconds)
**Purpose:** Comprehensive security assessment
**Checks:**
- All SSH configuration issues
- All password policy issues
- Firewall status and rules
- Critical file permissions
- Unnecessary services
- SUID/SGID files
- Open ports

**Use Case:** Weekly security audits, compliance assessments

#### 3. Compliance Scan
**Purpose:** Framework-specific compliance checking
**Checks:** CIS Benchmarks, PCI-DSS, HIPAA, SOC 2 requirements
**Use Case:** Regulatory compliance, audit preparation

#### 4. Custom Scan
**Purpose:** User-defined category scanning
**Example:**
```json
{
  "type": "custom",
  "options": {
    "categories": ["ssh", "firewall"],
    "depth": "deep"
  }
}
```

### Finding Structure

Each finding contains:

```python
{
    "id": 1,                           # Auto-incremented ID
    "category": "SSH Configuration",   # Logical grouping
    "severity": "Critical",            # CRITICAL/HIGH/MEDIUM/LOW/INFO
    "title": "Root Login Enabled",     # Brief description
    "description": "Detailed explanation of the issue and its risks",
    "recommendation": "STEP-BY-STEP FIX:\n1. ...\n2. ...",  # Remediation
    "affected_item": "/etc/ssh/sshd_config",  # Specific location
    "timestamp": "2025-12-23T14:05:35Z",      # Discovery time
    "references": [                    # External resources
        "https://nvd.nist.gov/...",
        "https://cis.org/..."
    ]
}
```

### Remediation Instructions Format

```
STEP-BY-STEP FIX:
1. [Action Step]
   [Command to execute]
   [Explanation of what this does]

2. [Next Action Step]
   [Command to execute]
   [Explanation]

⚠️ WARNING:
[Potential impacts of this fix]

VERIFICATION:
[How to verify the fix worked]
[Expected output]

ADDITIONAL NOTES:
[Important considerations]
[Best practices]
[Links to documentation]
```

### Example Remediation

```
STEP-BY-STEP FIX:
1. Backup the SSH configuration file:
   sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup
   This creates a backup in case you need to revert changes.

2. Edit the SSH configuration:
   sudo nano /etc/ssh/sshd_config
   OR
   sudo vi /etc/ssh/sshd_config

3. Find the line containing 'PermitRootLogin' and change it to:
   PermitRootLogin no

   If the line doesn't exist, add it.

4. Save the file:
   - In nano: Ctrl+X, then Y, then Enter
   - In vi: Press Esc, type :wq, press Enter

5. Test the configuration for syntax errors:
   sudo sshd -t

   If no errors are shown, the configuration is valid.

6. Restart the SSH service to apply changes:
   sudo systemctl restart sshd
   OR
   sudo service ssh restart

⚠️ WARNING:
- Ensure you have an alternative access method before restarting SSH
- If connected via SSH, you may lose connection briefly
- Test access before closing current session

VERIFICATION:
1. Check the configuration:
   grep "^PermitRootLogin" /etc/ssh/sshd_config

   Expected output: PermitRootLogin no

2. Verify SSH service is running:
   sudo systemctl status sshd

   Should show "active (running)"

3. Test from another terminal:
   ssh root@localhost

   Should be denied (this is expected and correct)

ADDITIONAL NOTES:
- Instead of using root, create a regular user with sudo privileges
- Consider using SSH keys instead of passwords
- Review other SSH hardening options: disable password auth, change port
- Reference: https://www.ssh.com/academy/ssh/sshd_config
```

---

## Data Flow Diagrams

### Complete Scan Request Flow

```
┌──────────┐
│ Frontend │ 1. User clicks "Start Security Scan"
└────┬─────┘
     │
     │ 2. POST /api/scan
     │    { type: "full" }
     ▼
┌─────────────────────────────────────────────┐
│           Flask API (app.py)                │
│                                             │
│  @app.route('/api/scan', methods=['POST'])  │
│  def security_scan():                       │
│      data = request.json                    │
│      scan_type = data.get('type', 'full')   │
│      options = data.get('options', {})      │
└────┬────────────────────────────────────────┘
     │
     │ 3. scanner.scan(scan_type, options)
     ▼
┌──────────────────────────────────────┐
│     Scanner (scanner.py)             │
│                                      │
│  scan_id = generate_id()             │
│  result = ScanResult(scan_id)        │
│  result.status = RUNNING             │
└────┬─────────────────────────────────┘
     │
     │ 4. Delegate to platform checker
     │    self.checker.full_scan()
     ▼
┌────────────────────────────────────────────┐
│   LinuxChecker (linux_checker.py)          │
│                                            │
│  full_scan():                              │
│      findings = []                         │
│      findings += _check_ssh_config()       │
│      findings += _check_passwords()        │
│      findings += _check_firewall()         │
│      findings += _check_permissions()      │
│      findings += _check_services()         │
│      return findings                       │
└────┬───────────────────────────────────────┘
     │
     │ 5. Execute individual checks
     ├─────────────────────────────┐
     ▼                             ▼
┌─────────────────┐    ┌──────────────────────┐
│ SSH Check       │    │ Password Check       │
│                 │    │                      │
│ 1. Read file    │    │ 1. Read login.defs   │
│ 2. Parse config │    │ 2. Check PAM config  │
│ 3. Find issues  │    │ 3. Analyze settings  │
│ 4. Create       │    │ 4. Create findings   │
│    findings     │    │                      │
└────┬────────────┘    └──────┬───────────────┘
     │                        │
     │ Return findings        │
     └────────┬───────────────┘
              │
              ▼
┌─────────────────────────────────────────┐
│   Aggregate Findings                    │
│                                         │
│   For each finding:                     │
│     - Add to ScanResult.findings        │
│     - Get detailed remediation          │
│     - Add references                    │
└────┬────────────────────────────────────┘
     │
     │ 6. Return findings to Scanner
     ▼
┌──────────────────────────────────────┐
│     Scanner                          │
│                                      │
│  result.findings = findings          │
│  result.complete()  # Set end_time   │
│  result.status = COMPLETED           │
│  Calculate duration                  │
└────┬─────────────────────────────────┘
     │
     │ 7. Return ScanResult to API
     ▼
┌─────────────────────────────────────────────┐
│           Flask API (app.py)                │
│                                             │
│  scan_result = scanner.scan(...)            │
│                                             │
│  # Calculate risk scores                    │
│  risk_scorer.score_vulnerabilities(result)  │
│                                             │
│  # Save to database                         │
│  db.save_scan(scan_result)                  │
│                                             │
│  # Convert to JSON                          │
│  response = scan_result.to_dict()           │
│                                             │
│  return jsonify(response), 200              │
└────┬────────────────────────────────────────┘
     │
     │ 8. JSON Response
     ▼
┌──────────┐
│ Frontend │ Receives scan results
│          │ Displays in dashboard
└──────────┘
```

### Database Write Flow

```
Scan Complete
     │
     ▼
┌────────────────────────────────┐
│  app.py: save_scan_to_db()     │
└────┬───────────────────────────┘
     │
     ├─────────────────┬────────────────────┐
     │                 │                    │
     ▼                 ▼                    ▼
┌─────────────┐  ┌──────────────┐  ┌─────────────────┐
│ scans table │  │vulnerabilities│  │ risk_scores     │
│             │  │    table      │  │     table       │
│ - scan_id   │  │               │  │                 │
│ - type      │  │ - vuln_id     │  │ - vuln_id       │
│ - timestamp │  │ - scan_id (FK)│  │ - score         │
│ - status    │  │ - severity    │  │ - base_score    │
│ - duration  │  │ - title       │  │ - temporal      │
│ - summary   │  │ - description │  │ - environmental │
└─────────────┘  │ - remediation │  └─────────────────┘
                 │ - affected    │
                 │ - category    │
                 └───────────────┘
```

---

## Function Documentation

### Core Scanner Functions

#### scanner.scan()
```python
def scan(self, scan_type: str = "quick", options: Optional[Dict[str, Any]] = None) -> ScanResult:
    """
    Perform a security scan.

    Args:
        scan_type (str): Type of scan - 'quick', 'full', 'custom', 'compliance'
        options (dict): Additional scan options
            - categories (list): For custom scans, specify categories to check
            - depth (str): 'shallow' or 'deep'

    Returns:
        ScanResult: Complete scan results with findings

    Raises:
        ValueError: If scan_type is invalid
        RuntimeError: If scan execution fails

    Example:
        >>> scanner = Scanner('Linux')
        >>> result = scanner.scan(scan_type='full')
        >>> print(f"Found {len(result.findings)} vulnerabilities")
    """
```

#### linux_checker._check_ssh_configuration()
```python
def _check_ssh_configuration(self) -> List[Dict]:
    """
    Check SSH server configuration for security issues.

    Checks performed:
        - PermitRootLogin disabled
        - PasswordAuthentication settings
        - Protocol version (should be 2)
        - Port configuration (non-standard recommended)
        - UsePAM enabled
        - X11Forwarding disabled
        - PermitEmptyPasswords disabled

    Returns:
        List[Dict]: List of findings (empty if all checks pass)

    File analyzed:
        /etc/ssh/sshd_config

    Severity levels:
        - CRITICAL: Root login enabled
        - HIGH: Password auth enabled, protocol 1 allowed
        - MEDIUM: Default port, X11 forwarding enabled
        - LOW: PAM not configured
    """
```

#### linux_checker._get_detailed_remediation()
```python
def _get_detailed_remediation(self, check_name: str, affected_item: str = "", **kwargs) -> str:
    """
    Get detailed step-by-step remediation instructions for a specific check.

    Args:
        check_name (str): Internal check identifier (e.g., 'ssh_permit_root_login')
        affected_item (str): File path or resource affected
        **kwargs: Additional context (current_value, recommended_value, etc.)

    Returns:
        str: Formatted remediation instructions with:
            - Step-by-step commands
            - Explanations
            - Warnings
            - Verification steps
            - Additional notes

    Format:
        STEP-BY-STEP FIX:
        1. [Action]
           [Command]
           [Explanation]
        ...
        ⚠️ WARNING: [Impacts]
        VERIFICATION: [How to verify]
        ADDITIONAL NOTES: [References]

    Example:
        >>> remediation = checker._get_detailed_remediation(
        ...     'ssh_permit_root_login',
        ...     '/etc/ssh/sshd_config'
        ... )
        >>> print(remediation)
    """
```

### Database Functions

#### init_db()
```python
def init_db():
    """
    Initialize database tables if they don't exist.

    Creates tables:
        - scans: Scan metadata and results
        - vulnerabilities: Individual findings
        - hardening_sessions: Remediation sessions
        - remediation_executions: Fix execution history
        - system_snapshots: Before/after state

    Connection:
        SQLite database at data/hardening_tool.db

    Called:
        On application startup (app.py initialization)
    """
```

#### save_scan_to_db()
```python
def save_scan_to_db(scan_result: ScanResult) -> bool:
    """
    Save scan results to database.

    Args:
        scan_result (ScanResult): Complete scan results

    Returns:
        bool: True if saved successfully, False otherwise

    Database operations:
        1. Insert into scans table
        2. Insert each finding into vulnerabilities table
        3. Link vulnerabilities to scan via scan_id (foreign key)
        4. Calculate and store risk scores

    Transactions:
        Uses SQLAlchemy session with automatic commit/rollback
    """
```

### Report Generation Functions

#### report_generator.generate_report()
```python
def generate_report(
    self,
    scan_results: Optional[Dict] = None,
    hardening_session: Optional[Dict] = None,
    before_scan: Optional[Dict] = None,
    after_scan: Optional[Dict] = None,
    report_format: str = "html",
    title: str = "Security Compliance Report"
) -> str:
    """
    Generate comprehensive security report.

    Args:
        scan_results: Current scan data
        hardening_session: Remediation session data
        before_scan: Pre-hardening scan
        after_scan: Post-hardening scan
        report_format: Output format (pdf, html, json, markdown, csv, excel, docx)
        title: Report title

    Returns:
        str: Path to generated report file

    File naming:
        reports/security_report_YYYYMMDD_HHMMSS.{extension}

    Formats:
        - pdf: Professional formatted PDF
        - html: Web-viewable HTML
        - json: Machine-readable JSON
        - markdown: Developer-friendly MD
        - csv: Raw data CSV
        - excel: XLSX spreadsheet
        - docx: Word document

    Raises:
        ValueError: If no data provided or invalid format
        IOError: If file write fails
    """
```

---

## Database Schema

### scans Table
```sql
CREATE TABLE scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id VARCHAR(100) UNIQUE NOT NULL,
    os_type VARCHAR(50),
    scan_type VARCHAR(50),
    status VARCHAR(50),
    start_time DATETIME,
    end_time DATETIME,
    duration_seconds FLOAT,
    total_vulnerabilities INTEGER,
    critical_count INTEGER,
    high_count INTEGER,
    medium_count INTEGER,
    low_count INTEGER,
    info_count INTEGER,
    compliance_score FLOAT,
    error_message TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

### vulnerabilities Table
```sql
CREATE TABLE vulnerabilities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id VARCHAR(100),
    category VARCHAR(100),
    severity VARCHAR(50),
    title VARCHAR(255),
    description TEXT,
    recommendation TEXT,
    affected_item VARCHAR(500),
    timestamp DATETIME,
    references TEXT,  -- JSON array
    risk_score FLOAT,
    status VARCHAR(50) DEFAULT 'open',
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
);
```

### Indexes
```sql
CREATE INDEX idx_scan_id ON vulnerabilities(scan_id);
CREATE INDEX idx_severity ON vulnerabilities(severity);
CREATE INDEX idx_status ON vulnerabilities(status);
CREATE INDEX idx_scan_timestamp ON scans(start_time);
```

---

## Error Handling

### Error Response Format
```json
{
  "error": "Error message",
  "details": "Detailed error information",
  "timestamp": "2025-12-23T14:05:30Z",
  "request_id": "req_abc123"
}
```

### Common Error Codes

| HTTP Code | Meaning | Example |
|-----------|---------|---------|
| 400 | Bad Request | Invalid scan_type parameter |
| 404 | Not Found | Scan ID doesn't exist |
| 500 | Internal Server Error | Database connection failed |
| 503 | Service Unavailable | Scanner module not loaded |

### Error Handling Pattern
```python
try:
    # Scan operation
    result = scanner.scan(scan_type, options)

except ValueError as e:
    # Invalid input
    logger.error(f"Invalid input: {e}")
    return jsonify({"error": str(e)}), 400

except RuntimeError as e:
    # Scan execution failed
    logger.error(f"Scan failed: {e}")
    return jsonify({"error": "Scan execution failed", "details": str(e)}), 500

except Exception as e:
    # Unexpected error
    logger.exception("Unexpected error during scan")
    return jsonify({"error": "Internal server error"}), 500
```

---

## Performance Considerations

### Scan Performance

| Scan Type | Duration | Checks Performed | Resource Usage |
|-----------|----------|------------------|----------------|
| Quick | 10-30s | 3-5 critical checks | Low (CPU < 10%) |
| Full | 60-120s | 15-20 comprehensive checks | Medium (CPU 20-40%) |
| Compliance | 90-150s | 30+ framework checks | Medium-High (CPU 30-50%) |

### Optimization Techniques

1. **Parallel Check Execution**
   ```python
   # Future enhancement
   with ThreadPoolExecutor(max_workers=4) as executor:
       futures = [
           executor.submit(self._check_ssh_configuration),
           executor.submit(self._check_password_policies),
           executor.submit(self._check_firewall_status),
           executor.submit(self._check_file_permissions)
       ]
       results = [f.result() for f in futures]
   ```

2. **Caching System Information**
   ```python
   @lru_cache(maxsize=1)
   def get_system_info():
       # Cache system info for 5 minutes
       return system_detector.get_full_info()
   ```

3. **Database Connection Pooling**
   ```python
   engine = create_engine(
       'sqlite:///data/hardening_tool.db',
       pool_size=10,
       max_overflow=20
   )
   ```

4. **Report Generation Async**
   ```python
   # Generate reports in background
   from celery import Celery

   @celery.task
   def generate_report_async(scan_id, format):
       return report_generator.generate_report(...)
   ```

---

## Logging

### Log Levels

```python
# Configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/app.log'),
        logging.StreamHandler()
    ]
)

# Usage in code
logger.debug("Detailed debug information")
logger.info("Scan started: scan_linux_20251223_140530")
logger.warning("SSH config file not found, using defaults")
logger.error("Failed to read /etc/shadow: Permission denied")
logger.critical("Database connection lost")
```

### Log File Structure
```
logs/
├── app.log              # Main application log
├── scanner.log          # Scanner module log
├── database.log         # Database operations
└── error.log            # Error-only log
```

---

## Security Considerations

### Input Validation
```python
# Validate scan_type
ALLOWED_SCAN_TYPES = ['quick', 'full', 'custom', 'compliance']
if scan_type not in ALLOWED_SCAN_TYPES:
    raise ValueError(f"Invalid scan_type: {scan_type}")

# Validate file paths (prevent path traversal)
def validate_path(path):
    if '..' in path or path.startswith('/'):
        raise ValueError("Invalid file path")
```

### Command Execution Safety
```python
# Use subprocess with list arguments (prevents shell injection)
result = subprocess.run(
    ['systemctl', 'status', 'sshd'],
    capture_output=True,
    text=True,
    timeout=10
)

# NEVER do this:
# os.system(f"systemctl status {service}")  # Vulnerable to injection!
```

### File Permission Checks
```python
# Verify permissions before reading sensitive files
import stat

def safe_read_file(filepath):
    st = os.stat(filepath)
    if st.st_mode & stat.S_IWOTH:
        logger.warning(f"{filepath} is world-writable!")

    with open(filepath, 'r') as f:
        return f.read()
```

---

## Development Guide

### Adding a New Security Check

1. **Add check method to linux_checker.py**
```python
def _check_new_feature(self) -> List[Dict]:
    """Check new security feature."""
    findings = []

    # Implement check logic

    return findings
```

2. **Add remediation instructions**
```python
def _get_detailed_remediation(self, check_name, ...):
    remediations = {
        # ... existing remediations ...
        "new_feature_check": """
STEP-BY-STEP FIX:
1. Do something
   command here
   explanation
"""
    }
```

3. **Add to scan methods**
```python
def full_scan(self, options=None):
    findings = []
    # ... existing checks ...
    findings.extend(self._check_new_feature())
    return findings
```

4. **Test the check**
```bash
python -m pytest tests/test_linux_checker.py::test_new_feature
```

### Adding a New API Endpoint

1. **Define route in app.py**
```python
@app.route('/api/new-endpoint', methods=['POST'])
def new_endpoint():
    """New endpoint description."""
    try:
        data = request.json
        # Process request
        result = process_data(data)
        return jsonify(result), 200
    except Exception as e:
        logger.error(f"Error in new_endpoint: {e}")
        return jsonify({"error": str(e)}), 500
```

2. **Add database models if needed**
```python
class NewModel(Base):
    __tablename__ = 'new_table'
    id = Column(Integer, primary_key=True)
    # ... columns ...
```

3. **Update API documentation**
```markdown
#### POST /api/new-endpoint
**Purpose:** Description
**Request:** {...}
**Response:** {...}
```

4. **Add tests**
```python
def test_new_endpoint(client):
    response = client.post('/api/new-endpoint', json={...})
    assert response.status_code == 200
```

---

## Troubleshooting

### Common Issues

#### 1. Scanner returns empty findings
```bash
# Check permissions
sudo python app.py

# Verify checker loaded
tail -f logs/app.log | grep "checker loaded"
```

#### 2. Database errors
```bash
# Reset database
rm data/hardening_tool.db
python app.py  # Auto-creates tables
```

#### 3. Import errors
```bash
# Reinstall dependencies
source venv/bin/activate
pip install -r requirements.txt --force-reinstall
```

#### 4. Permission denied errors
```bash
# Run with sudo for system checks
sudo python app.py

# Or add user to required groups
sudo usermod -aG adm,systemd-journal $USER
```

---

## Testing

### Run All Tests
```bash
cd src/backend
python -m pytest tests/ -v
```

### Test Specific Module
```bash
python -m pytest tests/test_scanner.py -v
```

### Test Coverage
```bash
pytest --cov=modules --cov-report=html
```

### Manual API Testing
```bash
# Health check
curl http://localhost:5000/api/health

# Run scan
curl -X POST http://localhost:5000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"type": "quick"}'

# Generate report
curl -X POST http://localhost:5000/api/report \
  -H "Content-Type: application/json" \
  -d '{"format": "json", "scan_type": "full"}' \
  -o report.json
```

---

## Appendix

### File Paths Reference
```
/etc/ssh/sshd_config          # SSH configuration
/etc/login.defs               # Password policies
/etc/security/pwquality.conf  # Password quality
/etc/pam.d/common-password    # PAM password module
/etc/passwd                   # User accounts
/etc/shadow                   # Password hashes
/etc/group                    # Group information
/etc/gshadow                  # Secure group information
```

### Command Reference
```bash
# SSH
systemctl status sshd
systemctl restart sshd
sshd -t                      # Test config

# Firewall
ufw status
ufw enable
iptables -L

# Files
ls -la /etc/shadow
chmod 640 /etc/shadow
chown root:shadow /etc/shadow

# Services
systemctl list-units --type=service
systemctl disable telnet.service
```

### Severity Guidelines

| Severity | CVSS Score | Response Time | Examples |
|----------|-----------|---------------|----------|
| CRITICAL | 9.0-10.0 | Immediate | Root login enabled, no firewall |
| HIGH | 7.0-8.9 | 24-48 hours | Weak passwords, open dangerous ports |
| MEDIUM | 4.0-6.9 | 1-2 weeks | Missing updates, suboptimal configs |
| LOW | 0.1-3.9 | 1 month | Minor misconfigurations |
| INFO | 0.0 | None | Informational findings |

---

**End of Backend Technical Guide**

For frontend documentation, see `DESIGN_DOCUMENTATION.md`
For user guide, see `DASHBOARD_README.md`
For changes log, see `CHANGES_SUMMARY.md`
