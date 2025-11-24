# 🛡️ System Hardening Tool

<div align="center">

![Security](https://img.shields.io/badge/Security-Hardening-blue)
![Python](https://img.shields.io/badge/Python-3.8+-green)
![React](https://img.shields.io/badge/React-18.2-blue)
![License](https://img.shields.io/badge/License-MIT-yellow)
![Status](https://img.shields.io/badge/Status-Production-success)

**Enterprise-grade automated security assessment and system hardening platform with cybersecurity-themed UI**

[Features](#-features) • [Quick Start](#-quick-start) • [Screenshots](#-screenshots) • [API Docs](#-api-documentation)

</div>

---

## 📋 Overview

The **System Hardening Tool** is a comprehensive, production-ready security platform that automates vulnerability detection, risk assessment, compliance checking, and guided remediation for Linux systems. Built with modern technologies (React + Flask + SQLAlchemy), it features a professional cybersecurity-themed dark mode interface, real-time monitoring, historical tracking, and intelligent remediation playbooks.

### 🎯 Key Capabilities

- **🔍 Automated Security Scanning** - Multi-dimensional vulnerability detection
- **⚠️ Advanced Risk Scoring** - CVSS-inspired 3-component risk assessment
- **📊 Historical Tracking** - Trend analysis with SQLite database
- **🧙 Guided Remediation** - Step-by-step playbook-based fixes
- **📈 Compliance Frameworks** - CIS, PCI-DSS, HIPAA, SOC 2 support
- **🎨 Cybersecurity UI Theme** - Professional dark mode with Matrix aesthetics
- **📡 Real-time Monitoring** - Live system metrics and process tracking
- **📁 Multi-Format Reports** - PDF, HTML, JSON, CSV exports

---

## ✨ Features

### 🔒 Security Scanning
- **Network Security Analysis**: SSH configuration, firewall rules, open ports
- **File System Auditing**: Permission checks, world-writable files, SUID/SGID detection
- **System Updates**: Package vulnerability scanning, outdated software identification
- **Service Hardening**: Configuration assessment, unnecessary service detection
- **Compliance Validation**: Multi-framework compliance checking

### ⚠️ Risk Assessment Engine
- **Three-Component Scoring**: Base score (severity × exploitability), Temporal factors, Environmental impact
- **Intelligent Prioritization**: Automatic vulnerability ranking by calculated risk
- **Distribution Analytics**: Visual risk distribution across categories
- **Trend Tracking**: Historical risk score progression with time-series graphs
- **Impact Prediction**: Estimated risk reduction calculations

### 🧙 Guided Remediation
- **4 Pre-built Playbooks**:
  1. **SSH Hardening** - Disable password auth, enforce key-based access
  2. **System Updates** - Automated package updates with validation
  3. **Permission Fixes** - Correct insecure file permissions
  4. **Firewall Setup** - UFW configuration with secure defaults
- **Phased Plans**: Priority-based execution (Critical → High → Medium → Low)
- **Validation Framework**: Post-remediation verification steps
- **Rollback Support**: Automatic rollback on validation failure

### 📊 Historical Data & Analytics
- **Scan History**: Complete record of all security assessments
- **Trend Visualization**: Line charts for vulnerabilities, compliance, risk scores
- **Comparative Analysis**: Before/after comparisons for remediation impact
- **SQLite Database**: Persistent storage with efficient querying
- **Execution Metrics**: Success rates, time-to-fix, risk reduction stats

### 📡 Real-time Monitoring
- **System Metrics**: CPU, memory, disk, network utilization
- **Process Management**: Top processes, resource hogs identification
- **Live Updates**: Auto-refresh monitoring dashboard
- **Alert Thresholds**: Configurable warnings for resource limits

### 📈 Compliance Management
- **Framework Support**: CIS Benchmarks, PCI-DSS, HIPAA, SOC 2, GDPR
- **Automated Checks**: Rule-based compliance validation
- **Scoring System**: Percentage-based compliance scoring
- **Gap Analysis**: Identify non-compliant configurations
- **Remediation Mapping**: Direct links to fix procedures

### 📁 Report Generation
- **PDF Reports**: Professional formatted documents with charts
- **HTML Exports**: Web-viewable reports with interactive elements
- **JSON/CSV**: Machine-readable exports for SIEM integration
- **Email Delivery**: Automated report distribution
- **Custom Templates**: Configurable report layouts

---

## 🚀 Quick Start

### Prerequisites

- **Python 3.8+** (Backend runtime)
- **Node.js 14+** (Frontend development)
- **pip & npm** (Package managers)
- **Linux OS** (Native or WSL2)
- **4GB RAM** minimum (8GB recommended)

### Installation Steps

```bash
# 1. Clone Repository
git clone https://github.com/yourusername/system-hardening-tool.git
cd system-hardening-tool

# 2. Backend Setup
cd src/backend
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt

# 3. Frontend Setup
cd ../frontend
npm install

# 4. Start Backend (Terminal 1)
cd src/backend
source venv/bin/activate
python app.py
# Server running on http://localhost:5000

# 5. Start Frontend (Terminal 2)
cd src/frontend
npm start
# Opens browser at http://localhost:3000
```

### First Run

1. **Access Dashboard**: Navigate to http://localhost:3000
2. **Wait for Connection**: Green "Connected" status indicator
3. **Run Initial Scan**: Click "Start Security Scan" button
4. **Explore Features**:
   - View scan results in the dashboard
   - Check Risk Analysis for prioritization
   - Browse History for trend analysis
   - Try Guided Remediation wizard
   - Review Compliance scores

---

## 🎨 Cybersecurity Theme

The application features a **professional dark mode interface** with:

- **Color Scheme**: Cyber blue (#00d9ff), purple (#b24bf3), matrix green (#00ff41)
- **Dark Backgrounds**: Reduced eye strain, professional appearance
- **Gradient Effects**: Smooth transitions, glowing borders
- **Hover Animations**: Interactive feedback, modern UX
- **Neon Accents**: Critical information highlighting
- **Custom Scrollbars**: Themed with gradient effects
- **Cyber Typography**: Uppercase headers, gradient text

### Theme Components

```css
/* Cybersecurity color palette */
--cyber-dark: #0a0e27
--cyber-blue: #00d9ff
--cyber-purple: #b24bf3
--cyber-green: #00ff41
--cyber-red: #ff0055
```

---

## 🏗️ Architecture

### Technology Stack

**Backend:**
- **Flask 2.3.2** - Lightweight web framework
- **SQLAlchemy 2.0.44** - ORM for database operations
- **psutil 5.9.5** - System and process monitoring
- **ReportLab 4.0.4** - PDF report generation
- **APScheduler 3.10.1** - Background task scheduling

**Frontend:**
- **React 18.2** - Component-based UI framework
- **Chart.js 4.4.0** - Data visualization library
- **Fetch API** - Modern HTTP client
- **CSS-in-JS** - Cybersecurity theme styling

**Database:**
- **SQLite** - Embedded relational database

### System Architecture

```
┌─────────────────┐         ┌──────────────────┐         ┌─────────────────┐
│                 │   API   │                  │   ORM   │                 │
│  React Frontend ├────────►│  Flask Backend   ├────────►│ SQLite Database │
│   (Port 3000)   │  JSON   │   (Port 5000)    │  Query  │  (Persistent)   │
│                 │         │                  │         │                 │
└─────────────────┘         └────────┬─────────┘         └─────────────────┘
                                     │
                     ┌───────────────┼───────────────┬──────────────┐
                     │               │               │              │
            ┌────────▼────────┐ ┌───▼────────┐ ┌───▼──────────┐ ┌─▼────────┐
            │ Security Scanner│ │ Risk Scorer│ │Playbook Engine│ │ Monitor  │
            └─────────────────┘ └────────────┘ └───────────────┘ └──────────┘
```

### Project Structure

```
system-hardening-tool/
├── src/
│   ├── backend/
│   │   ├── app.py                          # Flask application
│   │   ├── modules/
│   │   │   ├── scanner.py                  # Vulnerability scanner
│   │   │   ├── risk_scoring.py             # Risk assessment engine
│   │   │   ├── database_models.py          # SQLAlchemy ORM models
│   │   │   ├── remediation_playbooks.py    # Playbook automation
│   │   │   ├── compliance_frameworks.py    # Compliance checker
│   │   │   ├── realtime_monitor.py         # System monitoring
│   │   │   ├── auto_remediation.py         # Automated fixes
│   │   │   ├── report_generator.py         # Report creation
│   │   │   ├── export_formats.py           # Export handlers
│   │   │   └── email_service.py            # Email delivery
│   │   ├── requirements.txt
│   │   └── venv/                           # Virtual environment
│   │
│   └── frontend/
│       ├── src/
│       │   ├── components/
│       │   │   ├── Dashboard.js            # Main dashboard
│       │   │   ├── RiskDashboard.js        # Risk analysis
│       │   │   ├── HistoryViewer.js        # Historical data
│       │   │   ├── RemediationWizard.js    # Guided remediation
│       │   │   ├── MonitoringDashboard.js  # Real-time monitor
│       │   │   ├── CompliancePanel.js      # Compliance view
│       │   │   └── RemediationPanel.js     # Auto-remediation
│       │   ├── api/
│       │   │   └── client.js               # API client (40+ functions)
│       │   ├── CyberTheme.css              # Cybersecurity theme
│       │   ├── index.js
│       │   └── App.js
│       ├── package.json
│       └── node_modules/
│
├── data/
│   └── hardening_tool.db                   # SQLite database
├── reports/                                 # Generated reports
├── logs/                                    # Application logs
├── config/
│   └── templates/                           # Report templates
└── README.md
```

---

## 📚 API Documentation

### Security Scanning

```http
POST /api/scan
Content-Type: application/json

{
  "scan_type": "full"  # Options: full, quick, network, filesystem
}

Response: {
  "scan_id": "scan_20251124_123456",
  "status": "completed",
  "totalVulnerabilities": 15,
  "complianceScore": 78,
  "criticalIssues": 3,
  "findings": [...]
}
```

### Historical Data

```http
# Get scan history
GET /api/history/scans?limit=20&offset=0

# Get specific scan
GET /api/history/scan/{scan_id}

# Get vulnerability trends
GET /api/history/trends?days=30

# Get statistics
GET /api/history/statistics
```

### Risk Assessment

```http
# Get risk trends
GET /api/risk/trends?days=30

# Get risk distribution
GET /api/risk/distribution

# Get high-risk vulnerabilities
GET /api/risk/high-risk?limit=10

# Get risk recommendations
POST /api/risk/recommendations
Body: { "vulnerabilities": [...] }
```

### Guided Remediation

```http
# List playbooks
GET /api/playbooks?category=Network Security

# Get specific playbook
GET /api/playbooks/{playbook_id}

# Match playbook to vulnerability
POST /api/playbooks/match
Body: { "vulnerability": {...} }

# Create remediation plan
POST /api/playbooks/plan
Body: { "vulnerabilities": [...] }

# Estimate effort
POST /api/playbooks/estimate
Body: { "vulnerabilities": [...] }

# Get execution history
GET /api/playbooks/executions?limit=10

# Get metrics
GET /api/playbooks/metrics
```

### Real-time Monitoring

```http
# Start monitoring
POST /api/monitoring/start

# Stop monitoring
POST /api/monitoring/stop

# Get metrics
GET /api/monitoring/metrics

# Get processes
GET /api/monitoring/processes?limit=10
```

### Compliance

```http
# List frameworks
GET /api/compliance/frameworks

# Check compliance
POST /api/compliance/check
Body: { "framework": "CIS" }

# Get compliance report
GET /api/compliance/report/{framework}
```

### Report Generation

```http
# Generate report
POST /api/report/generate
Body: {
  "format": "pdf",  # pdf, html, json, csv
  "scan_id": "scan_20251124_123456"
}

# List reports
GET /api/reports/list

# Email report
POST /api/report/email
Body: {
  "report_id": "report_123",
  "recipients": ["admin@example.com"]
}
```

---

## 🖼️ Screenshots

### Main Dashboard
Professional dark theme with real-time statistics and navigation.

### Risk Analysis Dashboard
Risk gauge, distribution charts, and trend visualization.

### Guided Remediation Wizard
3-step wizard: Select vulnerabilities → Review plan → Execute.

### History Viewer
Historical trends with interactive charts and scan comparisons.

---

## 🧪 Testing

### Comprehensive Function Test

```bash
# Test health check
curl http://localhost:5000/api/health

# Test security scan
curl -X POST http://localhost:5000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"scan_type": "full"}'

# Test risk analysis
curl http://localhost:5000/api/risk/distribution

# Test playbooks
curl http://localhost:5000/api/playbooks

# Test compliance
curl -X POST http://localhost:5000/api/compliance/check \
  -H "Content-Type: application/json" \
  -d '{"framework": "CIS"}'
```

### Automated Testing

```bash
# Backend unit tests
cd src/backend
python -m pytest tests/

# Frontend component tests
cd src/frontend
npm test
```

---

## 📊 Database Schema

### Tables Overview

**scans** - Security assessment records
- Stores scan metadata, metrics, risk scores
- Links to vulnerabilities via one-to-many relationship

**vulnerabilities** - Individual security findings
- Details for each detected vulnerability
- Risk scoring data and remediation status

**hardening_sessions** - Remediation executions
- Tracks applied fixes and configurations
- Links to related scans

**remediation_executions** - Playbook runs
- Execution steps, validation results
- Before/after risk scores

**system_snapshots** - State comparisons
- System configuration snapshots
- Used for before/after analysis

---

## ⚙️ Configuration

### Backend (.env file)

```env
# Server Settings
FLASK_ENV=production
DEBUG=False
HOST=0.0.0.0
PORT=5000

# Database
DATABASE_PATH=data/hardening_tool.db

# Reports
REPORT_OUTPUT_DIR=reports/
TEMPLATE_DIR=config/templates/

# Email (Optional)
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USERNAME=your-email@gmail.com
MAIL_PASSWORD=your-app-password
MAIL_DEFAULT_SENDER=security@yourdomain.com

# Monitoring
MONITORING_INTERVAL=5
ALERT_THRESHOLD_CPU=80
ALERT_THRESHOLD_MEMORY=85
```

### Frontend (src/api/client.js)

```javascript
const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:5000/api';
```

---

## 🐛 Troubleshooting

### Backend Issues

**Port already in use:**
```bash
# Find process on port 5000
lsof -i :5000
kill -9 <PID>
```

**Module not found:**
```bash
source venv/bin/activate
pip install -r requirements.txt
```

**Database errors:**
```bash
# Reset database
rm data/hardening_tool.db
# Restart backend - tables auto-create
```

### Frontend Issues

**Compilation errors:**
```bash
rm -rf node_modules package-lock.json
npm install
```

**API connection failed:**
- Verify backend is running on port 5000
- Check browser console for CORS errors
- Ensure no firewall blocking localhost

---

## 🔒 Security Considerations

### Production Deployment

⚠️ **Important Security Measures:**

1. **Authentication**: Implement JWT or OAuth2
2. **HTTPS**: Enable TLS/SSL encryption
3. **RBAC**: Add role-based access control
4. **Rate Limiting**: Prevent API abuse
5. **Input Validation**: Sanitize all user inputs
6. **Secure Storage**: Encrypt sensitive data
7. **Audit Logging**: Track all security actions

### Data Privacy

- Scan results contain sensitive system information
- Store database securely (encrypted filesystem recommended)
- Restrict access to reports directory
- Use environment variables for credentials
- Never commit secrets to version control

---

## 🤝 Contributing

Contributions welcome! Please follow these guidelines:

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Follow code style (PEP 8 for Python, ESLint for JavaScript)
4. Add tests for new features
5. Update documentation
6. Commit changes (`git commit -m 'Add amazing feature'`)
7. Push to branch (`git push origin feature/amazing-feature`)
8. Open Pull Request

---

## 📝 License

MIT License - see [LICENSE](LICENSE) file

```
Copyright (c) 2025 System Hardening Tool Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software...
```

---

## 🗺️ Roadmap

### Planned Features

- [ ] **Multi-user support** with authentication
- [ ] **Scheduled scanning** with cron integration
- [ ] **Container security** (Docker, Kubernetes)
- [ ] **Cloud platform support** (AWS, Azure, GCP)
- [ ] **SIEM integration** (Splunk, ELK)
- [ ] **Advanced playbook editor** with drag-drop
- [ ] **Machine learning** for anomaly detection
- [ ] **Mobile app** for monitoring
- [ ] **Distributed scanning** for multiple systems
- [ ] **API rate limiting** and throttling

---

## 📧 Support

- **Issues**: [GitHub Issues](https://github.com/yourusername/system-hardening-tool/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/system-hardening-tool/discussions)
- **Email**: support@yourdomain.com
- **Documentation**: Full docs available in `/docs` directory

---

## 🙏 Acknowledgments

- **CVSS** - Vulnerability scoring methodology
- **CIS Benchmarks** - Security configuration standards
- **OWASP** - Security best practices
- **Chart.js** - Data visualization
- **Flask** & **React** - Excellent frameworks
- **Claude Code** - AI-powered development

---

<div align="center">

**🛡️ Securing Systems, One Scan at a Time 🛡️**

Version 2.0.0 | Last Updated: November 2025

⭐ **Star this repo if you find it useful!** ⭐

[⬆ Back to Top](#-system-hardening-tool)

</div>
