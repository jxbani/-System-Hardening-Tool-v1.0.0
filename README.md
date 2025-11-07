# System Hardening Tool

A comprehensive security hardening and vulnerability assessment tool with a professional web-based dashboard.

![Version](https://img.shields.io/badge/version-1.0.0-blue)
![Python](https://img.shields.io/badge/python-3.8+-green)
![React](https://img.shields.io/badge/react-18.2-blue)
![License](https://img.shields.io/badge/license-MIT-green)

## Features

✅ **Security Scanning**: Automated vulnerability detection and security assessment
✅ **System Hardening**: Apply security fixes and hardening configurations
✅ **Real-time Dashboard**: Professional React-based UI with live updates
✅ **PDF Reports**: Generate detailed security reports
✅ **System Monitoring**: Track CPU, memory, and disk usage
✅ **Activity Logging**: Real-time activity feed with color-coded status indicators

## Tech Stack

### Backend
- Python 3.8+
- Flask (REST API)
- psutil (System monitoring)
- Flask-CORS (Cross-origin support)

### Frontend
- React 18
- Axios (HTTP client)
- Modern inline CSS styling
- Responsive design

## Prerequisites

### Linux
- Python 3.8 or higher
- Node.js 14+ and npm
- pip (Python package manager)
- Git

### Windows 11
- Python 3.8 or higher ([Download](https://www.python.org/downloads/))
- Node.js 14+ and npm ([Download](https://nodejs.org/))
- Git ([Download](https://git-scm.com/download/win))

---

## Installation & Setup

### 📥 Linux Installation

#### 1. Clone the Repository
```bash
git clone https://github.com/YOUR_USERNAME/system-hardening-tool.git
cd system-hardening-tool
```

#### 2. Backend Setup
```bash
# Navigate to backend directory
cd src/backend

# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

#### 3. Frontend Setup
```bash
# Navigate to frontend directory (from project root)
cd ../../src/frontend

# Install dependencies
npm install
```

#### 4. Run the Application

**Terminal 1 - Start Backend:**
```bash
cd src/backend
source venv/bin/activate
python app.py
```

You should see:
```
* Running on http://127.0.0.1:5000
```

**Terminal 2 - Start Frontend:**
```bash
cd src/frontend
npm start
```

Browser will automatically open to http://localhost:3000

#### 5. Access the Dashboard
- **Frontend**: http://localhost:3000
- **Backend API**: http://localhost:5000

---

### 💻 Windows 11 Installation

#### 1. Clone the Repository
Open PowerShell or Command Prompt:
```powershell
git clone https://github.com/YOUR_USERNAME/system-hardening-tool.git
cd system-hardening-tool
```

#### 2. Backend Setup
```powershell
# Navigate to backend directory
cd src\backend

# Create virtual environment
python -m venv venv

# Activate virtual environment
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

#### 3. Frontend Setup
```powershell
# Navigate to frontend directory (from project root)
cd ..\..\src\frontend

# Install dependencies
npm install
```

#### 4. Run the Application

**Command Prompt/PowerShell Window 1 - Start Backend:**
```powershell
cd src\backend
venv\Scripts\activate
python app.py
```

You should see:
```
* Running on http://127.0.0.1:5000
```

**Command Prompt/PowerShell Window 2 - Start Frontend:**
```powershell
cd src\frontend
npm start
```

Browser will automatically open to http://localhost:3000

#### 5. Access the Dashboard
- **Frontend**: http://localhost:3000
- **Backend API**: http://localhost:5000

---

## 📖 Usage Guide

### Running a Security Scan

1. Open the dashboard at http://localhost:3000
2. Wait for backend connection (green "connected" indicator)
3. Click **"Start Security Scan"** button
4. View results in the scan results table

### Applying Security Fixes

1. Run a security scan first
2. Review vulnerabilities in the results table
3. Click **"🛠️ Fix Vulnerabilities"** button
4. Monitor progress in Recent Activity panel
5. Run a new scan to verify fixes applied

### Generating PDF Reports

1. After running a scan, click **"📄 Generate PDF Report"**
2. Check Recent Activity panel for confirmation
3. View report details in browser console (F12)

### Dashboard Features

**System Information Card**:
- Operating System and version
- Hostname and architecture
- Real-time CPU usage %
- Real-time Memory usage %
- Real-time Disk usage %

**Security Overview Card**:
- Total vulnerabilities count
- Compliance score percentage
- Critical issues count
- Warnings count

**Recent Activity Panel**:
- Real-time activity log
- Color-coded status (info/success/error)
- Timestamp for each activity

---

## 📁 Project Structure

```
system-hardening-tool/
├── src/
│   ├── backend/
│   │   ├── app.py                  # Flask API server
│   │   ├── requirements.txt        # Python dependencies
│   │   ├── venv/                   # Virtual environment (gitignored)
│   │   └── .env                    # Environment variables
│   └── frontend/
│       ├── src/
│       │   ├── components/
│       │   │   └── Dashboard.js    # Main dashboard component
│       │   ├── api/
│       │   │   └── client.js       # API client
│       │   ├── App.js             # Main App component
│       │   └── index.js           # Entry point
│       ├── package.json           # Node dependencies
│       ├── node_modules/          # Dependencies (gitignored)
│       └── public/                # Static files
├── logs/                          # Application logs
├── .gitignore                     # Git ignore rules
└── README.md                      # This file
```

---

## 🔌 API Endpoints

### Health Check
```
GET /api/health
```
Returns API status and version

### System Information
```
GET /api/system-info
```
Returns detailed system metrics (CPU, RAM, disk, etc.)

### Security Scan
```
POST /api/scan
Body: { "type": "full" } (optional)
```
Runs vulnerability assessment and returns findings

### Apply Hardening
```
POST /api/harden
Body: { "rules": ["rule1", "rule2"], "dry_run": true }
```
Applies security fixes based on scan results

### Generate Report
```
POST /api/report
Body: { "format": "pdf" }
```
Generates security report in specified format

---

## ⚙️ Configuration

### Backend Configuration (.env)
Create `.env` file in `src/backend/`:
```env
DEBUG=False
PORT=5000
ALLOWED_ORIGINS=*
```

### Frontend Configuration
Frontend automatically proxies to backend (configured in `package.json`)

---

## 🐛 Troubleshooting

### Backend Won't Start

**Issue**: `ModuleNotFoundError` or import errors
**Solution**:
```bash
source venv/bin/activate  # Linux
venv\Scripts\activate     # Windows
pip install -r requirements.txt
```

**Issue**: Port 5000 already in use
**Solution**: Change port in `.env` file or stop conflicting service

### Frontend Won't Start

**Issue**: `EADDRINUSE` port 3000
**Solution**: Stop other apps using port 3000 or set different port:
```bash
PORT=3001 npm start  # Linux
set PORT=3001 && npm start  # Windows
```

**Issue**: Dependency errors
**Solution**:
```bash
rm -rf node_modules package-lock.json  # Linux
rmdir /s node_modules && del package-lock.json  # Windows
npm install
```

### Backend Status Shows "Disconnected"

1. Verify backend is running on port 5000
2. Check browser console (F12) for CORS errors
3. Ensure no firewall blocking localhost:5000
4. Try refreshing the page

### Scan Button is Disabled

1. Wait for backend status to show "connected"
2. Check backend terminal for errors
3. Refresh the browser page
4. Verify backend logs: `logs/app.log`

---

## 🔒 Security Notes

⚠️ **Important**:
- This tool is for authorized security testing only
- Requires appropriate permissions for system-level operations
- Do not use on production systems without proper authorization
- Always review hardening changes before applying
- Keep backups of system configurations

---

## 🛠️ Development

### Adding New Features

**Backend** - Add endpoints in `src/backend/app.py`:
```python
@app.route('/api/new-endpoint', methods=['POST'])
def new_feature():
    # Your code here
    return jsonify({"status": "success"})
```

**Frontend** - Update API client in `src/frontend/src/api/client.js`:
```javascript
export async function newFeature() {
    const response = await fetch(`${API_BASE_URL}/new-endpoint`, {
        method: 'POST'
    });
    return await handleResponse(response);
}
```

### Testing

- **Backend logs**: `logs/app.log`
- **Frontend console**: Browser DevTools (F12)
- **Network requests**: Browser Network tab (F12)

---

## 🗺️ Roadmap

- [ ] Real vulnerability scanning engine
- [ ] Actual PDF generation with reportlab
- [ ] User authentication system
- [ ] Scheduled automated scans
- [ ] Email notifications
- [ ] Multi-system support
- [ ] Custom hardening policies
- [ ] Compliance frameworks (CIS, NIST, PCI-DSS)
- [ ] Historical scan data and trending
- [ ] Export to CSV/JSON formats

---

## 📝 License

MIT License - See LICENSE file for details

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 💬 Support

For issues and questions:
- 📫 Open an issue on GitHub
- 📚 Check existing issues for solutions
- 📋 Review logs in `logs/app.log`

---

## 📜 Credits

Generated with **Claude Code** - AI-powered development assistant

---

**Version**: 1.0.0
**Last Updated**: November 2025
**Maintainer**: [Your Name]
