import React, { useState, useEffect, useCallback } from 'react';
import { getSystemInfo, runScan, checkHealth, generateReport } from '../api/client';
import ModernScanResults from './ModernScanResults';
import './ModernDashboard.css';

function ModernDashboard() {
  // State management
  const [systemInfo, setSystemInfo] = useState(null);
  const [scanData, setScanData] = useState(null);
  const [statistics, setStatistics] = useState({
    totalVulnerabilities: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    complianceScore: 0,
    lastScanTime: null
  });
  const [loading, setLoading] = useState(true);
  const [scanning, setScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [generatingReport, setGeneratingReport] = useState(false);
  const [reportFormat, setReportFormat] = useState('pdf');
  const [error, setError] = useState(null);
  const [successMessage, setSuccessMessage] = useState(null);
  const [backendStatus, setBackendStatus] = useState('checking');
  const [showResults, setShowResults] = useState(false);

  /**
   * Check backend health status
   */
  const checkBackendHealth = useCallback(async () => {
    try {
      await checkHealth();
      setBackendStatus('connected');
      return true;
    } catch (err) {
      console.error('Backend health check failed:', err);
      setBackendStatus('disconnected');
      return false;
    }
  }, []);

  /**
   * Fetch initial dashboard data
   */
  const fetchDashboardData = useCallback(async () => {
    setLoading(true);
    setError(null);

    try {
      const isHealthy = await checkBackendHealth();

      if (isHealthy) {
        const response = await getSystemInfo();
        const sysInfo = response.data || response;
        setSystemInfo(sysInfo);
      }
    } catch (err) {
      console.error('Error fetching dashboard data:', err);
      setError('Failed to load dashboard data. Please ensure the backend is running.');
    } finally {
      setLoading(false);
    }
  }, [checkBackendHealth]);

  // Initial data fetch
  useEffect(() => {
    fetchDashboardData();

    // Set up periodic health checks
    const healthCheckInterval = setInterval(checkBackendHealth, 30000);

    return () => clearInterval(healthCheckInterval);
  }, [fetchDashboardData, checkBackendHealth]);

  /**
   * Handle security scan with progress simulation
   */
  const handleStartScan = async () => {
    if (backendStatus !== 'connected') {
      setError('Backend is not connected. Please check if the server is running on port 5000.');
      return;
    }

    setScanning(true);
    setError(null);
    setSuccessMessage(null);
    setScanProgress(0);
    setShowResults(false);

    // Simulate progress
    const progressInterval = setInterval(() => {
      setScanProgress(prev => {
        if (prev >= 90) {
          clearInterval(progressInterval);
          return 90;
        }
        return prev + 10;
      });
    }, 200);

    try {
      const results = await runScan();

      clearInterval(progressInterval);
      setScanProgress(100);

      // Process scan results
      setScanData(results);

      // Calculate statistics
      const findings = results.findings || [];
      const stats = {
        totalVulnerabilities: findings.length,
        critical: findings.filter(f => f.severity?.toLowerCase() === 'critical').length,
        high: findings.filter(f => f.severity?.toLowerCase() === 'high').length,
        medium: findings.filter(f => f.severity?.toLowerCase() === 'medium').length,
        low: findings.filter(f => f.severity?.toLowerCase() === 'low').length,
        complianceScore: results.complianceScore || 0,
        lastScanTime: new Date().toISOString()
      };

      setStatistics(stats);
      setSuccessMessage(`Scan completed successfully! Found ${stats.totalVulnerabilities} issues.`);

      // Show results after brief delay
      setTimeout(() => {
        setShowResults(true);
      }, 500);

    } catch (err) {
      clearInterval(progressInterval);
      console.error('Error running scan:', err);
      setError(`Scan failed: ${err.message}`);
      setScanProgress(0);
    } finally {
      setScanning(false);
    }
  };

  /**
   * Handle report generation
   */
  const handleGenerateReport = async () => {
    if (!scanData) {
      setError('Please run a scan first before generating a report');
      return;
    }

    setGeneratingReport(true);
    setError(null);

    const formatExtensions = {
      'pdf': '.pdf',
      'html': '.html',
      'excel': '.xlsx',
      'csv': '.csv',
      'docx': '.docx',
      'markdown': '.md',
      'json': '.json'
    };

    try {
      const blob = await generateReport({
        format: reportFormat,
        title: 'IronGuard OS Security Report',
        scan_results: scanData
      });

      // Create download link
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `ironguard-security-report-${new Date().toISOString().split('T')[0]}${formatExtensions[reportFormat]}`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      window.URL.revokeObjectURL(url);

      setSuccessMessage(`${reportFormat.toUpperCase()} report downloaded successfully!`);
    } catch (err) {
      console.error('Error generating report:', err);
      setError(`Failed to generate report: ${err.message}`);
    } finally {
      setGeneratingReport(false);
    }
  };

  /**
   * Format number with animation-ready display
   */
  const formatNumber = (num) => {
    return num.toString().padStart(2, '0');
  };

  /**
   * Get compliance score color
   */
  const getComplianceColor = (score) => {
    if (score >= 90) return 'var(--success)';
    if (score >= 70) return 'var(--warning)';
    return 'var(--danger)';
  };

  // Loading state
  if (loading) {
    return (
      <div className="modern-dashboard">
        <div className="loading-screen">
          <div className="loading-content">
            <div className="cyber-loader">
              <div className="loader-ring"></div>
              <div className="loader-ring"></div>
              <div className="loader-ring"></div>
            </div>
            <h2 className="loading-text">Initializing Security Dashboard</h2>
            <p className="loading-subtext">Connecting to IronGuard OS Security Core...</p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="modern-dashboard">
      {/* Header */}
      <header className="dashboard-header">
        <div className="header-content">
          <div className="header-left">
            <div className="logo-container">
              <div className="logo-icon">
                <svg width="40" height="40" viewBox="0 0 40 40" fill="none">
                  <path d="M20 2L4 10V18C4 28 20 38 20 38C20 38 36 28 36 18V10L20 2Z"
                        stroke="url(#logo-gradient)" strokeWidth="2" fill="url(#logo-fill)"/>
                  <path d="M20 12L14 15V20C14 24 20 28 20 28C20 28 26 24 26 20V15L20 12Z"
                        fill="var(--primary)"/>
                  <defs>
                    <linearGradient id="logo-gradient" x1="4" y1="2" x2="36" y2="38">
                      <stop offset="0%" stopColor="var(--primary)" />
                      <stop offset="100%" stopColor="var(--secondary)" />
                    </linearGradient>
                    <linearGradient id="logo-fill" x1="4" y1="2" x2="36" y2="38">
                      <stop offset="0%" stopColor="var(--primary)" stopOpacity="0.1" />
                      <stop offset="100%" stopColor="var(--secondary)" stopOpacity="0.2" />
                    </linearGradient>
                  </defs>
                </svg>
              </div>
              <div className="logo-text">
                <h1 className="app-title">IronGuard OS</h1>
                <p className="app-subtitle">Security Command Center</p>
              </div>
            </div>
          </div>

          <div className="header-right">
            <div className={`backend-status status-${backendStatus}`}>
              <div className="status-indicator">
                <span className="status-dot"></span>
                <div className="status-pulse"></div>
              </div>
              <div className="status-text">
                <span className="status-label">System Status</span>
                <span className="status-value">
                  {backendStatus === 'connected' ? 'Online' :
                   backendStatus === 'disconnected' ? 'Offline' : 'Checking...'}
                </span>
              </div>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="dashboard-main">
        <div className="dashboard-container">

          {/* Alert Messages */}
          {error && (
            <div className="alert alert-error">
              <div className="alert-icon">
                <svg width="20" height="20" viewBox="0 0 20 20" fill="currentColor">
                  <path d="M10 0C4.48 0 0 4.48 0 10C0 15.52 4.48 20 10 20C15.52 20 20 15.52 20 10C20 4.48 15.52 0 10 0ZM11 15H9V13H11V15ZM11 11H9V5H11V11Z"/>
                </svg>
              </div>
              <span className="alert-message">{error}</span>
              <button className="alert-close" onClick={() => setError(null)}>
                <svg width="14" height="14" viewBox="0 0 14 14" fill="currentColor">
                  <path d="M14 1.41L12.59 0L7 5.59L1.41 0L0 1.41L5.59 7L0 12.59L1.41 14L7 8.41L12.59 14L14 12.59L8.41 7L14 1.41Z"/>
                </svg>
              </button>
            </div>
          )}

          {successMessage && (
            <div className="alert alert-success">
              <div className="alert-icon">
                <svg width="20" height="20" viewBox="0 0 20 20" fill="currentColor">
                  <path d="M10 0C4.48 0 0 4.48 0 10C0 15.52 4.48 20 10 20C15.52 20 20 15.52 20 10C20 4.48 15.52 0 10 0ZM8 15L3 10L4.41 8.59L8 12.17L15.59 4.58L17 6L8 15Z"/>
                </svg>
              </div>
              <span className="alert-message">{successMessage}</span>
              <button className="alert-close" onClick={() => setSuccessMessage(null)}>
                <svg width="14" height="14" viewBox="0 0 14 14" fill="currentColor">
                  <path d="M14 1.41L12.59 0L7 5.59L1.41 0L0 1.41L5.59 7L0 12.59L1.41 14L7 8.41L12.59 14L14 12.59L8.41 7L14 1.41Z"/>
                </svg>
              </button>
            </div>
          )}

          {/* Hero Section */}
          <section className="hero-section">
            <div className="hero-grid">

              {/* Scan Control Card */}
              <div className="hero-card scan-control-card">
                <div className="card-header">
                  <h2 className="card-title">Security Scan</h2>
                  <div className="card-icon">
                    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                    </svg>
                  </div>
                </div>

                <div className="scan-control-content">
                  <p className="scan-description">
                    Run comprehensive security analysis to identify vulnerabilities, compliance issues, and system weaknesses.
                  </p>

                  {statistics.lastScanTime && (
                    <div className="last-scan-info">
                      <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor">
                        <path d="M8 0C3.6 0 0 3.6 0 8s3.6 8 8 8 8-3.6 8-8-3.6-8-8-8zm0 14c-3.3 0-6-2.7-6-6s2.7-6 6-6 6 2.7 6 6-2.7 6-6 6z"/>
                        <path d="M9 4H7v5l4.3 2.5.7-1.2-3-1.8V4z"/>
                      </svg>
                      <span>Last scan: {new Date(statistics.lastScanTime).toLocaleString()}</span>
                    </div>
                  )}

                  <button
                    className={`btn btn-primary btn-scan ${scanning ? 'scanning' : ''}`}
                    onClick={handleStartScan}
                    disabled={scanning || backendStatus !== 'connected'}
                  >
                    {scanning ? (
                      <>
                        <span className="btn-spinner"></span>
                        <span>Scanning System...</span>
                      </>
                    ) : (
                      <>
                        <svg width="20" height="20" viewBox="0 0 20 20" fill="currentColor">
                          <path d="M10 0L0 6V10C0 15.55 4.84 20.74 10 22C15.16 20.74 20 15.55 20 10V6L10 0ZM10 10.99L5 13.99V8.99L10 5.99L15 8.99V13.99L10 10.99Z"/>
                        </svg>
                        <span>Start Security Scan</span>
                      </>
                    )}
                  </button>

                  {scanning && (
                    <div className="scan-progress">
                      <div className="progress-bar">
                        <div
                          className="progress-fill"
                          style={{ width: `${scanProgress}%` }}
                        >
                          <div className="progress-shine"></div>
                        </div>
                      </div>
                      <div className="progress-text">
                        <span className="progress-label">Analyzing security posture</span>
                        <span className="progress-percentage">{scanProgress}%</span>
                      </div>
                    </div>
                  )}
                </div>
              </div>

              {/* Compliance Score Card */}
              <div className="hero-card compliance-card">
                <div className="card-header">
                  <h2 className="card-title">Compliance Score</h2>
                  <div className="card-icon">
                    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/>
                      <polyline points="22 4 12 14.01 9 11.01"/>
                    </svg>
                  </div>
                </div>

                <div className="compliance-content">
                  <div className="compliance-circle">
                    <svg className="compliance-svg" viewBox="0 0 200 200">
                      <defs>
                        <linearGradient id="compliance-gradient" x1="0%" y1="0%" x2="100%" y2="100%">
                          <stop offset="0%" stopColor="var(--primary)" />
                          <stop offset="100%" stopColor="var(--secondary)" />
                        </linearGradient>
                      </defs>
                      <circle
                        cx="100"
                        cy="100"
                        r="85"
                        fill="none"
                        stroke="rgba(255,255,255,0.1)"
                        strokeWidth="12"
                      />
                      <circle
                        cx="100"
                        cy="100"
                        r="85"
                        fill="none"
                        stroke="url(#compliance-gradient)"
                        strokeWidth="12"
                        strokeLinecap="round"
                        strokeDasharray={`${statistics.complianceScore * 5.34} 534`}
                        transform="rotate(-90 100 100)"
                        className="compliance-progress"
                      />
                    </svg>
                    <div className="compliance-value" style={{ color: getComplianceColor(statistics.complianceScore) }}>
                      <span className="compliance-number">{statistics.complianceScore}</span>
                      <span className="compliance-percent">%</span>
                    </div>
                  </div>

                  <div className="compliance-info">
                    <p className="compliance-label">Security Compliance</p>
                    <p className="compliance-description">
                      {statistics.complianceScore >= 90 ? 'Excellent security posture' :
                       statistics.complianceScore >= 70 ? 'Good, but needs improvement' :
                       statistics.complianceScore > 0 ? 'Critical issues detected' :
                       'Run a scan to assess compliance'}
                    </p>
                  </div>
                </div>
              </div>

            </div>
          </section>

          {/* Statistics Grid */}
          <section className="stats-section">
            <div className="stats-grid">

              <div className="stat-card stat-total">
                <div className="stat-icon">
                  <svg width="32" height="32" viewBox="0 0 32 32" fill="currentColor">
                    <path d="M16 2L4 8v8c0 7.73 5.36 14.95 12 16.72C22.64 30.95 28 23.73 28 16V8L16 2zm0 26.9C10.65 27.13 6 21.45 6 16V9.46l10-5 10 5V16c0 5.45-4.65 11.13-10 12.9z"/>
                  </svg>
                </div>
                <div className="stat-content">
                  <div className="stat-value">{formatNumber(statistics.totalVulnerabilities)}</div>
                  <div className="stat-label">Total Issues</div>
                </div>
                <div className="stat-glow"></div>
              </div>

              <div className="stat-card stat-critical">
                <div className="stat-icon">
                  <svg width="32" height="32" viewBox="0 0 32 32" fill="currentColor">
                    <path d="M16 2L2 28h28L16 2zm0 6l9.5 16.5h-19L16 8zm-1 13v2h2v-2h-2zm0-8v6h2v-6h-2z"/>
                  </svg>
                </div>
                <div className="stat-content">
                  <div className="stat-value">{formatNumber(statistics.critical)}</div>
                  <div className="stat-label">Critical</div>
                </div>
                <div className="stat-glow"></div>
              </div>

              <div className="stat-card stat-high">
                <div className="stat-icon">
                  <svg width="32" height="32" viewBox="0 0 32 32" fill="currentColor">
                    <path d="M16 4C9.4 4 4 9.4 4 16s5.4 12 12 12 12-5.4 12-12S22.6 4 16 4zm0 22c-5.5 0-10-4.5-10-10S10.5 6 16 6s10 4.5 10 10-4.5 10-10 10z"/>
                    <path d="M15 11h2v8h-2zm0 10h2v2h-2z"/>
                  </svg>
                </div>
                <div className="stat-content">
                  <div className="stat-value">{formatNumber(statistics.high)}</div>
                  <div className="stat-label">High</div>
                </div>
                <div className="stat-glow"></div>
              </div>

              <div className="stat-card stat-medium">
                <div className="stat-icon">
                  <svg width="32" height="32" viewBox="0 0 32 32" fill="currentColor">
                    <circle cx="16" cy="16" r="12" fill="none" stroke="currentColor" strokeWidth="2"/>
                    <path d="M16 10v8m0 2v2"/>
                  </svg>
                </div>
                <div className="stat-content">
                  <div className="stat-value">{formatNumber(statistics.medium)}</div>
                  <div className="stat-label">Medium</div>
                </div>
                <div className="stat-glow"></div>
              </div>

              <div className="stat-card stat-low">
                <div className="stat-icon">
                  <svg width="32" height="32" viewBox="0 0 32 32" fill="currentColor">
                    <circle cx="16" cy="16" r="12" fill="none" stroke="currentColor" strokeWidth="2"/>
                    <path d="M12 16l3 3 6-6"/>
                  </svg>
                </div>
                <div className="stat-content">
                  <div className="stat-value">{formatNumber(statistics.low)}</div>
                  <div className="stat-label">Low</div>
                </div>
                <div className="stat-glow"></div>
              </div>

            </div>
          </section>

          {/* System Information */}
          {systemInfo && (
            <section className="system-section">
              <div className="section-header">
                <h2 className="section-title">System Information</h2>
                <div className="section-icon">
                  <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <rect x="2" y="3" width="20" height="14" rx="2" ry="2"/>
                    <line x1="8" y1="21" x2="16" y2="21"/>
                    <line x1="12" y1="17" x2="12" y2="21"/>
                  </svg>
                </div>
              </div>

              <div className="system-grid">
                <div className="system-card">
                  <div className="system-label">Operating System</div>
                  <div className="system-value">{systemInfo.platform || 'Unknown'} {systemInfo.platform_release || ''}</div>
                </div>
                <div className="system-card">
                  <div className="system-label">Hostname</div>
                  <div className="system-value">{systemInfo.hostname || 'Unknown'}</div>
                </div>
                <div className="system-card">
                  <div className="system-label">Architecture</div>
                  <div className="system-value">{systemInfo.architecture || 'Unknown'}</div>
                </div>
                <div className="system-card">
                  <div className="system-label">CPU Usage</div>
                  <div className="system-value">
                    {systemInfo.cpu_percent ? (
                      <span className="metric-value">{systemInfo.cpu_percent}%</span>
                    ) : 'N/A'}
                  </div>
                </div>
                <div className="system-card">
                  <div className="system-label">Memory Usage</div>
                  <div className="system-value">
                    {systemInfo.memory_percent ? (
                      <span className="metric-value">{systemInfo.memory_percent}%</span>
                    ) : 'N/A'}
                  </div>
                </div>
                <div className="system-card">
                  <div className="system-label">Disk Usage</div>
                  <div className="system-value">
                    {systemInfo.disk_percent ? (
                      <span className="metric-value">{systemInfo.disk_percent}%</span>
                    ) : 'N/A'}
                  </div>
                </div>
              </div>
            </section>
          )}

          {/* Report Generation */}
          {scanData && (
            <section className="report-section">
              <div className="report-card">
                <div className="report-header">
                  <div className="report-info">
                    <h3 className="report-title">Generate Security Report</h3>
                    <p className="report-description">Export detailed security analysis in your preferred format</p>
                  </div>
                  <div className="report-icon">
                    <svg width="48" height="48" viewBox="0 0 48 48" fill="none" stroke="currentColor" strokeWidth="2">
                      <path d="M28 4H12a4 4 0 0 0-4 4v32a4 4 0 0 0 4 4h24a4 4 0 0 0 4-4V16L28 4z"/>
                      <polyline points="28 4 28 16 40 16"/>
                      <line x1="16" y1="24" x2="32" y2="24"/>
                      <line x1="16" y1="30" x2="32" y2="30"/>
                      <line x1="16" y1="36" x2="24" y2="36"/>
                    </svg>
                  </div>
                </div>

                <div className="report-controls">
                  <div className="format-selector">
                    <label htmlFor="reportFormat" className="format-label">
                      <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor">
                        <path d="M8 0L0 4v6c0 4.97 3.44 9.62 8 10.75C12.56 19.62 16 14.97 16 10V4L8 0z"/>
                      </svg>
                      <span>Report Format</span>
                    </label>
                    <select
                      id="reportFormat"
                      className="format-select"
                      value={reportFormat}
                      onChange={(e) => setReportFormat(e.target.value)}
                      disabled={generatingReport}
                    >
                      <option value="pdf">PDF Document</option>
                      <option value="excel">Excel Spreadsheet (.xlsx)</option>
                      <option value="csv">CSV Data (.csv)</option>
                      <option value="docx">Word Document (.docx)</option>
                      <option value="markdown">Markdown (.md)</option>
                      <option value="html">HTML Page</option>
                      <option value="json">JSON Data</option>
                    </select>
                  </div>

                  <button
                    className="btn btn-secondary btn-report"
                    onClick={handleGenerateReport}
                    disabled={generatingReport}
                  >
                    {generatingReport ? (
                      <>
                        <span className="btn-spinner"></span>
                        <span>Generating...</span>
                      </>
                    ) : (
                      <>
                        <svg width="20" height="20" viewBox="0 0 20 20" fill="currentColor">
                          <path d="M10 0L2 4v6c0 4.97 3.44 9.62 8 10.75C14.56 19.62 18 14.97 18 10V4L10 0zm0 18.7C5.91 17.58 4 13.43 4 10V5.43l6-2.68 6 2.68V10c0 3.43-1.91 7.58-6 8.7z"/>
                          <path d="M7 9l2 2 4-4"/>
                        </svg>
                        <span>Generate Report</span>
                      </>
                    )}
                  </button>
                </div>
              </div>
            </section>
          )}

          {/* Scan Results */}
          {showResults && scanData && (
            <section className="results-section">
              <ModernScanResults
                scanData={scanData}
                onRefreshNeeded={handleStartScan}
              />
            </section>
          )}

        </div>
      </main>
    </div>
  );
}

export default ModernDashboard;
