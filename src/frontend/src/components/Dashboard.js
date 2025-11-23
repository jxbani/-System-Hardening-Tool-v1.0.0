import React, { useState, useEffect, useCallback } from 'react';
import { getSystemInfo, runScan, checkHealth, applyHardening, generateReport } from '../api/client';
import MonitoringDashboard from './MonitoringDashboard';
import CompliancePanel from './CompliancePanel';
import RemediationPanel from './RemediationPanel';
import HistoryViewer from './HistoryViewer';
import RiskDashboard from './RiskDashboard';

function Dashboard() {
  // State management
  const [systemInfo, setSystemInfo] = useState(null);
  const [statistics, setStatistics] = useState({
    vulnerabilities: 0,
    complianceScore: 0,
    critical: 0,
    warning: 0,
  });
  const [scanResults, setScanResults] = useState([]);
  const [fullScanData, setFullScanData] = useState(null); // Store full scan response for reporting
  const [recentActivity, setRecentActivity] = useState([]);
  const [loading, setLoading] = useState(true);
  const [scanning, setScanning] = useState(false);
  const [fixing, setFixing] = useState(false);
  const [generatingReport, setGeneratingReport] = useState(false);
  const [reportFormat, setReportFormat] = useState('pdf'); // Selected report format
  const [error, setError] = useState(null);
  const [backendStatus, setBackendStatus] = useState('checking');
  const [activeView, setActiveView] = useState('dashboard'); // dashboard, monitoring, compliance, remediation

  /**
   * Add activity to recent activity list
   */
  const addActivity = useCallback((message, type = 'info') => {
    const newActivity = {
      id: Date.now(),
      message,
      type,
      timestamp: new Date().toLocaleTimeString(),
    };

    setRecentActivity(prev => [newActivity, ...prev.slice(0, 4)]);
  }, []);

  /**
   * Fetch all dashboard data
   */
  const fetchDashboardData = useCallback(async () => {
    setLoading(true);
    setError(null);

    try {
      // Check backend health
      await checkHealth();
      setBackendStatus('connected');

      // Fetch system information
      const response = await getSystemInfo();
      // Extract the data object from the response
      const sysInfo = response.data || response;
      setSystemInfo(sysInfo);

      // Add initial activity
      addActivity('Dashboard loaded', 'info');
    } catch (err) {
      console.error('Error fetching dashboard data:', err);
      setError(err.message);
      setBackendStatus('disconnected');
    } finally {
      setLoading(false);
    }
  }, [addActivity]);

  // Fetch initial data on component mount
  useEffect(() => {
    fetchDashboardData();
  }, [fetchDashboardData]);

  /**
   * Handle scan button click
   */
  const handleStartScan = async () => {
    setScanning(true);
    setError(null);
    addActivity('Security scan started', 'info');

    try {
      const results = await runScan();

      // Save full scan data for reporting
      setFullScanData(results);

      // Update statistics with scan results
      if (results) {
        setStatistics({
          vulnerabilities: results.totalVulnerabilities || 0,
          complianceScore: results.complianceScore || 0,
          critical: results.criticalIssues || 0,
          warning: results.warnings || 0,
        });

        // Transform results into table format
        if (results.findings && Array.isArray(results.findings)) {
          setScanResults(results.findings);
        } else {
          // Mock data for demonstration if no findings
          setScanResults([
            {
              id: 1,
              category: 'Network',
              severity: 'Critical',
              description: 'SSH running with weak encryption',
              status: 'Open',
              timestamp: new Date().toLocaleString()
            },
            {
              id: 2,
              category: 'File System',
              severity: 'Warning',
              description: 'Incorrect file permissions on /etc/shadow',
              status: 'Open',
              timestamp: new Date().toLocaleString()
            }
          ]);
        }
      }

      addActivity('Security scan completed successfully', 'success');
    } catch (err) {
      console.error('Error running scan:', err);
      setError(err.message);
      addActivity('Security scan failed', 'error');
    } finally {
      setScanning(false);
    }
  };

  /**
   * Handle fix vulnerabilities button click
   */
  const handleFixVulnerabilities = async () => {
    if (!scanResults || scanResults.length === 0) {
      setError('Please run a scan first to identify vulnerabilities');
      return;
    }

    setFixing(true);
    setError(null);
    addActivity('Applying security fixes...', 'info');

    try {
      // Extract rule IDs from scan results if available, otherwise use default
      const rules = scanResults.map((result) => result.id || result.category);

      const results = await applyHardening(rules);

      console.log('Hardening results:', results);

      addActivity(`Applied ${results.changes_applied || 0} security fixes`, 'success');

      // Optionally refresh the scan to show improvements
      setTimeout(() => {
        addActivity('Run a new scan to verify fixes', 'info');
      }, 1000);
    } catch (err) {
      console.error('Error applying fixes:', err);
      setError(err.message);
      addActivity('Failed to apply security fixes', 'error');
    } finally {
      setFixing(false);
    }
  };

  /**
   * Handle generate PDF report button click
   */
  const handleGenerateReport = async () => {
    if (!fullScanData) {
      setError('Please run a scan first before generating a report');
      addActivity('Cannot generate report - no scan data available', 'error');
      return;
    }

    setGeneratingReport(true);
    setError(null);

    const formatNames = {
      'pdf': 'PDF',
      'html': 'HTML',
      'excel': 'Excel',
      'csv': 'CSV',
      'docx': 'Word',
      'markdown': 'Markdown'
    };

    const formatExtensions = {
      'pdf': '.pdf',
      'html': '.html',
      'excel': '.xlsx',
      'csv': '.csv',
      'docx': '.docx',
      'markdown': '.md'
    };

    const formatName = formatNames[reportFormat] || reportFormat.toUpperCase();
    const extension = formatExtensions[reportFormat] || `.${reportFormat}`;

    addActivity(`Generating ${formatName} report...`, 'info');

    try {
      const blob = await generateReport({
        format: reportFormat,
        title: 'System Security Report',
        scan_results: fullScanData
      });

      console.log('Report generated successfully');

      // Create a download link for the report blob
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `security-report-${new Date().toISOString().split('T')[0]}${extension}`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      window.URL.revokeObjectURL(url);

      addActivity(`${formatName} report downloaded successfully`, 'success');
    } catch (err) {
      console.error('Error generating report:', err);
      setError(err.message);
      addActivity(`Failed to generate ${formatName} report`, 'error');
    } finally {
      setGeneratingReport(false);
    }
  };

  /**
   * Navigate to a section
   */
  const navigateToSection = (section) => {
    console.log(`Navigating to: ${section}`);
    setActiveView(section.toLowerCase());
    addActivity(`Navigated to ${section}`, 'info');
  };

  /**
   * Get severity color
   */
  const getSeverityColor = (severity) => {
    switch (severity?.toLowerCase()) {
      case 'critical':
        return '#dc3545';
      case 'high':
        return '#fd7e14';
      case 'warning':
      case 'medium':
        return '#ffc107';
      case 'low':
      case 'info':
        return '#17a2b8';
      default:
        return '#6c757d';
    }
  };

  // Inline Styles
  const styles = {
    dashboardContainer: {
      padding: '20px',
      maxWidth: '1400px',
      margin: '0 auto',
      backgroundColor: '#f5f7fa',
      minHeight: '100vh',
      fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif',
    },
    dashboardHeader: {
      display: 'flex',
      justifyContent: 'space-between',
      alignItems: 'center',
      marginBottom: '30px',
      padding: '20px',
      backgroundColor: '#ffffff',
      borderRadius: '8px',
      boxShadow: '0 2px 4px rgba(0,0,0,0.1)',
    },
    headerTitle: {
      margin: 0,
      fontSize: '28px',
      color: '#2c3e50',
      fontWeight: '600',
    },
    backendStatus: {
      display: 'flex',
      alignItems: 'center',
      gap: '8px',
      fontSize: '14px',
      fontWeight: '500',
      padding: '8px 16px',
      borderRadius: '20px',
      backgroundColor: '#f8f9fa',
    },
    statusIndicator: {
      width: '10px',
      height: '10px',
      borderRadius: '50%',
      animation: backendStatus === 'connected' ? 'pulse 2s infinite' : 'none',
    },
    statusConnected: {
      backgroundColor: '#28a745',
    },
    statusDisconnected: {
      backgroundColor: '#dc3545',
    },
    statusChecking: {
      backgroundColor: '#ffc107',
    },
    alert: {
      padding: '15px 20px',
      marginBottom: '20px',
      borderRadius: '8px',
      display: 'flex',
      alignItems: 'center',
      gap: '12px',
      backgroundColor: '#f8d7da',
      color: '#721c24',
      border: '1px solid #f5c6cb',
    },
    alertClose: {
      marginLeft: 'auto',
      background: 'none',
      border: 'none',
      fontSize: '24px',
      cursor: 'pointer',
      color: '#721c24',
      lineHeight: '1',
    },
    dashboardGrid: {
      display: 'grid',
      gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))',
      gap: '20px',
      marginBottom: '30px',
    },
    card: {
      backgroundColor: '#ffffff',
      borderRadius: '8px',
      padding: '24px',
      boxShadow: '0 2px 8px rgba(0,0,0,0.1)',
      transition: 'transform 0.2s, box-shadow 0.2s',
    },
    cardHover: {
      transform: 'translateY(-2px)',
      boxShadow: '0 4px 12px rgba(0,0,0,0.15)',
    },
    cardTitle: {
      margin: '0 0 20px 0',
      fontSize: '20px',
      color: '#2c3e50',
      fontWeight: '600',
      borderBottom: '2px solid #e9ecef',
      paddingBottom: '10px',
    },
    infoGrid: {
      display: 'grid',
      gap: '12px',
    },
    infoItem: {
      display: 'flex',
      justifyContent: 'space-between',
      padding: '10px',
      backgroundColor: '#f8f9fa',
      borderRadius: '6px',
    },
    infoLabel: {
      fontWeight: '500',
      color: '#6c757d',
    },
    infoValue: {
      fontWeight: '600',
      color: '#2c3e50',
    },
    statsGrid: {
      display: 'grid',
      gridTemplateColumns: 'repeat(2, 1fr)',
      gap: '16px',
    },
    statItem: {
      textAlign: 'center',
      padding: '20px',
      backgroundColor: '#f8f9fa',
      borderRadius: '8px',
      border: '2px solid #e9ecef',
    },
    statValue: {
      fontSize: '32px',
      fontWeight: '700',
      color: '#2c3e50',
      marginBottom: '8px',
    },
    statValueCritical: {
      color: '#dc3545',
    },
    statValueWarning: {
      color: '#ffc107',
    },
    statValueScore: {
      color: '#28a745',
    },
    statLabel: {
      fontSize: '14px',
      color: '#6c757d',
      fontWeight: '500',
    },
    scanCard: {
      textAlign: 'center',
    },
    scanDescription: {
      color: '#6c757d',
      marginBottom: '20px',
      lineHeight: '1.6',
    },
    btnPrimary: {
      backgroundColor: '#007bff',
      color: '#ffffff',
      border: 'none',
      padding: '12px 32px',
      fontSize: '16px',
      fontWeight: '600',
      borderRadius: '6px',
      cursor: 'pointer',
      transition: 'background-color 0.2s, transform 0.1s',
      display: 'inline-flex',
      alignItems: 'center',
      gap: '8px',
      width: '100%',
      justifyContent: 'center',
    },
    btnPrimaryHover: {
      backgroundColor: '#0056b3',
    },
    btnDisabled: {
      backgroundColor: '#6c757d',
      cursor: 'not-allowed',
      opacity: 0.6,
    },
    btnSuccess: {
      backgroundColor: '#28a745',
      color: '#ffffff',
      border: 'none',
      padding: '12px 32px',
      fontSize: '16px',
      fontWeight: '600',
      borderRadius: '6px',
      cursor: 'pointer',
      transition: 'background-color 0.2s, transform 0.1s',
      display: 'inline-flex',
      alignItems: 'center',
      gap: '8px',
      marginRight: '12px',
    },
    btnWarning: {
      backgroundColor: '#ffc107',
      color: '#000000',
      border: 'none',
      padding: '12px 32px',
      fontSize: '16px',
      fontWeight: '600',
      borderRadius: '6px',
      cursor: 'pointer',
      transition: 'background-color 0.2s, transform 0.1s',
      display: 'inline-flex',
      alignItems: 'center',
      gap: '8px',
    },
    actionButtons: {
      display: 'flex',
      gap: '12px',
      marginTop: '20px',
      marginBottom: '20px',
      flexWrap: 'wrap',
      alignItems: 'center',
    },
    formatSelectorContainer: {
      display: 'flex',
      alignItems: 'center',
      gap: '8px',
      padding: '8px 12px',
      backgroundColor: '#f8f9fa',
      borderRadius: '8px',
      border: '1px solid #dee2e6',
    },
    formatLabel: {
      fontSize: '14px',
      fontWeight: '500',
      color: '#495057',
      whiteSpace: 'nowrap',
    },
    formatSelect: {
      padding: '8px 12px',
      fontSize: '14px',
      borderRadius: '6px',
      border: '1px solid #ced4da',
      backgroundColor: '#ffffff',
      color: '#495057',
      cursor: 'pointer',
      outline: 'none',
      transition: 'border-color 0.15s ease-in-out, box-shadow 0.15s ease-in-out',
    },
    scanWarning: {
      marginTop: '12px',
      color: '#dc3545',
      fontSize: '14px',
      fontStyle: 'italic',
    },
    activityList: {
      listStyle: 'none',
      padding: 0,
      margin: 0,
    },
    activityItem: {
      display: 'flex',
      alignItems: 'center',
      gap: '12px',
      padding: '12px',
      borderBottom: '1px solid #e9ecef',
    },
    activityDot: {
      width: '8px',
      height: '8px',
      borderRadius: '50%',
      flexShrink: 0,
    },
    activityDotSuccess: {
      backgroundColor: '#28a745',
    },
    activityDotError: {
      backgroundColor: '#dc3545',
    },
    activityDotInfo: {
      backgroundColor: '#17a2b8',
    },
    activityContent: {
      display: 'flex',
      flexDirection: 'column',
      gap: '4px',
      flex: 1,
    },
    activityMessage: {
      fontSize: '14px',
      color: '#2c3e50',
      fontWeight: '500',
    },
    activityTime: {
      fontSize: '12px',
      color: '#6c757d',
    },
    navButtons: {
      display: 'grid',
      gridTemplateColumns: 'repeat(2, 1fr)',
      gap: '12px',
    },
    navBtn: {
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
      gap: '8px',
      padding: '16px',
      backgroundColor: '#f8f9fa',
      border: '2px solid #e9ecef',
      borderRadius: '8px',
      cursor: 'pointer',
      transition: 'all 0.2s',
      fontSize: '14px',
      fontWeight: '500',
      color: '#2c3e50',
    },
    navIcon: {
      fontSize: '24px',
    },
    loadingState: {
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
      justifyContent: 'center',
      minHeight: '400px',
      gap: '20px',
    },
    spinner: {
      width: '50px',
      height: '50px',
      border: '4px solid #f3f3f3',
      borderTop: '4px solid #007bff',
      borderRadius: '50%',
      animation: 'spin 1s linear infinite',
    },
    spinnerSmall: {
      width: '16px',
      height: '16px',
      border: '2px solid #ffffff',
      borderTop: '2px solid transparent',
      borderRadius: '50%',
      display: 'inline-block',
      animation: 'spin 1s linear infinite',
    },
    noData: {
      textAlign: 'center',
      color: '#6c757d',
      fontStyle: 'italic',
      padding: '20px',
    },
    resultsSection: {
      marginTop: '30px',
    },
    tableContainer: {
      backgroundColor: '#ffffff',
      borderRadius: '8px',
      padding: '24px',
      boxShadow: '0 2px 8px rgba(0,0,0,0.1)',
      overflowX: 'auto',
    },
    table: {
      width: '100%',
      borderCollapse: 'collapse',
    },
    tableHeader: {
      backgroundColor: '#f8f9fa',
      borderBottom: '2px solid #dee2e6',
    },
    th: {
      padding: '12px 16px',
      textAlign: 'left',
      fontWeight: '600',
      color: '#2c3e50',
      fontSize: '14px',
      textTransform: 'uppercase',
      letterSpacing: '0.5px',
    },
    td: {
      padding: '12px 16px',
      borderBottom: '1px solid #e9ecef',
      color: '#495057',
      fontSize: '14px',
    },
    tableRow: {
      transition: 'background-color 0.2s',
    },
    severityBadge: {
      display: 'inline-block',
      padding: '4px 12px',
      borderRadius: '12px',
      fontSize: '12px',
      fontWeight: '600',
      color: '#ffffff',
      textTransform: 'uppercase',
    },
    statusBadge: {
      display: 'inline-block',
      padding: '4px 12px',
      borderRadius: '12px',
      fontSize: '12px',
      fontWeight: '600',
      backgroundColor: '#ffc107',
      color: '#000000',
    },
  };

  // Loading state
  if (loading) {
    return (
      <div style={styles.dashboardContainer}>
        <div style={styles.loadingState}>
          <div style={styles.spinner}></div>
          <p>Loading dashboard...</p>
        </div>
        <style>
          {`
            @keyframes spin {
              0% { transform: rotate(0deg); }
              100% { transform: rotate(360deg); }
            }
            @keyframes pulse {
              0%, 100% { opacity: 1; }
              50% { opacity: 0.5; }
            }
          `}
        </style>
      </div>
    );
  }

  return (
    <div style={styles.dashboardContainer}>
      <style>
        {`
          @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
          }
          @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
          }
          .card:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
          }
          .nav-btn:hover {
            background-color: #007bff !important;
            color: #ffffff !important;
            border-color: #007bff !important;
          }
          .btn-primary:not(:disabled):hover {
            background-color: #0056b3 !important;
          }
          .table-row:hover {
            background-color: #f8f9fa;
          }
        `}
      </style>

      <div style={styles.dashboardHeader}>
        <h1 style={styles.headerTitle}>Security Dashboard</h1>
        <div style={styles.backendStatus}>
          <span style={{
            ...styles.statusIndicator,
            ...(backendStatus === 'connected' ? styles.statusConnected :
                backendStatus === 'disconnected' ? styles.statusDisconnected :
                styles.statusChecking)
          }}></span>
          Backend: {backendStatus}
        </div>
      </div>

      {/* Error Alert */}
      {error && (
        <div style={styles.alert}>
          <span>⚠️</span>
          <span>{error}</span>
          <button
            style={styles.alertClose}
            onClick={() => setError(null)}
            aria-label="Close"
          >
            ×
          </button>
        </div>
      )}

      {/* Back to Dashboard button when viewing other panels */}
      {activeView !== 'dashboard' && (
        <button
          style={{
            ...styles.btnPrimary,
            marginBottom: '20px',
            width: 'auto',
          }}
          onClick={() => setActiveView('dashboard')}
        >
          ← Back to Dashboard
        </button>
      )}

      {/* Render different views based on activeView state */}
      {activeView === 'monitoring' && <MonitoringDashboard />}
      {activeView === 'compliance' && <CompliancePanel />}
      {activeView === 'remediation' && <RemediationPanel />}
      {activeView === 'history' && <HistoryViewer />}
      {activeView === 'risk' && <RiskDashboard />}

      {/* Main Dashboard View */}
      {activeView === 'dashboard' && (
      <>
      <div style={styles.dashboardGrid}>
        {/* System Information Card */}
        <div style={styles.card} className="card">
          <h2 style={styles.cardTitle}>System Information</h2>
          {systemInfo ? (
            <div style={styles.infoGrid}>
              <div style={styles.infoItem}>
                <span style={styles.infoLabel}>Operating System:</span>
                <span style={styles.infoValue}>
                  {systemInfo.platform || 'Unknown'} {systemInfo.platform_release || ''}
                </span>
              </div>
              <div style={styles.infoItem}>
                <span style={styles.infoLabel}>Hostname:</span>
                <span style={styles.infoValue}>{systemInfo.hostname || 'Unknown'}</span>
              </div>
              <div style={styles.infoItem}>
                <span style={styles.infoLabel}>Architecture:</span>
                <span style={styles.infoValue}>{systemInfo.architecture || 'Unknown'}</span>
              </div>
              <div style={styles.infoItem}>
                <span style={styles.infoLabel}>CPU Usage:</span>
                <span style={styles.infoValue}>{systemInfo.cpu_percent ? `${systemInfo.cpu_percent}%` : 'N/A'}</span>
              </div>
              <div style={styles.infoItem}>
                <span style={styles.infoLabel}>Memory Usage:</span>
                <span style={styles.infoValue}>{systemInfo.memory_percent ? `${systemInfo.memory_percent}%` : 'N/A'}</span>
              </div>
              <div style={styles.infoItem}>
                <span style={styles.infoLabel}>Disk Usage:</span>
                <span style={styles.infoValue}>{systemInfo.disk_percent ? `${systemInfo.disk_percent}%` : 'N/A'}</span>
              </div>
            </div>
          ) : (
            <p style={styles.noData}>No system information available</p>
          )}
        </div>

        {/* Quick Statistics */}
        <div style={styles.card} className="card">
          <h2 style={styles.cardTitle}>Security Overview</h2>
          <div style={styles.statsGrid}>
            <div style={styles.statItem}>
              <div style={styles.statValue}>{statistics.vulnerabilities}</div>
              <div style={styles.statLabel}>Vulnerabilities</div>
            </div>
            <div style={styles.statItem}>
              <div style={{...styles.statValue, ...styles.statValueScore}}>{statistics.complianceScore}%</div>
              <div style={styles.statLabel}>Compliance Score</div>
            </div>
            <div style={styles.statItem}>
              <div style={{...styles.statValue, ...styles.statValueCritical}}>{statistics.critical}</div>
              <div style={styles.statLabel}>Critical Issues</div>
            </div>
            <div style={styles.statItem}>
              <div style={{...styles.statValue, ...styles.statValueWarning}}>{statistics.warning}</div>
              <div style={styles.statLabel}>Warnings</div>
            </div>
          </div>
        </div>

        {/* Scan Action Card */}
        <div style={{...styles.card, ...styles.scanCard}} className="card">
          <h2 style={styles.cardTitle}>Security Scan</h2>
          <p style={styles.scanDescription}>Run a comprehensive security scan to identify vulnerabilities and compliance issues.</p>
          <button
            style={{
              ...styles.btnPrimary,
              ...(scanning || backendStatus !== 'connected' ? styles.btnDisabled : {})
            }}
            className="btn-primary"
            onClick={handleStartScan}
            disabled={scanning || backendStatus !== 'connected'}
          >
            {scanning ? (
              <>
                <span style={styles.spinnerSmall}></span>
                Scanning...
              </>
            ) : (
              'Start Security Scan'
            )}
          </button>
          {backendStatus !== 'connected' && (
            <p style={styles.scanWarning}>Backend must be connected to run scan</p>
          )}
        </div>

        {/* Recent Activity */}
        <div style={styles.card} className="card">
          <h2 style={styles.cardTitle}>Recent Activity</h2>
          {recentActivity.length > 0 ? (
            <ul style={styles.activityList}>
              {recentActivity.map(activity => (
                <li key={activity.id} style={styles.activityItem}>
                  <span style={{
                    ...styles.activityDot,
                    ...(activity.type === 'success' ? styles.activityDotSuccess :
                        activity.type === 'error' ? styles.activityDotError :
                        styles.activityDotInfo)
                  }}></span>
                  <div style={styles.activityContent}>
                    <span style={styles.activityMessage}>{activity.message}</span>
                    <span style={styles.activityTime}>{activity.timestamp}</span>
                  </div>
                </li>
              ))}
            </ul>
          ) : (
            <p style={styles.noData}>No recent activity</p>
          )}
        </div>

        {/* Navigation Panel */}
        <div style={styles.card} className="card">
          <h2 style={styles.cardTitle}>Advanced Features</h2>
          <div style={{display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '12px'}}>
            <button
              style={styles.navBtn}
              className="nav-btn"
              onClick={() => navigateToSection('monitoring')}
            >
              <span style={styles.navIcon}>📡</span>
              <span>Monitoring</span>
            </button>
            <button
              style={styles.navBtn}
              className="nav-btn"
              onClick={() => navigateToSection('compliance')}
            >
              <span style={styles.navIcon}>📋</span>
              <span>Compliance</span>
            </button>
            <button
              style={styles.navBtn}
              className="nav-btn"
              onClick={() => navigateToSection('remediation')}
            >
              <span style={styles.navIcon}>🔧</span>
              <span>Remediation</span>
            </button>
            <button
              style={styles.navBtn}
              className="nav-btn"
              onClick={() => navigateToSection('risk')}
            >
              <span style={styles.navIcon}>⚠️</span>
              <span>Risk Analysis</span>
            </button>
            <button
              style={styles.navBtn}
              className="nav-btn"
              onClick={() => navigateToSection('history')}
            >
              <span style={styles.navIcon}>📊</span>
              <span>History</span>
            </button>
          </div>
        </div>
      </div>

      {/* Scan Results Table */}
      {scanResults.length > 0 && (
        <div style={styles.resultsSection}>
          <div style={styles.tableContainer}>
            <h2 style={styles.cardTitle}>Scan Results</h2>

            {/* Action Buttons */}
            <div style={styles.actionButtons}>
              <button
                style={{
                  ...styles.btnSuccess,
                  ...(fixing || backendStatus !== 'connected' ? styles.btnDisabled : {})
                }}
                onClick={handleFixVulnerabilities}
                disabled={fixing || backendStatus !== 'connected'}
              >
                {fixing ? (
                  <>
                    <span style={styles.spinnerSmall}></span>
                    Fixing...
                  </>
                ) : (
                  <>
                    🛠️ Fix Vulnerabilities
                  </>
                )}
              </button>

              {/* Report Format Selector */}
              <div style={styles.formatSelectorContainer}>
                <label htmlFor="reportFormat" style={styles.formatLabel}>
                  Report Format:
                </label>
                <select
                  id="reportFormat"
                  value={reportFormat}
                  onChange={(e) => setReportFormat(e.target.value)}
                  style={styles.formatSelect}
                  disabled={generatingReport}
                >
                  <option value="pdf">PDF</option>
                  <option value="excel">Excel (.xlsx)</option>
                  <option value="csv">CSV</option>
                  <option value="docx">Word (.docx)</option>
                  <option value="markdown">Markdown (.md)</option>
                  <option value="html">HTML</option>
                </select>
              </div>

              <button
                style={{
                  ...styles.btnWarning,
                  ...(generatingReport ? styles.btnDisabled : {})
                }}
                onClick={handleGenerateReport}
                disabled={generatingReport}
              >
                {generatingReport ? (
                  <>
                    <span style={styles.spinnerSmall}></span>
                    Generating...
                  </>
                ) : (
                  <>
                    📄 Generate Report
                  </>
                )}
              </button>
            </div>

            <table style={styles.table}>
              <thead style={styles.tableHeader}>
                <tr>
                  <th style={styles.th}>ID</th>
                  <th style={styles.th}>Category</th>
                  <th style={styles.th}>Severity</th>
                  <th style={styles.th}>Description</th>
                  <th style={styles.th}>Status</th>
                  <th style={styles.th}>Timestamp</th>
                </tr>
              </thead>
              <tbody>
                {scanResults.map((result, index) => (
                  <tr key={result.id || index} style={styles.tableRow} className="table-row">
                    <td style={styles.td}>{result.id || index + 1}</td>
                    <td style={styles.td}>{result.category || 'N/A'}</td>
                    <td style={styles.td}>
                      <span style={{
                        ...styles.severityBadge,
                        backgroundColor: getSeverityColor(result.severity)
                      }}>
                        {result.severity || 'Unknown'}
                      </span>
                    </td>
                    <td style={styles.td}>{result.description || 'No description'}</td>
                    <td style={styles.td}>
                      <span style={styles.statusBadge}>
                        {result.status || 'Open'}
                      </span>
                    </td>
                    <td style={styles.td}>{result.timestamp || new Date().toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
      </>
      )}
    </div>
  );
}

export default Dashboard;
