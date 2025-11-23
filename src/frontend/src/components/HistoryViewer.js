import React, { useState, useEffect } from 'react';
import {
  getScanHistory,
  getHardeningHistory,
  getVulnerabilityTrends,
  getStatistics,
  getScanDetails
} from '../api/client';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  Title,
  Tooltip,
  Legend,
  Filler
} from 'chart.js';
import { Line, Bar } from 'react-chartjs-2';

// Register Chart.js components
ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  Title,
  Tooltip,
  Legend,
  Filler
);

function HistoryViewer() {
  const [activeTab, setActiveTab] = useState('overview');
  const [scanHistory, setScanHistory] = useState([]);
  const [hardeningHistory, setHardeningHistory] = useState([]);
  const [trends, setTrends] = useState(null);
  const [statistics, setStatistics] = useState(null);
  const [selectedScan, setSelectedScan] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [trendDays, setTrendDays] = useState(30);

  useEffect(() => {
    fetchAllData();
  }, [trendDays]);

  const fetchAllData = async () => {
    setLoading(true);
    setError(null);

    try {
      const [scansData, hardeningData, trendsData, statsData] = await Promise.all([
        getScanHistory(20),
        getHardeningHistory(20),
        getVulnerabilityTrends(trendDays),
        getStatistics()
      ]);

      setScanHistory(scansData.scans || []);
      setHardeningHistory(hardeningData.sessions || []);
      setTrends(trendsData);
      setStatistics(statsData);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleScanClick = async (scanId) => {
    try {
      const details = await getScanDetails(scanId);
      setSelectedScan(details);
    } catch (err) {
      setError(err.message);
    }
  };

  const styles = {
    container: {
      padding: '20px',
      backgroundColor: '#ffffff',
      borderRadius: '8px',
      boxShadow: '0 2px 8px rgba(0,0,0,0.1)',
    },
    header: {
      marginBottom: '20px',
      paddingBottom: '15px',
      borderBottom: '2px solid #e9ecef',
    },
    title: {
      margin: '0 0 15px 0',
      fontSize: '24px',
      color: '#2c3e50',
      fontWeight: '600',
    },
    tabs: {
      display: 'flex',
      gap: '8px',
      marginBottom: '20px',
      borderBottom: '2px solid #e9ecef',
      flexWrap: 'wrap',
    },
    tab: {
      padding: '12px 24px',
      fontSize: '14px',
      fontWeight: '600',
      background: 'none',
      border: 'none',
      borderBottom: '3px solid transparent',
      cursor: 'pointer',
      color: '#6c757d',
      transition: 'all 0.2s',
    },
    tabActive: {
      color: '#007bff',
      borderBottomColor: '#007bff',
    },
    statsGrid: {
      display: 'grid',
      gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
      gap: '20px',
      marginBottom: '30px',
    },
    statCard: {
      padding: '20px',
      backgroundColor: '#f8f9fa',
      borderRadius: '8px',
      border: '2px solid #e9ecef',
      textAlign: 'center',
    },
    statValue: {
      fontSize: '32px',
      fontWeight: '700',
      color: '#2c3e50',
      marginBottom: '8px',
    },
    statLabel: {
      fontSize: '14px',
      color: '#6c757d',
      fontWeight: '500',
    },
    chartContainer: {
      padding: '20px',
      backgroundColor: '#ffffff',
      borderRadius: '8px',
      border: '1px solid #e9ecef',
      marginBottom: '20px',
    },
    chartTitle: {
      fontSize: '18px',
      fontWeight: '600',
      color: '#2c3e50',
      marginBottom: '20px',
    },
    historyList: {
      display: 'flex',
      flexDirection: 'column',
      gap: '12px',
    },
    historyItem: {
      padding: '16px',
      backgroundColor: '#f8f9fa',
      borderRadius: '8px',
      border: '1px solid #dee2e6',
      cursor: 'pointer',
      transition: 'all 0.2s',
    },
    historyItemHover: {
      backgroundColor: '#e9ecef',
      borderColor: '#007bff',
    },
    historyHeader: {
      display: 'flex',
      justifyContent: 'space-between',
      alignItems: 'start',
      marginBottom: '8px',
    },
    historyTitle: {
      fontSize: '16px',
      fontWeight: '600',
      color: '#2c3e50',
    },
    historyDate: {
      fontSize: '12px',
      color: '#6c757d',
    },
    historyDetails: {
      display: 'grid',
      gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))',
      gap: '12px',
      fontSize: '14px',
      color: '#495057',
    },
    badge: {
      padding: '4px 12px',
      borderRadius: '12px',
      fontSize: '12px',
      fontWeight: '600',
      display: 'inline-block',
    },
    badgeSuccess: {
      backgroundColor: '#d4edda',
      color: '#155724',
    },
    badgeWarning: {
      backgroundColor: '#fff3cd',
      color: '#856404',
    },
    badgeDanger: {
      backgroundColor: '#f8d7da',
      color: '#721c24',
    },
    error: {
      padding: '12px',
      backgroundColor: '#f8d7da',
      color: '#721c24',
      borderRadius: '6px',
      marginBottom: '15px',
    },
    loading: {
      textAlign: 'center',
      padding: '40px',
      color: '#6c757d',
    },
    emptyState: {
      textAlign: 'center',
      padding: '60px 20px',
      color: '#6c757d',
      fontSize: '16px',
    },
    controls: {
      display: 'flex',
      gap: '12px',
      marginBottom: '20px',
      alignItems: 'center',
    },
    select: {
      padding: '8px 12px',
      fontSize: '14px',
      borderRadius: '6px',
      border: '1px solid #ced4da',
      backgroundColor: '#ffffff',
      cursor: 'pointer',
    },
  };

  const renderOverview = () => (
    <div>
      {/* Statistics */}
      {statistics && (
        <div style={styles.statsGrid}>
          <div style={styles.statCard}>
            <div style={styles.statValue}>{statistics.total_scans}</div>
            <div style={styles.statLabel}>Total Scans</div>
          </div>
          <div style={styles.statCard}>
            <div style={styles.statValue}>{statistics.total_hardening_sessions}</div>
            <div style={styles.statLabel}>Hardening Sessions</div>
          </div>
          {statistics.latest_scan && (
            <>
              <div style={styles.statCard}>
                <div style={styles.statValue}>{statistics.latest_scan.totalVulnerabilities}</div>
                <div style={styles.statLabel}>Current Vulnerabilities</div>
              </div>
              <div style={styles.statCard}>
                <div style={styles.statValue}>{statistics.latest_scan.complianceScore}%</div>
                <div style={styles.statLabel}>Compliance Score</div>
              </div>
            </>
          )}
        </div>
      )}

      {/* Trend Charts */}
      {trends && trends.dates && trends.dates.length > 0 && (
        <>
          <div style={styles.controls}>
            <label style={{fontSize: '14px', fontWeight: '500', color: '#495057'}}>
              Time Range:
            </label>
            <select
              style={styles.select}
              value={trendDays}
              onChange={(e) => setTrendDays(Number(e.target.value))}
            >
              <option value={7}>Last 7 days</option>
              <option value={14}>Last 14 days</option>
              <option value={30}>Last 30 days</option>
              <option value={90}>Last 90 days</option>
            </select>
          </div>

          <div style={styles.chartContainer}>
            <h3 style={styles.chartTitle}>Vulnerability Trends</h3>
            <Line
              data={{
                labels: trends.dates.map(d => new Date(d).toLocaleDateString()),
                datasets: [
                  {
                    label: 'Total Vulnerabilities',
                    data: trends.total_vulnerabilities,
                    borderColor: '#007bff',
                    backgroundColor: 'rgba(0, 123, 255, 0.1)',
                    fill: true,
                    tension: 0.4,
                  },
                  {
                    label: 'Critical Issues',
                    data: trends.critical_issues,
                    borderColor: '#dc3545',
                    backgroundColor: 'rgba(220, 53, 69, 0.1)',
                    fill: true,
                    tension: 0.4,
                  },
                ],
              }}
              options={{
                responsive: true,
                maintainAspectRatio: true,
                plugins: {
                  legend: {
                    position: 'top',
                  },
                },
                scales: {
                  y: {
                    beginAtZero: true,
                  },
                },
              }}
            />
          </div>

          <div style={styles.chartContainer}>
            <h3 style={styles.chartTitle}>Compliance Score History</h3>
            <Bar
              data={{
                labels: trends.dates.map(d => new Date(d).toLocaleDateString()),
                datasets: [
                  {
                    label: 'Compliance Score (%)',
                    data: trends.compliance_scores,
                    backgroundColor: trends.compliance_scores.map(score =>
                      score >= 80 ? 'rgba(40, 167, 69, 0.6)' :
                      score >= 60 ? 'rgba(255, 193, 7, 0.6)' :
                      'rgba(220, 53, 69, 0.6)'
                    ),
                    borderColor: trends.compliance_scores.map(score =>
                      score >= 80 ? '#28a745' :
                      score >= 60 ? '#ffc107' :
                      '#dc3545'
                    ),
                    borderWidth: 2,
                  },
                ],
              }}
              options={{
                responsive: true,
                maintainAspectRatio: true,
                plugins: {
                  legend: {
                    position: 'top',
                  },
                },
                scales: {
                  y: {
                    beginAtZero: true,
                    max: 100,
                  },
                },
              }}
            />
          </div>
        </>
      )}
    </div>
  );

  const renderScanHistory = () => (
    <div>
      {scanHistory.length === 0 ? (
        <div style={styles.emptyState}>No scan history available. Run a scan to get started!</div>
      ) : (
        <div style={styles.historyList}>
          {scanHistory.map((scan) => (
            <div
              key={scan.id}
              style={styles.historyItem}
              onClick={() => handleScanClick(scan.scan_id)}
              onMouseEnter={(e) => {
                e.currentTarget.style.backgroundColor = '#e9ecef';
                e.currentTarget.style.borderColor = '#007bff';
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.backgroundColor = '#f8f9fa';
                e.currentTarget.style.borderColor = '#dee2e6';
              }}
            >
              <div style={styles.historyHeader}>
                <div>
                  <div style={styles.historyTitle}>{scan.scan_id}</div>
                  <div style={styles.historyDate}>
                    {new Date(scan.timestamp).toLocaleString()}
                  </div>
                </div>
                <span style={{
                  ...styles.badge,
                  ...(scan.status === 'completed' ? styles.badgeSuccess : styles.badgeWarning)
                }}>
                  {scan.status}
                </span>
              </div>
              <div style={styles.historyDetails}>
                <div>Vulnerabilities: <strong>{scan.totalVulnerabilities}</strong></div>
                <div>Critical: <strong>{scan.criticalIssues}</strong></div>
                <div>Compliance: <strong>{scan.complianceScore}%</strong></div>
                <div>Type: <strong>{scan.scan_type}</strong></div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );

  const renderHardeningHistory = () => (
    <div>
      {hardeningHistory.length === 0 ? (
        <div style={styles.emptyState}>No hardening history available.</div>
      ) : (
        <div style={styles.historyList}>
          {hardeningHistory.map((session) => (
            <div key={session.id} style={styles.historyItem}>
              <div style={styles.historyHeader}>
                <div>
                  <div style={styles.historyTitle}>{session.operation_id}</div>
                  <div style={styles.historyDate}>
                    {new Date(session.timestamp).toLocaleString()}
                  </div>
                </div>
                <span style={{
                  ...styles.badge,
                  ...(session.dry_run ? styles.badgeWarning : styles.badgeSuccess)
                }}>
                  {session.dry_run ? 'DRY RUN' : 'APPLIED'}
                </span>
              </div>
              <div style={styles.historyDetails}>
                <div>Policy: <strong>{session.policy}</strong></div>
                <div>Changes: <strong>{session.changes_applied}</strong></div>
                <div>Status: <strong>{session.status}</strong></div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );

  if (loading) {
    return (
      <div style={styles.container}>
        <div style={styles.loading}>Loading history...</div>
      </div>
    );
  }

  return (
    <div style={styles.container}>
      <div style={styles.header}>
        <h2 style={styles.title}>Security History & Trends</h2>
      </div>

      {error && <div style={styles.error}>{error}</div>}

      <div style={styles.tabs}>
        <button
          style={{
            ...styles.tab,
            ...(activeTab === 'overview' ? styles.tabActive : {})
          }}
          onClick={() => setActiveTab('overview')}
        >
          Overview & Trends
        </button>
        <button
          style={{
            ...styles.tab,
            ...(activeTab === 'scans' ? styles.tabActive : {})
          }}
          onClick={() => setActiveTab('scans')}
        >
          Scan History ({scanHistory.length})
        </button>
        <button
          style={{
            ...styles.tab,
            ...(activeTab === 'hardening' ? styles.tabActive : {})
          }}
          onClick={() => setActiveTab('hardening')}
        >
          Hardening History ({hardeningHistory.length})
        </button>
      </div>

      {activeTab === 'overview' && renderOverview()}
      {activeTab === 'scans' && renderScanHistory()}
      {activeTab === 'hardening' && renderHardeningHistory()}

      {selectedScan && (
        <div style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          backgroundColor: 'rgba(0,0,0,0.5)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          padding: '20px',
          zIndex: 1000,
        }}>
          <div style={{
            backgroundColor: '#ffffff',
            borderRadius: '8px',
            padding: '30px',
            maxWidth: '800px',
            maxHeight: '80vh',
            overflow: 'auto',
            boxShadow: '0 4px 20px rgba(0,0,0,0.3)',
          }}>
            <h3 style={{marginTop: 0}}>Scan Details: {selectedScan.scan_id}</h3>
            <p><strong>Timestamp:</strong> {new Date(selectedScan.timestamp).toLocaleString()}</p>
            <p><strong>Total Vulnerabilities:</strong> {selectedScan.totalVulnerabilities}</p>
            <p><strong>Compliance Score:</strong> {selectedScan.complianceScore}%</p>

            <h4>Findings:</h4>
            <div style={{maxHeight: '300px', overflow: 'auto'}}>
              {selectedScan.findings && selectedScan.findings.map((finding, index) => (
                <div key={index} style={{
                  padding: '12px',
                  marginBottom: '8px',
                  backgroundColor: '#f8f9fa',
                  borderRadius: '6px',
                  borderLeft: `4px solid ${
                    finding.severity === 'Critical' ? '#dc3545' :
                    finding.severity === 'Warning' ? '#ffc107' : '#17a2b8'
                  }`
                }}>
                  <div><strong>{finding.category}</strong> - {finding.severity}</div>
                  <div style={{fontSize: '14px', marginTop: '4px'}}>{finding.description}</div>
                </div>
              ))}
            </div>

            <button
              onClick={() => setSelectedScan(null)}
              style={{
                marginTop: '20px',
                padding: '10px 20px',
                backgroundColor: '#007bff',
                color: '#ffffff',
                border: 'none',
                borderRadius: '6px',
                cursor: 'pointer',
                fontWeight: '600',
              }}
            >
              Close
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

export default HistoryViewer;
