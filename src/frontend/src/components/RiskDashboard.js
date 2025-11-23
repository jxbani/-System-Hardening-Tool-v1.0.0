import React, { useState, useEffect, useCallback } from 'react';
import { Line, Doughnut, Bar } from 'react-chartjs-2';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  ArcElement,
  Title,
  Tooltip,
  Legend,
  Filler
} from 'chart.js';
import {
  getRiskTrends,
  getRiskDistribution,
  getHighRiskVulnerabilities,
  getStatistics
} from '../api/client';

// Register Chart.js components
ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  ArcElement,
  Title,
  Tooltip,
  Legend,
  Filler
);

function RiskDashboard() {
  const [riskTrends, setRiskTrends] = useState(null);
  const [riskDistribution, setRiskDistribution] = useState(null);
  const [highRiskVulns, setHighRiskVulns] = useState([]);
  const [overallRiskScore, setOverallRiskScore] = useState(0);
  const [riskLevel, setRiskLevel] = useState('Low');
  const [loading, setLoading] = useState(true);
  const [trendDays, setTrendDays] = useState(30);

  const fetchRiskData = useCallback(async () => {
    setLoading(true);
    try {
      // Fetch all risk data in parallel
      const [trends, distribution, highRisk, stats] = await Promise.all([
        getRiskTrends(trendDays),
        getRiskDistribution(),
        getHighRiskVulnerabilities(10),
        getStatistics()
      ]);

      setRiskTrends(trends);
      setRiskDistribution(distribution.distribution);
      setHighRiskVulns(highRisk.vulnerabilities || []);

      // Get overall risk score from latest scan
      if (stats.latest_scan) {
        setOverallRiskScore(stats.latest_scan.overall_risk_score || 0);
        setRiskLevel(stats.latest_scan.risk_level || 'Low');
      }
    } catch (error) {
      console.error('Error fetching risk data:', error);
    } finally {
      setLoading(false);
    }
  }, [trendDays]);

  useEffect(() => {
    fetchRiskData();
  }, [fetchRiskData]);

  const getRiskColor = (score) => {
    if (score >= 9.0) return '#dc3545'; // Critical - Red
    if (score >= 7.0) return '#fd7e14'; // High - Orange
    if (score >= 4.0) return '#ffc107'; // Medium - Yellow
    return '#28a745'; // Low - Green
  };

  const getRiskLevelColor = (level) => {
    const levelLower = level?.toLowerCase() || 'low';
    if (levelLower === 'critical') return '#dc3545';
    if (levelLower === 'high') return '#fd7e14';
    if (levelLower === 'medium') return '#ffc107';
    return '#28a745';
  };

  // Risk Gauge Component
  const RiskGauge = ({ score, level }) => {
    const percentage = (score / 10) * 100;
    const color = getRiskColor(score);

    return (
      <div style={styles.gaugeContainer}>
        <div style={styles.gaugeTitle}>Overall Risk Score</div>
        <div style={styles.gaugeCircle}>
          <svg width="200" height="200" viewBox="0 0 200 200">
            <circle
              cx="100"
              cy="100"
              r="80"
              fill="none"
              stroke="#e9ecef"
              strokeWidth="20"
            />
            <circle
              cx="100"
              cy="100"
              r="80"
              fill="none"
              stroke={color}
              strokeWidth="20"
              strokeDasharray={`${percentage * 5.03} ${500 - percentage * 5.03}`}
              strokeLinecap="round"
              transform="rotate(-90 100 100)"
            />
          </svg>
          <div style={styles.gaugeScore}>
            <div style={{...styles.scoreNumber, color}}>{score.toFixed(1)}</div>
            <div style={{...styles.scorelabel, color}}>{level}</div>
          </div>
        </div>
        <div style={styles.gaugeScale}>
          <span>0.0</span>
          <span>2.5</span>
          <span>5.0</span>
          <span>7.5</span>
          <span>10.0</span>
        </div>
      </div>
    );
  };

  // Risk Distribution Doughnut Chart
  const renderDistributionChart = () => {
    if (!riskDistribution) return null;

    const data = {
      labels: ['Critical', 'High', 'Medium', 'Low'],
      datasets: [{
        data: [
          riskDistribution.critical || 0,
          riskDistribution.high || 0,
          riskDistribution.medium || 0,
          riskDistribution.low || 0
        ],
        backgroundColor: [
          '#dc3545',
          '#fd7e14',
          '#ffc107',
          '#28a745'
        ],
        borderWidth: 2,
        borderColor: '#ffffff'
      }]
    };

    const options = {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          position: 'right',
          labels: {
            padding: 15,
            font: { size: 12 }
          }
        },
        tooltip: {
          callbacks: {
            label: function(context) {
              const label = context.label || '';
              const value = context.parsed || 0;
              const total = context.dataset.data.reduce((a, b) => a + b, 0);
              const percentage = total > 0 ? ((value / total) * 100).toFixed(1) : 0;
              return `${label}: ${value} (${percentage}%)`;
            }
          }
        }
      }
    };

    return (
      <div style={{height: '300px'}}>
        <Doughnut data={data} options={options} />
      </div>
    );
  };

  // Risk Trend Line Chart
  const renderTrendChart = () => {
    if (!riskTrends || !riskTrends.dates || riskTrends.dates.length === 0) {
      return <div style={styles.noData}>No trend data available. Run multiple scans to see trends.</div>;
    }

    const data = {
      labels: riskTrends.dates.map(d => new Date(d).toLocaleDateString()),
      datasets: [{
        label: 'Overall Risk Score',
        data: riskTrends.overall_risk_scores,
        borderColor: '#007bff',
        backgroundColor: 'rgba(0, 123, 255, 0.1)',
        fill: true,
        tension: 0.4,
        pointRadius: 4,
        pointHoverRadius: 6
      }]
    };

    const options = {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        y: {
          beginAtZero: true,
          max: 10,
          ticks: {
            callback: function(value) {
              return value.toFixed(1);
            }
          },
          grid: {
            color: 'rgba(0, 0, 0, 0.05)'
          }
        },
        x: {
          grid: {
            display: false
          }
        }
      },
      plugins: {
        legend: {
          display: true,
          position: 'top'
        },
        tooltip: {
          callbacks: {
            label: function(context) {
              const score = context.parsed.y;
              const level = score >= 9 ? 'Critical' : score >= 7 ? 'High' : score >= 4 ? 'Medium' : 'Low';
              return `Risk Score: ${score.toFixed(1)} (${level})`;
            }
          }
        }
      }
    };

    return (
      <div style={{height: '300px'}}>
        <Line data={data} options={options} />
      </div>
    );
  };

  const styles = {
    container: {
      padding: '20px',
      backgroundColor: '#f5f7fa',
      minHeight: '100vh',
    },
    header: {
      marginBottom: '30px',
    },
    title: {
      fontSize: '28px',
      fontWeight: '600',
      color: '#2c3e50',
      marginBottom: '10px',
    },
    subtitle: {
      fontSize: '14px',
      color: '#6c757d',
    },
    grid: {
      display: 'grid',
      gridTemplateColumns: 'repeat(auto-fit, minmax(350px, 1fr))',
      gap: '20px',
      marginBottom: '20px',
    },
    card: {
      backgroundColor: '#ffffff',
      borderRadius: '8px',
      padding: '24px',
      boxShadow: '0 2px 8px rgba(0,0,0,0.1)',
    },
    cardTitle: {
      fontSize: '18px',
      fontWeight: '600',
      color: '#2c3e50',
      marginBottom: '20px',
      borderBottom: '2px solid #e9ecef',
      paddingBottom: '10px',
    },
    gaugeContainer: {
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
    },
    gaugeTitle: {
      fontSize: '16px',
      fontWeight: '600',
      color: '#2c3e50',
      marginBottom: '20px',
    },
    gaugeCircle: {
      position: 'relative',
      width: '200px',
      height: '200px',
      marginBottom: '20px',
    },
    gaugeScore: {
      position: 'absolute',
      top: '50%',
      left: '50%',
      transform: 'translate(-50%, -50%)',
      textAlign: 'center',
    },
    scoreNumber: {
      fontSize: '48px',
      fontWeight: '700',
      lineHeight: '1',
    },
    scorelabel: {
      fontSize: '16px',
      fontWeight: '600',
      marginTop: '5px',
      textTransform: 'uppercase',
    },
    gaugeScale: {
      display: 'flex',
      justifyContent: 'space-between',
      width: '100%',
      fontSize: '12px',
      color: '#6c757d',
    },
    trendControls: {
      display: 'flex',
      gap: '10px',
      marginBottom: '20px',
    },
    trendBtn: {
      padding: '8px 16px',
      border: '1px solid #dee2e6',
      borderRadius: '6px',
      backgroundColor: '#ffffff',
      cursor: 'pointer',
      fontSize: '14px',
      fontWeight: '500',
      transition: 'all 0.2s',
    },
    trendBtnActive: {
      backgroundColor: '#007bff',
      color: '#ffffff',
      borderColor: '#007bff',
    },
    vulnList: {
      listStyle: 'none',
      padding: 0,
      margin: 0,
    },
    vulnItem: {
      padding: '15px',
      borderBottom: '1px solid #e9ecef',
      transition: 'background-color 0.2s',
    },
    vulnHeader: {
      display: 'flex',
      justifyContent: 'space-between',
      alignItems: 'center',
      marginBottom: '8px',
    },
    vulnCategory: {
      fontSize: '14px',
      fontWeight: '600',
      color: '#2c3e50',
    },
    vulnRiskBadge: {
      padding: '4px 12px',
      borderRadius: '12px',
      fontSize: '12px',
      fontWeight: '600',
      color: '#ffffff',
    },
    vulnDescription: {
      fontSize: '13px',
      color: '#495057',
      marginBottom: '8px',
    },
    vulnMeta: {
      display: 'flex',
      gap: '15px',
      fontSize: '12px',
      color: '#6c757d',
    },
    noData: {
      textAlign: 'center',
      color: '#6c757d',
      fontStyle: 'italic',
      padding: '40px 20px',
    },
    loading: {
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
  };

  if (loading) {
    return (
      <div style={styles.container}>
        <div style={styles.loading}>
          <div style={styles.spinner}></div>
          <p>Loading risk analysis...</p>
        </div>
        <style>
          {`
            @keyframes spin {
              0% { transform: rotate(0deg); }
              100% { transform: rotate(360deg); }
            }
          `}
        </style>
      </div>
    );
  }

  return (
    <div style={styles.container}>
      <div style={styles.header}>
        <h1 style={styles.title}>Risk Analysis Dashboard</h1>
        <p style={styles.subtitle}>Comprehensive risk assessment and vulnerability prioritization</p>
      </div>

      <div style={styles.grid}>
        {/* Risk Score Gauge */}
        <div style={styles.card}>
          <RiskGauge score={overallRiskScore} level={riskLevel} />
        </div>

        {/* Risk Distribution */}
        <div style={styles.card}>
          <h3 style={styles.cardTitle}>Risk Distribution</h3>
          {renderDistributionChart()}
        </div>
      </div>

      {/* Risk Trends */}
      <div style={styles.card}>
        <h3 style={styles.cardTitle}>Risk Score Trends</h3>
        <div style={styles.trendControls}>
          {[7, 14, 30, 90].map(days => (
            <button
              key={days}
              style={{
                ...styles.trendBtn,
                ...(trendDays === days ? styles.trendBtnActive : {})
              }}
              onClick={() => setTrendDays(days)}
            >
              {days} Days
            </button>
          ))}
        </div>
        {renderTrendChart()}
      </div>

      {/* High Risk Vulnerabilities */}
      <div style={styles.card}>
        <h3 style={styles.cardTitle}>Highest Risk Vulnerabilities</h3>
        {highRiskVulns.length > 0 ? (
          <ul style={styles.vulnList}>
            {highRiskVulns.map((vuln, index) => (
              <li
                key={vuln.id || index}
                style={styles.vulnItem}
                className="vuln-item"
              >
                <div style={styles.vulnHeader}>
                  <span style={styles.vulnCategory}>{vuln.category}</span>
                  <span style={{
                    ...styles.vulnRiskBadge,
                    backgroundColor: getRiskLevelColor(vuln.risk_level)
                  }}>
                    {vuln.risk_score?.toFixed(1)} - {vuln.risk_level}
                  </span>
                </div>
                <div style={styles.vulnDescription}>{vuln.description}</div>
                <div style={styles.vulnMeta}>
                  <span>Severity: {vuln.severity}</span>
                  {vuln.risk_factors && (
                    <>
                      <span>Exploitability: {(vuln.risk_factors.exploitability * 100).toFixed(0)}%</span>
                      <span>Exposure: {vuln.risk_factors.exposure}</span>
                    </>
                  )}
                </div>
              </li>
            ))}
          </ul>
        ) : (
          <div style={styles.noData}>No vulnerabilities found. Run a security scan to identify risks.</div>
        )}
      </div>

      <style>
        {`
          @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
          }
          .vuln-item:hover {
            background-color: #f8f9fa;
          }
        `}
      </style>
    </div>
  );
}

export default RiskDashboard;
