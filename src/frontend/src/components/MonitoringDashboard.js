import React, { useState, useEffect } from 'react';
import {
  getMonitoringStatus,
  getCurrentMetrics,
  startMonitoring,
  stopMonitoring
} from '../api/client';

function MonitoringDashboard() {
  const [status, setStatus] = useState(null);
  const [metrics, setMetrics] = useState(null);
  const [monitoring, setMonitoring] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    fetchMonitoringData();
    // Refresh metrics every 5 seconds if monitoring is active
    const interval = setInterval(() => {
      if (monitoring) {
        fetchMetrics();
      }
    }, 5000);

    return () => clearInterval(interval);
  }, [monitoring]);

  const fetchMonitoringData = async () => {
    try {
      setLoading(true);
      const statusData = await getMonitoringStatus();
      setStatus(statusData);
      setMonitoring(statusData.monitoring);

      const metricsData = await getCurrentMetrics();
      setMetrics(metricsData);

      setError(null);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const fetchMetrics = async () => {
    try {
      const metricsData = await getCurrentMetrics();
      setMetrics(metricsData);
    } catch (err) {
      console.error('Error fetching metrics:', err);
    }
  };

  const handleStartMonitoring = async () => {
    try {
      await startMonitoring(5);
      setMonitoring(true);
      fetchMonitoringData();
    } catch (err) {
      setError(err.message);
    }
  };

  const handleStopMonitoring = async () => {
    try {
      await stopMonitoring();
      setMonitoring(false);
      fetchMonitoringData();
    } catch (err) {
      setError(err.message);
    }
  };

  const getStatusColor = (status) => {
    switch (status) {
      case 'normal':
        return '#28a745';
      case 'warning':
        return '#ffc107';
      case 'critical':
        return '#dc3545';
      default:
        return '#6c757d';
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
      display: 'flex',
      justifyContent: 'space-between',
      alignItems: 'center',
      marginBottom: '20px',
      paddingBottom: '15px',
      borderBottom: '2px solid #e9ecef',
    },
    title: {
      margin: 0,
      fontSize: '24px',
      color: '#2c3e50',
      fontWeight: '600',
    },
    statusBadge: {
      padding: '8px 16px',
      borderRadius: '20px',
      fontSize: '14px',
      fontWeight: '600',
      backgroundColor: status?.status === 'healthy' ? '#d4edda' : '#f8d7da',
      color: status?.status === 'healthy' ? '#155724' : '#721c24',
    },
    grid: {
      display: 'grid',
      gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))',
      gap: '20px',
      marginBottom: '20px',
    },
    metricCard: {
      padding: '20px',
      backgroundColor: '#f8f9fa',
      borderRadius: '8px',
      border: '2px solid #e9ecef',
    },
    metricLabel: {
      fontSize: '14px',
      color: '#6c757d',
      fontWeight: '500',
      marginBottom: '8px',
    },
    metricValue: {
      fontSize: '28px',
      fontWeight: '700',
      color: '#2c3e50',
      marginBottom: '4px',
    },
    metricStatus: {
      fontSize: '12px',
      fontWeight: '600',
      textTransform: 'uppercase',
      padding: '4px 8px',
      borderRadius: '4px',
      display: 'inline-block',
    },
    button: {
      padding: '10px 24px',
      fontSize: '14px',
      fontWeight: '600',
      borderRadius: '6px',
      border: 'none',
      cursor: 'pointer',
      transition: 'background-color 0.2s',
    },
    buttonPrimary: {
      backgroundColor: '#007bff',
      color: '#ffffff',
    },
    buttonDanger: {
      backgroundColor: '#dc3545',
      color: '#ffffff',
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
  };

  if (loading && !metrics) {
    return (
      <div style={styles.container}>
        <div style={styles.loading}>Loading monitoring data...</div>
      </div>
    );
  }

  return (
    <div style={styles.container}>
      <div style={styles.header}>
        <h2 style={styles.title}>Real-time Monitoring</h2>
        <div>
          {status && (
            <span style={styles.statusBadge}>
              System: {status.status || 'Unknown'}
            </span>
          )}
        </div>
      </div>

      {error && (
        <div style={styles.error}>{error}</div>
      )}

      <div style={{ marginBottom: '20px' }}>
        {!monitoring ? (
          <button
            style={{...styles.button, ...styles.buttonPrimary}}
            onClick={handleStartMonitoring}
          >
            Start Monitoring
          </button>
        ) : (
          <button
            style={{...styles.button, ...styles.buttonDanger}}
            onClick={handleStopMonitoring}
          >
            Stop Monitoring
          </button>
        )}
      </div>

      {metrics && (
        <div style={styles.grid}>
          <div style={styles.metricCard}>
            <div style={styles.metricLabel}>CPU Usage</div>
            <div style={styles.metricValue}>{metrics.cpu?.percent?.toFixed(1) || 0}%</div>
            <span
              style={{
                ...styles.metricStatus,
                backgroundColor: getStatusColor(metrics.cpu?.status),
                color: '#ffffff'
              }}
            >
              {metrics.cpu?.status || 'unknown'}
            </span>
          </div>

          <div style={styles.metricCard}>
            <div style={styles.metricLabel}>Memory Usage</div>
            <div style={styles.metricValue}>{metrics.memory?.percent?.toFixed(1) || 0}%</div>
            <span
              style={{
                ...styles.metricStatus,
                backgroundColor: getStatusColor(metrics.memory?.status),
                color: '#ffffff'
              }}
            >
              {metrics.memory?.status || 'unknown'}
            </span>
          </div>

          <div style={styles.metricCard}>
            <div style={styles.metricLabel}>Disk Usage</div>
            <div style={styles.metricValue}>{metrics.disk?.percent?.toFixed(1) || 0}%</div>
            <span
              style={{
                ...styles.metricStatus,
                backgroundColor: getStatusColor(metrics.disk?.status),
                color: '#ffffff'
              }}
            >
              {metrics.disk?.status || 'unknown'}
            </span>
          </div>

          <div style={styles.metricCard}>
            <div style={styles.metricLabel}>Open Ports</div>
            <div style={styles.metricValue}>{metrics.processes?.open_ports || 0}</div>
            <span
              style={{
                ...styles.metricStatus,
                backgroundColor: '#6c757d',
                color: '#ffffff'
              }}
            >
              monitored
            </span>
          </div>

          {metrics.uptime && (
            <div style={styles.metricCard}>
              <div style={styles.metricLabel}>System Uptime</div>
              <div style={{fontSize: '20px', fontWeight: '600', color: '#2c3e50'}}>
                {metrics.uptime.formatted || 'N/A'}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default MonitoringDashboard;
