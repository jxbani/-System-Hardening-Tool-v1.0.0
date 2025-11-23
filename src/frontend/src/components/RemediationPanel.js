import React, { useState, useEffect } from 'react';
import {
  getPendingApprovals,
  approveRemediation,
  rejectRemediation,
  createCheckpoint,
  getRemediationHistory
} from '../api/client';

function RemediationPanel() {
  const [pendingApprovals, setPendingApprovals] = useState([]);
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [activeTab, setActiveTab] = useState('pending');

  useEffect(() => {
    fetchData();
  }, []);

  const fetchData = async () => {
    setLoading(true);
    setError(null);

    try {
      const [pendingData, historyData] = await Promise.all([
        getPendingApprovals(),
        getRemediationHistory(10)
      ]);

      setPendingApprovals(pendingData.pending || []);
      setHistory(historyData.history || []);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleApprove = async (id) => {
    try {
      await approveRemediation(id);
      await fetchData();
    } catch (err) {
      setError(err.message);
    }
  };

  const handleReject = async (id) => {
    try {
      await rejectRemediation(id, 'Rejected by user');
      await fetchData();
    } catch (err) {
      setError(err.message);
    }
  };

  const handleCreateCheckpoint = async () => {
    try {
      setError(null);
      const result = await createCheckpoint('Manual checkpoint from UI');
      alert(`Checkpoint created: ${result.checkpoint_id}`);
      await fetchData();
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
    button: {
      padding: '10px 20px',
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
    buttonSuccess: {
      backgroundColor: '#28a745',
      color: '#ffffff',
      marginRight: '8px',
    },
    buttonDanger: {
      backgroundColor: '#dc3545',
      color: '#ffffff',
    },
    tabs: {
      display: 'flex',
      gap: '8px',
      marginBottom: '20px',
      borderBottom: '2px solid #e9ecef',
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
    card: {
      padding: '16px',
      backgroundColor: '#f8f9fa',
      borderRadius: '8px',
      border: '1px solid #dee2e6',
      marginBottom: '12px',
    },
    cardHeader: {
      display: 'flex',
      justifyContent: 'space-between',
      alignItems: 'start',
      marginBottom: '12px',
    },
    cardTitle: {
      fontSize: '16px',
      fontWeight: '600',
      color: '#2c3e50',
      marginBottom: '4px',
    },
    cardDetail: {
      fontSize: '14px',
      color: '#6c757d',
      marginBottom: '4px',
    },
    badge: {
      padding: '4px 12px',
      borderRadius: '12px',
      fontSize: '12px',
      fontWeight: '600',
      textTransform: 'uppercase',
    },
    badgeCritical: {
      backgroundColor: '#dc3545',
      color: '#ffffff',
    },
    badgeHigh: {
      backgroundColor: '#fd7e14',
      color: '#ffffff',
    },
    badgeMedium: {
      backgroundColor: '#ffc107',
      color: '#000000',
    },
    badgeLow: {
      backgroundColor: '#28a745',
      color: '#ffffff',
    },
    actions: {
      display: 'flex',
      gap: '8px',
      marginTop: '12px',
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
      padding: '40px',
      color: '#6c757d',
      fontStyle: 'italic',
    },
  };

  const getSeverityBadge = (severity) => {
    const severityLower = (severity || 'medium').toLowerCase();
    let badgeStyle = styles.badgeMedium;

    if (severityLower === 'critical') badgeStyle = styles.badgeCritical;
    else if (severityLower === 'high') badgeStyle = styles.badgeHigh;
    else if (severityLower === 'low') badgeStyle = styles.badgeLow;

    return { ...styles.badge, ...badgeStyle };
  };

  const renderPending = () => {
    if (pendingApprovals.length === 0) {
      return <div style={styles.emptyState}>No pending approvals</div>;
    }

    return pendingApprovals.map((approval, index) => (
      <div key={index} style={styles.card}>
        <div style={styles.cardHeader}>
          <div>
            <div style={styles.cardTitle}>{approval.vulnerability_id || 'Remediation Request'}</div>
            <div style={styles.cardDetail}>ID: {approval.id}</div>
            <div style={styles.cardDetail}>Requested: {approval.timestamp || 'N/A'}</div>
          </div>
          <span style={getSeverityBadge(approval.severity)}>
            {approval.severity}
          </span>
        </div>
        {approval.description && (
          <div style={{ ...styles.cardDetail, marginBottom: '12px' }}>
            {approval.description}
          </div>
        )}
        <div style={styles.actions}>
          <button
            style={{ ...styles.button, ...styles.buttonSuccess }}
            onClick={() => handleApprove(approval.id)}
          >
            Approve
          </button>
          <button
            style={{ ...styles.button, ...styles.buttonDanger }}
            onClick={() => handleReject(approval.id)}
          >
            Reject
          </button>
        </div>
      </div>
    ));
  };

  const renderHistory = () => {
    if (history.length === 0) {
      return <div style={styles.emptyState}>No remediation history</div>;
    }

    return history.map((item, index) => (
      <div key={index} style={styles.card}>
        <div style={styles.cardHeader}>
          <div>
            <div style={styles.cardTitle}>{item.vulnerability_id || 'Remediation'}</div>
            <div style={styles.cardDetail}>ID: {item.id}</div>
            <div style={styles.cardDetail}>Date: {item.timestamp || 'N/A'}</div>
          </div>
          <span style={getSeverityBadge(item.severity)}>
            {item.status || 'completed'}
          </span>
        </div>
        {item.description && (
          <div style={styles.cardDetail}>
            {item.description}
          </div>
        )}
      </div>
    ));
  };

  return (
    <div style={styles.container}>
      <div style={styles.header}>
        <h2 style={styles.title}>Automated Remediation</h2>
        <button
          style={{ ...styles.button, ...styles.buttonPrimary }}
          onClick={handleCreateCheckpoint}
        >
          Create Checkpoint
        </button>
      </div>

      {error && (
        <div style={styles.error}>{error}</div>
      )}

      <div style={styles.tabs}>
        <button
          style={{
            ...styles.tab,
            ...(activeTab === 'pending' ? styles.tabActive : {})
          }}
          onClick={() => setActiveTab('pending')}
        >
          Pending Approvals ({pendingApprovals.length})
        </button>
        <button
          style={{
            ...styles.tab,
            ...(activeTab === 'history' ? styles.tabActive : {})
          }}
          onClick={() => setActiveTab('history')}
        >
          History ({history.length})
        </button>
      </div>

      {loading ? (
        <div style={styles.loading}>Loading...</div>
      ) : (
        <div>
          {activeTab === 'pending' && renderPending()}
          {activeTab === 'history' && renderHistory()}
        </div>
      )}
    </div>
  );
}

export default RemediationPanel;
