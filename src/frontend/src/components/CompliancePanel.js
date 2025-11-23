import React, { useState } from 'react';
import {
  checkCISCompliance,
  checkNISTCompliance,
  checkPCIDSSCompliance,
  checkHIPAACompliance,
  checkSOC2Compliance,
  checkAllCompliance
} from '../api/client';

function CompliancePanel() {
  const [results, setResults] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [selectedFramework, setSelectedFramework] = useState('all');

  const handleCheckCompliance = async (framework) => {
    setLoading(true);
    setError(null);

    try {
      let data;
      switch (framework) {
        case 'cis':
          data = await checkCISCompliance(1);
          break;
        case 'nist':
          data = await checkNISTCompliance();
          break;
        case 'pci-dss':
          data = await checkPCIDSSCompliance();
          break;
        case 'hipaa':
          data = await checkHIPAACompliance();
          break;
        case 'soc2':
          data = await checkSOC2Compliance();
          break;
        case 'all':
        default:
          data = await checkAllCompliance();
          break;
      }
      setResults(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const getScoreColor = (score) => {
    if (score >= 80) return '#28a745';
    if (score >= 60) return '#ffc107';
    return '#dc3545';
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
    controls: {
      display: 'flex',
      gap: '12px',
      alignItems: 'center',
      flexWrap: 'wrap',
    },
    select: {
      padding: '10px 16px',
      fontSize: '14px',
      borderRadius: '6px',
      border: '1px solid #ced4da',
      backgroundColor: '#ffffff',
      color: '#495057',
      cursor: 'pointer',
      minWidth: '200px',
    },
    button: {
      padding: '10px 24px',
      fontSize: '14px',
      fontWeight: '600',
      borderRadius: '6px',
      border: 'none',
      cursor: 'pointer',
      backgroundColor: '#007bff',
      color: '#ffffff',
      transition: 'background-color 0.2s',
    },
    buttonDisabled: {
      backgroundColor: '#6c757d',
      cursor: 'not-allowed',
      opacity: 0.6,
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
    resultsGrid: {
      display: 'grid',
      gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
      gap: '20px',
      marginTop: '20px',
    },
    frameworkCard: {
      padding: '20px',
      backgroundColor: '#f8f9fa',
      borderRadius: '8px',
      border: '2px solid #e9ecef',
    },
    frameworkName: {
      fontSize: '18px',
      fontWeight: '600',
      color: '#2c3e50',
      marginBottom: '12px',
    },
    scoreCircle: {
      width: '120px',
      height: '120px',
      margin: '0 auto 15px',
      borderRadius: '50%',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      fontSize: '32px',
      fontWeight: '700',
      color: '#ffffff',
      border: '6px solid',
    },
    statusBadge: {
      padding: '6px 12px',
      borderRadius: '12px',
      fontSize: '12px',
      fontWeight: '600',
      textTransform: 'uppercase',
      display: 'inline-block',
      marginTop: '8px',
    },
    compliant: {
      backgroundColor: '#d4edda',
      color: '#155724',
    },
    nonCompliant: {
      backgroundColor: '#f8d7da',
      color: '#721c24',
    },
    detailsRow: {
      display: 'flex',
      justifyContent: 'space-between',
      padding: '8px 0',
      borderBottom: '1px solid #dee2e6',
    },
    detailLabel: {
      fontSize: '14px',
      color: '#6c757d',
      fontWeight: '500',
    },
    detailValue: {
      fontSize: '14px',
      color: '#2c3e50',
      fontWeight: '600',
    },
  };

  const renderSummary = () => {
    if (!results || !results.summary) return null;

    const { summary } = results;
    return (
      <div style={{ marginBottom: '30px', padding: '20px', backgroundColor: '#e7f3ff', borderRadius: '8px' }}>
        <h3 style={{ margin: '0 0 15px 0', fontSize: '20px', color: '#2c3e50' }}>Overall Summary</h3>
        <div style={styles.resultsGrid}>
          <div style={styles.detailsRow}>
            <span style={styles.detailLabel}>Average Score:</span>
            <span style={{ ...styles.detailValue, color: getScoreColor(summary.average_score) }}>
              {summary.average_score?.toFixed(1)}%
            </span>
          </div>
          <div style={styles.detailsRow}>
            <span style={styles.detailLabel}>Frameworks Checked:</span>
            <span style={styles.detailValue}>{summary.frameworks_checked}</span>
          </div>
          <div style={styles.detailsRow}>
            <span style={styles.detailLabel}>Compliant:</span>
            <span style={styles.detailValue}>
              {summary.compliant_frameworks}/{summary.frameworks_checked}
            </span>
          </div>
        </div>
      </div>
    );
  };

  const renderFrameworkResults = () => {
    if (!results) return null;

    // If checking all frameworks
    if (results.summary) {
      const frameworks = ['cis', 'nist', 'pci_dss', 'hipaa', 'soc2'];
      return (
        <div style={styles.resultsGrid}>
          {frameworks.map(fw => {
            const data = results[fw];
            if (!data) return null;
            return (
              <div key={fw} style={styles.frameworkCard}>
                <div style={styles.frameworkName}>{data.framework}</div>
                <div
                  style={{
                    ...styles.scoreCircle,
                    backgroundColor: getScoreColor(data.score),
                    borderColor: getScoreColor(data.score),
                  }}
                >
                  {data.score?.toFixed(0)}%
                </div>
                <div style={{ textAlign: 'center' }}>
                  <span
                    style={{
                      ...styles.statusBadge,
                      ...(data.compliance_status === 'compliant' ? styles.compliant : styles.nonCompliant)
                    }}
                  >
                    {data.compliance_status}
                  </span>
                </div>
                <div style={{ marginTop: '15px' }}>
                  <div style={styles.detailsRow}>
                    <span style={styles.detailLabel}>Passed:</span>
                    <span style={styles.detailValue}>{data.passed || data.passed_checks || 0}</span>
                  </div>
                  <div style={styles.detailsRow}>
                    <span style={styles.detailLabel}>Failed:</span>
                    <span style={styles.detailValue}>{data.failed || data.failed_checks || 0}</span>
                  </div>
                  <div style={styles.detailsRow}>
                    <span style={styles.detailLabel}>Total:</span>
                    <span style={styles.detailValue}>{data.total_checks || data.total_controls || 0}</span>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      );
    }

    // Single framework result
    return (
      <div style={styles.resultsGrid}>
        <div style={styles.frameworkCard}>
          <div style={styles.frameworkName}>{results.framework}</div>
          <div
            style={{
              ...styles.scoreCircle,
              backgroundColor: getScoreColor(results.score),
              borderColor: getScoreColor(results.score),
            }}
          >
            {results.score?.toFixed(0)}%
          </div>
          <div style={{ textAlign: 'center' }}>
            <span
              style={{
                ...styles.statusBadge,
                ...(results.compliance_status === 'compliant' ? styles.compliant : styles.nonCompliant)
              }}
            >
              {results.compliance_status}
            </span>
          </div>
          <div style={{ marginTop: '15px' }}>
            <div style={styles.detailsRow}>
              <span style={styles.detailLabel}>Passed:</span>
              <span style={styles.detailValue}>{results.passed || results.passed_checks || 0}</span>
            </div>
            <div style={styles.detailsRow}>
              <span style={styles.detailLabel}>Failed:</span>
              <span style={styles.detailValue}>{results.failed || results.failed_checks || 0}</span>
            </div>
            <div style={styles.detailsRow}>
              <span style={styles.detailLabel}>Total:</span>
              <span style={styles.detailValue}>{results.total_checks || results.total_controls || 0}</span>
            </div>
          </div>
        </div>
      </div>
    );
  };

  return (
    <div style={styles.container}>
      <div style={styles.header}>
        <h2 style={styles.title}>Compliance Framework Checker</h2>
        <div style={styles.controls}>
          <select
            style={styles.select}
            value={selectedFramework}
            onChange={(e) => setSelectedFramework(e.target.value)}
            disabled={loading}
          >
            <option value="all">All Frameworks</option>
            <option value="cis">CIS Benchmarks</option>
            <option value="nist">NIST 800-53</option>
            <option value="pci-dss">PCI-DSS</option>
            <option value="hipaa">HIPAA</option>
            <option value="soc2">SOC 2</option>
          </select>
          <button
            style={{
              ...styles.button,
              ...(loading ? styles.buttonDisabled : {})
            }}
            onClick={() => handleCheckCompliance(selectedFramework)}
            disabled={loading}
          >
            {loading ? 'Checking...' : 'Check Compliance'}
          </button>
        </div>
      </div>

      {error && (
        <div style={styles.error}>{error}</div>
      )}

      {loading && (
        <div style={styles.loading}>Checking compliance...</div>
      )}

      {!loading && results && (
        <>
          {renderSummary()}
          {renderFrameworkResults()}
        </>
      )}

      {!loading && !results && !error && (
        <div style={styles.loading}>
          Select a framework and click "Check Compliance" to begin
        </div>
      )}
    </div>
  );
}

export default CompliancePanel;
