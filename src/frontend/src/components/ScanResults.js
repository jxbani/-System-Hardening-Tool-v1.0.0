import React, { useState, useEffect } from 'react';
import { applyHardening } from '../api/client';
import './ScanResults.css';

function ScanResults({ scanData, onHardeningComplete }) {
  const [findings, setFindings] = useState([]);
  const [selectedIssues, setSelectedIssues] = useState(new Set());
  const [severityFilter, setSeverityFilter] = useState('all');
  const [applying, setApplying] = useState(false);
  const [error, setError] = useState(null);
  const [success, setSuccess] = useState(null);

  // Process scan data when it changes
  useEffect(() => {
    if (scanData && scanData.findings) {
      setFindings(scanData.findings);
    }
  }, [scanData]);

  /**
   * Get severity color class
   */
  const getSeverityClass = (severity) => {
    const severityLower = severity?.toLowerCase() || '';
    switch (severityLower) {
      case 'critical':
        return 'severity-critical';
      case 'high':
        return 'severity-high';
      case 'medium':
        return 'severity-medium';
      case 'low':
        return 'severity-low';
      default:
        return 'severity-unknown';
    }
  };

  /**
   * Toggle individual issue selection
   */
  const toggleIssueSelection = (issueId) => {
    setSelectedIssues(prev => {
      const newSet = new Set(prev);
      if (newSet.has(issueId)) {
        newSet.delete(issueId);
      } else {
        newSet.add(issueId);
      }
      return newSet;
    });
  };

  /**
   * Toggle all visible issues
   */
  const toggleAllVisibleIssues = () => {
    const visibleFindings = getFilteredFindings();
    const allSelected = visibleFindings.every(f => selectedIssues.has(f.id));

    if (allSelected) {
      // Deselect all visible
      setSelectedIssues(prev => {
        const newSet = new Set(prev);
        visibleFindings.forEach(f => newSet.delete(f.id));
        return newSet;
      });
    } else {
      // Select all visible
      setSelectedIssues(prev => {
        const newSet = new Set(prev);
        visibleFindings.forEach(f => newSet.add(f.id));
        return newSet;
      });
    }
  };

  /**
   * Get filtered findings based on severity filter
   */
  const getFilteredFindings = () => {
    if (severityFilter === 'all') {
      return findings;
    }
    return findings.filter(f => f.severity?.toLowerCase() === severityFilter.toLowerCase());
  };

  /**
   * Handle apply hardening button click
   */
  const handleApplyHardening = async () => {
    if (selectedIssues.size === 0) {
      setError('Please select at least one issue to fix');
      return;
    }

    setApplying(true);
    setError(null);
    setSuccess(null);

    try {
      const ruleIds = Array.from(selectedIssues);
      const result = await applyHardening(ruleIds);

      setSuccess(`Successfully applied hardening rules. ${result.applied || selectedIssues.size} rules applied.`);
      setSelectedIssues(new Set()); // Clear selection

      // Callback to parent component
      if (onHardeningComplete) {
        onHardeningComplete(result);
      }
    } catch (err) {
      console.error('Error applying hardening:', err);
      setError(err.message);
    } finally {
      setApplying(false);
    }
  };

  /**
   * Get severity badge count
   */
  const getSeverityCount = (severity) => {
    return findings.filter(f => f.severity?.toLowerCase() === severity.toLowerCase()).length;
  };

  const filteredFindings = getFilteredFindings();
  const allVisibleSelected = filteredFindings.length > 0 && filteredFindings.every(f => selectedIssues.has(f.id));

  return (
    <div className="scan-results-container">
      <div className="results-header">
        <h2>Scan Results</h2>
        <div className="results-summary">
          <span className="summary-item">
            Total Issues: <strong>{findings.length}</strong>
          </span>
          <span className="summary-item">
            Selected: <strong>{selectedIssues.size}</strong>
          </span>
        </div>
      </div>

      {/* Alerts */}
      {error && (
        <div className="alert alert-error">
          <span className="alert-icon">⚠️</span>
          <span>{error}</span>
          <button className="alert-close" onClick={() => setError(null)}>×</button>
        </div>
      )}

      {success && (
        <div className="alert alert-success">
          <span className="alert-icon">✓</span>
          <span>{success}</span>
          <button className="alert-close" onClick={() => setSuccess(null)}>×</button>
        </div>
      )}

      {/* Filters and Actions */}
      <div className="results-controls">
        <div className="severity-filters">
          <button
            className={`filter-btn ${severityFilter === 'all' ? 'active' : ''}`}
            onClick={() => setSeverityFilter('all')}
          >
            All ({findings.length})
          </button>
          <button
            className={`filter-btn severity-critical ${severityFilter === 'critical' ? 'active' : ''}`}
            onClick={() => setSeverityFilter('critical')}
          >
            Critical ({getSeverityCount('critical')})
          </button>
          <button
            className={`filter-btn severity-high ${severityFilter === 'high' ? 'active' : ''}`}
            onClick={() => setSeverityFilter('high')}
          >
            High ({getSeverityCount('high')})
          </button>
          <button
            className={`filter-btn severity-medium ${severityFilter === 'medium' ? 'active' : ''}`}
            onClick={() => setSeverityFilter('medium')}
          >
            Medium ({getSeverityCount('medium')})
          </button>
          <button
            className={`filter-btn severity-low ${severityFilter === 'low' ? 'active' : ''}`}
            onClick={() => setSeverityFilter('low')}
          >
            Low ({getSeverityCount('low')})
          </button>
        </div>

        <button
          className="btn btn-primary btn-apply"
          onClick={handleApplyHardening}
          disabled={applying || selectedIssues.size === 0}
        >
          {applying ? (
            <>
              <span className="spinner-small"></span>
              Applying...
            </>
          ) : (
            `Apply Selected Hardening (${selectedIssues.size})`
          )}
        </button>
      </div>

      {/* Results Table */}
      {filteredFindings.length > 0 ? (
        <div className="table-container">
          <table className="results-table">
            <thead>
              <tr>
                <th className="checkbox-col">
                  <input
                    type="checkbox"
                    checked={allVisibleSelected}
                    onChange={toggleAllVisibleIssues}
                    aria-label="Select all visible issues"
                  />
                </th>
                <th className="severity-col">Severity</th>
                <th className="id-col">ID</th>
                <th className="title-col">Issue</th>
                <th className="description-col">Description</th>
                <th className="recommendation-col">Recommendation</th>
              </tr>
            </thead>
            <tbody>
              {filteredFindings.map((finding) => (
                <tr
                  key={finding.id}
                  className={selectedIssues.has(finding.id) ? 'selected' : ''}
                >
                  <td className="checkbox-col">
                    <input
                      type="checkbox"
                      checked={selectedIssues.has(finding.id)}
                      onChange={() => toggleIssueSelection(finding.id)}
                      aria-label={`Select issue ${finding.id}`}
                    />
                  </td>
                  <td className="severity-col">
                    <span className={`severity-badge ${getSeverityClass(finding.severity)}`}>
                      {finding.severity || 'Unknown'}
                    </span>
                  </td>
                  <td className="id-col">
                    <code>{finding.id}</code>
                  </td>
                  <td className="title-col">
                    <strong>{finding.title || 'Untitled Issue'}</strong>
                  </td>
                  <td className="description-col">
                    {finding.description || 'No description available'}
                  </td>
                  <td className="recommendation-col">
                    {finding.recommendation || finding.remediation || 'No recommendation available'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="no-results">
          <div className="no-results-icon">🔍</div>
          <h3>No issues found</h3>
          <p>
            {severityFilter === 'all'
              ? 'No security issues were found in the scan.'
              : `No ${severityFilter} severity issues found.`}
          </p>
        </div>
      )}

      {/* Legend */}
      <div className="severity-legend">
        <h4>Severity Legend:</h4>
        <div className="legend-items">
          <div className="legend-item">
            <span className="severity-badge severity-critical">Critical</span>
            <span className="legend-text">Immediate action required</span>
          </div>
          <div className="legend-item">
            <span className="severity-badge severity-high">High</span>
            <span className="legend-text">Should be addressed soon</span>
          </div>
          <div className="legend-item">
            <span className="severity-badge severity-medium">Medium</span>
            <span className="legend-text">Address when possible</span>
          </div>
          <div className="legend-item">
            <span className="severity-badge severity-low">Low</span>
            <span className="legend-text">Minor issue or improvement</span>
          </div>
        </div>
      </div>
    </div>
  );
}

export default ScanResults;
