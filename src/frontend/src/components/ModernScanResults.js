import React, { useState, useEffect } from 'react';
import { applyHardening } from '../api/client';
import ModernVulnerabilityModal from './ModernVulnerabilityModal';
import './ModernScanResults.css';

function ModernScanResults({ scanData, onRefreshNeeded }) {
  const [findings, setFindings] = useState([]);
  const [selectedIssues, setSelectedIssues] = useState(new Set());
  const [severityFilter, setSeverityFilter] = useState('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [sortBy, setSortBy] = useState('severity');
  const [applying, setApplying] = useState(false);
  const [error, setError] = useState(null);
  const [success, setSuccess] = useState(null);
  const [selectedVulnerability, setSelectedVulnerability] = useState(null);

  // Process scan data
  useEffect(() => {
    if (scanData && scanData.findings) {
      setFindings(scanData.findings);
    }
  }, [scanData]);

  /**
   * Get severity color and priority
   */
  const getSeverityInfo = (severity) => {
    const severityLower = severity?.toLowerCase() || '';
    switch (severityLower) {
      case 'critical':
        return { class: 'severity-critical', priority: 1, color: '#FF3366' };
      case 'high':
        return { class: 'severity-high', priority: 2, color: '#FF6B35' };
      case 'medium':
        return { class: 'severity-medium', priority: 3, color: '#FFA500' };
      case 'low':
        return { class: 'severity-low', priority: 4, color: '#4ECDC4' };
      default:
        return { class: 'severity-unknown', priority: 5, color: '#95A3B3' };
    }
  };

  /**
   * Get severity count
   */
  const getSeverityCount = (severity) => {
    if (severity === 'all') return findings.length;
    return findings.filter(f => f.severity?.toLowerCase() === severity).length;
  };

  /**
   * Filter and sort findings
   */
  const getFilteredAndSortedFindings = () => {
    let filtered = findings;

    // Apply severity filter
    if (severityFilter !== 'all') {
      filtered = filtered.filter(f => f.severity?.toLowerCase() === severityFilter);
    }

    // Apply search filter
    if (searchQuery) {
      const query = searchQuery.toLowerCase();
      filtered = filtered.filter(f =>
        f.title?.toLowerCase().includes(query) ||
        f.description?.toLowerCase().includes(query) ||
        f.id?.toLowerCase().includes(query) ||
        f.category?.toLowerCase().includes(query)
      );
    }

    // Apply sorting
    filtered = [...filtered].sort((a, b) => {
      switch (sortBy) {
        case 'severity':
          return getSeverityInfo(a.severity).priority - getSeverityInfo(b.severity).priority;
        case 'id':
          return (a.id || '').localeCompare(b.id || '');
        case 'category':
          return (a.category || '').localeCompare(b.category || '');
        default:
          return 0;
      }
    });

    return filtered;
  };

  /**
   * Toggle issue selection
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
    const visibleFindings = getFilteredAndSortedFindings();
    const allSelected = visibleFindings.every(f => selectedIssues.has(f.id));

    if (allSelected) {
      setSelectedIssues(prev => {
        const newSet = new Set(prev);
        visibleFindings.forEach(f => newSet.delete(f.id));
        return newSet;
      });
    } else {
      setSelectedIssues(prev => {
        const newSet = new Set(prev);
        visibleFindings.forEach(f => newSet.add(f.id));
        return newSet;
      });
    }
  };

  /**
   * Handle apply hardening
   */
  const handleApplyHardening = async () => {
    if (selectedIssues.size === 0) {
      setError('Please select at least one issue to remediate');
      return;
    }

    setApplying(true);
    setError(null);
    setSuccess(null);

    try {
      const ruleIds = Array.from(selectedIssues);
      const result = await applyHardening(ruleIds);

      setSuccess(`Successfully applied ${result.applied || selectedIssues.size} security fixes. Refresh recommended.`);
      setSelectedIssues(new Set());

      // Notify parent to refresh scan
      if (onRefreshNeeded) {
        setTimeout(() => {
          onRefreshNeeded();
        }, 2000);
      }
    } catch (err) {
      console.error('Error applying hardening:', err);
      setError(`Failed to apply fixes: ${err.message}`);
    } finally {
      setApplying(false);
    }
  };

  const filteredFindings = getFilteredAndSortedFindings();
  const allVisibleSelected = filteredFindings.length > 0 && filteredFindings.every(f => selectedIssues.has(f.id));

  if (!findings || findings.length === 0) {
    return (
      <div className="modern-scan-results">
        <div className="results-empty">
          <div className="empty-icon">
            <svg width="80" height="80" viewBox="0 0 80 80" fill="none" stroke="currentColor" strokeWidth="2">
              <circle cx="40" cy="40" r="35" opacity="0.3"/>
              <path d="M40 20v24m0 8v4" strokeLinecap="round"/>
              <circle cx="40" cy="56" r="2" fill="currentColor"/>
            </svg>
          </div>
          <h3 className="empty-title">No Security Issues Found</h3>
          <p className="empty-description">
            Your system passed all security checks. Continue monitoring for new threats.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="modern-scan-results">

      {/* Results Header */}
      <div className="results-header">
        <div className="header-left">
          <h2 className="results-title">Security Findings</h2>
          <div className="results-count">
            <span className="count-number">{filteredFindings.length}</span>
            <span className="count-label">
              {filteredFindings.length === 1 ? 'issue' : 'issues'}
              {searchQuery || severityFilter !== 'all' ? ' (filtered)' : ''}
            </span>
          </div>
        </div>

        <div className="header-right">
          {selectedIssues.size > 0 && (
            <div className="selected-count">
              <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor">
                <path d="M8 0L0 4v6c0 4.97 3.44 9.62 8 10.75C12.56 19.62 16 14.97 16 10V4L8 0zm0 14l-4-4 1.41-1.41L8 11.17l6.59-6.58L16 6l-8 8z"/>
              </svg>
              <span>{selectedIssues.size} selected</span>
            </div>
          )}
        </div>
      </div>

      {/* Alerts */}
      {error && (
        <div className="alert alert-error">
          <div className="alert-icon">
            <svg width="20" height="20" viewBox="0 0 20 20" fill="currentColor">
              <path d="M10 0C4.48 0 0 4.48 0 10C0 15.52 4.48 20 10 20C15.52 20 20 15.52 20 10C20 4.48 15.52 0 10 0ZM11 15H9V13H11V15ZM11 11H9V5H11V11Z"/>
            </svg>
          </div>
          <span className="alert-message">{error}</span>
          <button className="alert-close" onClick={() => setError(null)}>×</button>
        </div>
      )}

      {success && (
        <div className="alert alert-success">
          <div className="alert-icon">
            <svg width="20" height="20" viewBox="0 0 20 20" fill="currentColor">
              <path d="M10 0C4.48 0 0 4.48 0 10C0 15.52 4.48 20 10 20C15.52 20 20 15.52 20 10C20 4.48 15.52 0 10 0ZM8 15L3 10L4.41 8.59L8 12.17L15.59 4.58L17 6L8 15Z"/>
            </svg>
          </div>
          <span className="alert-message">{success}</span>
          <button className="alert-close" onClick={() => setSuccess(null)}>×</button>
        </div>
      )}

      {/* Controls */}
      <div className="results-controls">

        {/* Search Bar */}
        <div className="search-bar">
          <svg width="20" height="20" viewBox="0 0 20 20" fill="currentColor" className="search-icon">
            <path d="M12.9 14.32a8 8 0 1 1 1.41-1.41l5.35 5.33-1.42 1.42-5.33-5.34zM8 14A6 6 0 1 0 8 2a6 6 0 0 0 0 12z"/>
          </svg>
          <input
            type="text"
            className="search-input"
            placeholder="Search vulnerabilities..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
          />
          {searchQuery && (
            <button className="search-clear" onClick={() => setSearchQuery('')}>
              <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor">
                <path d="M8 0C3.6 0 0 3.6 0 8s3.6 8 8 8 8-3.6 8-8-3.6-8-8-8zm4 10.9L10.9 12 8 9.1 5.1 12 4 10.9 6.9 8 4 5.1 5.1 4 8 6.9 10.9 4 12 5.1 9.1 8 12 10.9z"/>
              </svg>
            </button>
          )}
        </div>

        {/* Sort Selector */}
        <div className="sort-selector">
          <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor" className="sort-icon">
            <path d="M3 2h10v2H3V2zm0 4h7v2H3V6zm0 4h4v2H3v-2z"/>
          </svg>
          <select
            className="sort-select"
            value={sortBy}
            onChange={(e) => setSortBy(e.target.value)}
          >
            <option value="severity">Sort by Severity</option>
            <option value="id">Sort by ID</option>
            <option value="category">Sort by Category</option>
          </select>
        </div>

        {/* Apply Hardening Button */}
        <button
          className="btn btn-primary btn-remediate"
          onClick={handleApplyHardening}
          disabled={applying || selectedIssues.size === 0}
        >
          {applying ? (
            <>
              <span className="btn-spinner"></span>
              <span>Applying Fixes...</span>
            </>
          ) : (
            <>
              <svg width="20" height="20" viewBox="0 0 20 20" fill="currentColor">
                <path d="M19 6.41L17.59 5 12 10.59 6.41 5 5 6.41 10.59 12 5 17.59 6.41 19 12 13.41 17.59 19 19 17.59 13.41 12 19 6.41z"/>
                <path d="M10 0C4.48 0 0 4.48 0 10s4.48 10 10 10 10-4.48 10-10S15.52 0 10 0zm0 18c-4.41 0-8-3.59-8-8s3.59-8 8-8 8 3.59 8 8-3.59 8-8 8z"/>
              </svg>
              <span>Apply Selected Fixes ({selectedIssues.size})</span>
            </>
          )}
        </button>
      </div>

      {/* Severity Filters */}
      <div className="severity-filters">
        <button
          className={`filter-chip ${severityFilter === 'all' ? 'active' : ''}`}
          onClick={() => setSeverityFilter('all')}
        >
          <span className="chip-label">All</span>
          <span className="chip-count">{getSeverityCount('all')}</span>
        </button>
        <button
          className={`filter-chip severity-critical ${severityFilter === 'critical' ? 'active' : ''}`}
          onClick={() => setSeverityFilter('critical')}
        >
          <span className="chip-dot"></span>
          <span className="chip-label">Critical</span>
          <span className="chip-count">{getSeverityCount('critical')}</span>
        </button>
        <button
          className={`filter-chip severity-high ${severityFilter === 'high' ? 'active' : ''}`}
          onClick={() => setSeverityFilter('high')}
        >
          <span className="chip-dot"></span>
          <span className="chip-label">High</span>
          <span className="chip-count">{getSeverityCount('high')}</span>
        </button>
        <button
          className={`filter-chip severity-medium ${severityFilter === 'medium' ? 'active' : ''}`}
          onClick={() => setSeverityFilter('medium')}
        >
          <span className="chip-dot"></span>
          <span className="chip-label">Medium</span>
          <span className="chip-count">{getSeverityCount('medium')}</span>
        </button>
        <button
          className={`filter-chip severity-low ${severityFilter === 'low' ? 'active' : ''}`}
          onClick={() => setSeverityFilter('low')}
        >
          <span className="chip-dot"></span>
          <span className="chip-label">Low</span>
          <span className="chip-count">{getSeverityCount('low')}</span>
        </button>
      </div>

      {/* Results Table */}
      {filteredFindings.length > 0 ? (
        <div className="results-table-container">
          <table className="results-table">
            <thead>
              <tr>
                <th className="th-checkbox">
                  <div className="checkbox-wrapper">
                    <input
                      type="checkbox"
                      className="checkbox-input"
                      checked={allVisibleSelected}
                      onChange={toggleAllVisibleIssues}
                      id="select-all"
                    />
                    <label htmlFor="select-all" className="checkbox-label"></label>
                  </div>
                </th>
                <th className="th-severity">Severity</th>
                <th className="th-id">ID</th>
                <th className="th-category">Category</th>
                <th className="th-title">Issue</th>
                <th className="th-actions">Actions</th>
              </tr>
            </thead>
            <tbody>
              {filteredFindings.map((finding, index) => {
                const severityInfo = getSeverityInfo(finding.severity);
                const isSelected = selectedIssues.has(finding.id);

                return (
                  <tr
                    key={finding.id || index}
                    className={`table-row ${isSelected ? 'row-selected' : ''}`}
                  >
                    <td className="td-checkbox">
                      <div className="checkbox-wrapper">
                        <input
                          type="checkbox"
                          className="checkbox-input"
                          checked={isSelected}
                          onChange={() => toggleIssueSelection(finding.id)}
                          id={`check-${finding.id}`}
                        />
                        <label htmlFor={`check-${finding.id}`} className="checkbox-label"></label>
                      </div>
                    </td>
                    <td className="td-severity">
                      <div className={`severity-badge ${severityInfo.class}`}>
                        <span className="severity-dot" style={{ backgroundColor: severityInfo.color }}></span>
                        <span className="severity-text">{finding.severity || 'Unknown'}</span>
                      </div>
                    </td>
                    <td className="td-id">
                      <code className="finding-id">{finding.id}</code>
                    </td>
                    <td className="td-category">
                      <div className="category-badge">
                        <svg width="14" height="14" viewBox="0 0 14 14" fill="currentColor">
                          <path d="M7 0L0 4v4c0 4.3 3 8.3 7 9.3 4-1 7-5 7-9.3V4L7 0z"/>
                        </svg>
                        <span>{finding.category || 'General'}</span>
                      </div>
                    </td>
                    <td className="td-title">
                      <div className="finding-title">
                        <strong>{finding.title || 'Untitled Issue'}</strong>
                        {finding.description && (
                          <p className="finding-description">
                            {finding.description.length > 80
                              ? `${finding.description.substring(0, 80)}...`
                              : finding.description}
                          </p>
                        )}
                      </div>
                    </td>
                    <td className="td-actions">
                      <button
                        className="btn-action btn-view"
                        onClick={() => setSelectedVulnerability(finding)}
                        title="View details and remediation steps"
                      >
                        <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor">
                          <path d="M8 3C4.5 3 1.5 5.5 0 8c1.5 2.5 4.5 5 8 5s6.5-2.5 8-5c-1.5-2.5-4.5-5-8-5zm0 8c-1.7 0-3-1.3-3-3s1.3-3 3-3 3 1.3 3 3-1.3 3-3 3z"/>
                          <circle cx="8" cy="8" r="1.5"/>
                        </svg>
                        <span>View Details</span>
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="results-empty-filtered">
          <div className="empty-icon">
            <svg width="60" height="60" viewBox="0 0 60 60" fill="none" stroke="currentColor" strokeWidth="2">
              <circle cx="30" cy="30" r="25" opacity="0.3"/>
              <path d="M20 30h20M30 20v20" strokeLinecap="round"/>
            </svg>
          </div>
          <h3 className="empty-title">No Matching Results</h3>
          <p className="empty-description">
            Try adjusting your filters or search query
          </p>
          <button
            className="btn btn-secondary"
            onClick={() => {
              setSeverityFilter('all');
              setSearchQuery('');
            }}
          >
            Clear Filters
          </button>
        </div>
      )}

      {/* Vulnerability Details Modal */}
      {selectedVulnerability && (
        <ModernVulnerabilityModal
          vulnerability={selectedVulnerability}
          onClose={() => setSelectedVulnerability(null)}
        />
      )}
    </div>
  );
}

export default ModernScanResults;
