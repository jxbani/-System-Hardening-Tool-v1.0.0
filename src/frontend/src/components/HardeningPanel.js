import React, { useState, useEffect } from 'react';
import { applyHardening, rollbackCheckpoint, getCheckpoints } from '../api/client';
import './HardeningPanel.css';

/**
 * HardeningPanel Component
 * Displays hardening rules and allows applying them with real-time progress tracking
 */
function HardeningPanel({ selectedRules = [], onComplete }) {
  // State management
  const [hardeningStatus, setHardeningStatus] = useState('idle'); // idle, running, success, error
  const [ruleStatuses, setRuleStatuses] = useState({});
  const [currentRuleIndex, setCurrentRuleIndex] = useState(0);
  const [progress, setProgress] = useState(0);
  const [error, setError] = useState(null);
  const [checkpointId, setCheckpointId] = useState(null);
  const [sessionResults, setSessionResults] = useState(null);
  const [showRollbackConfirm, setShowRollbackConfirm] = useState(false);
  const [rollbackInProgress, setRollbackInProgress] = useState(false);

  /**
   * Initialize rule statuses when selected rules change
   */
  useEffect(() => {
    if (selectedRules.length > 0) {
      const initialStatuses = {};
      selectedRules.forEach(rule => {
        initialStatuses[rule.id] = {
          status: 'pending',
          message: 'Waiting to apply...',
          ruleData: rule
        };
      });
      setRuleStatuses(initialStatuses);
      setProgress(0);
      setCurrentRuleIndex(0);
    }
  }, [selectedRules]);

  /**
   * Apply hardening rules
   */
  const handleApplyHardening = async () => {
    if (selectedRules.length === 0) {
      setError('No rules selected');
      return;
    }

    setHardeningStatus('running');
    setError(null);
    setProgress(0);
    setCurrentRuleIndex(0);

    try {
      // Extract rule IDs
      const ruleIds = selectedRules.map(rule => rule.id);

      // Simulate progressive updates (in real implementation, use websockets or polling)
      simulateProgressiveUpdates();

      // Call backend API
      const result = await applyHardening(ruleIds);

      // Process results
      if (result.session) {
        setSessionResults(result.session);
        setCheckpointId(result.session.checkpoint_id);

        // Update individual rule statuses from session results
        if (result.session.results) {
          const updatedStatuses = {};
          result.session.results.forEach(ruleResult => {
            updatedStatuses[ruleResult.rule_id] = {
              status: ruleResult.status,
              message: getStatusMessage(ruleResult),
              before: ruleResult.before_value,
              after: ruleResult.after_value,
              duration: ruleResult.duration_seconds,
              error: ruleResult.error_message,
              warnings: ruleResult.warning_messages,
              ruleData: selectedRules.find(r => r.id === ruleResult.rule_id)
            };
          });
          setRuleStatuses(updatedStatuses);
        }

        // Check overall status
        if (result.session.failed_rules > 0) {
          setHardeningStatus('error');
          setError(`${result.session.failed_rules} rule(s) failed to apply`);
        } else if (result.session.successful_rules === result.session.total_rules) {
          setHardeningStatus('success');
          setProgress(100);
        } else {
          setHardeningStatus('error');
          setError('Some rules were skipped or failed');
        }
      }

      // Notify parent component
      if (onComplete) {
        onComplete(result);
      }

    } catch (err) {
      console.error('Error applying hardening:', err);
      setError(err.message);
      setHardeningStatus('error');

      // Mark all pending rules as failed
      const updatedStatuses = { ...ruleStatuses };
      Object.keys(updatedStatuses).forEach(ruleId => {
        if (updatedStatuses[ruleId].status === 'pending' ||
            updatedStatuses[ruleId].status === 'in_progress') {
          updatedStatuses[ruleId].status = 'failed';
          updatedStatuses[ruleId].message = 'Failed due to error';
        }
      });
      setRuleStatuses(updatedStatuses);
    }
  };

  /**
   * Simulate progressive rule updates
   * In production, this would use WebSockets or server-sent events
   */
  const simulateProgressiveUpdates = () => {
    let currentIndex = 0;
    const interval = setInterval(() => {
      if (currentIndex < selectedRules.length) {
        setCurrentRuleIndex(currentIndex);
        setProgress(Math.round((currentIndex / selectedRules.length) * 100));

        // Mark current rule as in progress
        setRuleStatuses(prev => ({
          ...prev,
          [selectedRules[currentIndex].id]: {
            ...prev[selectedRules[currentIndex].id],
            status: 'in_progress',
            message: 'Applying rule...'
          }
        }));

        currentIndex++;
      } else {
        clearInterval(interval);
        setProgress(100);
      }
    }, 500); // Update every 500ms

    // Store interval ID to clear it if needed
    return () => clearInterval(interval);
  };

  /**
   * Get human-readable status message from rule result
   */
  const getStatusMessage = (ruleResult) => {
    if (ruleResult.status === 'success') {
      return ruleResult.validation_message || 'Applied successfully';
    } else if (ruleResult.status === 'failed') {
      return ruleResult.error_message || 'Failed to apply';
    } else if (ruleResult.status === 'skipped') {
      return ruleResult.error_message || 'Skipped';
    } else if (ruleResult.status === 'rolled_back') {
      return 'Rolled back due to error';
    }
    return ruleResult.status;
  };

  /**
   * Handle rollback action
   */
  const handleRollback = async () => {
    if (!checkpointId) {
      setError('No checkpoint ID available for rollback');
      return;
    }

    setRollbackInProgress(true);
    setError(null);

    try {
      const result = await rollbackCheckpoint(checkpointId);

      if (result.success) {
        // Mark all rules as rolled back
        const updatedStatuses = {};
        Object.keys(ruleStatuses).forEach(ruleId => {
          updatedStatuses[ruleId] = {
            ...ruleStatuses[ruleId],
            status: 'rolled_back',
            message: 'Rolled back successfully'
          };
        });
        setRuleStatuses(updatedStatuses);
        setHardeningStatus('idle');
        setShowRollbackConfirm(false);

        // Notify user
        alert('System successfully rolled back to previous state');
      } else {
        setError(result.message || 'Rollback failed');
      }
    } catch (err) {
      console.error('Error during rollback:', err);
      setError(`Rollback failed: ${err.message}`);
    } finally {
      setRollbackInProgress(false);
    }
  };

  /**
   * Get status icon for a rule
   */
  const getStatusIcon = (status) => {
    switch (status) {
      case 'success':
        return '✓';
      case 'failed':
        return '✗';
      case 'in_progress':
        return '⟳';
      case 'pending':
        return '○';
      case 'skipped':
        return '⊘';
      case 'rolled_back':
        return '↶';
      default:
        return '○';
    }
  };

  /**
   * Get severity badge class
   */
  const getSeverityClass = (severity) => {
    return `severity-badge severity-${severity?.toLowerCase() || 'medium'}`;
  };

  /**
   * Calculate summary statistics
   */
  const getSummaryStats = () => {
    const stats = {
      total: selectedRules.length,
      success: 0,
      failed: 0,
      pending: 0,
      inProgress: 0
    };

    Object.values(ruleStatuses).forEach(rule => {
      if (rule.status === 'success') stats.success++;
      else if (rule.status === 'failed') stats.failed++;
      else if (rule.status === 'in_progress') stats.inProgress++;
      else if (rule.status === 'pending') stats.pending++;
    });

    return stats;
  };

  const summaryStats = getSummaryStats();

  // Empty state
  if (selectedRules.length === 0) {
    return (
      <div className="hardening-panel">
        <div className="empty-state">
          <div className="empty-icon">🛡️</div>
          <h3>No Rules Selected</h3>
          <p>Select hardening rules to apply security configurations to your system.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="hardening-panel">
      {/* Header */}
      <div className="panel-header">
        <div className="header-content">
          <h2>Apply Hardening Rules</h2>
          <div className="rule-count">
            {selectedRules.length} rule{selectedRules.length !== 1 ? 's' : ''} selected
          </div>
        </div>

        <div className="header-actions">
          {hardeningStatus === 'idle' && (
            <button
              className="btn btn-primary btn-apply"
              onClick={handleApplyHardening}
            >
              <span className="btn-icon">▶</span>
              Apply Hardening
            </button>
          )}

          {hardeningStatus === 'error' && checkpointId && (
            <button
              className="btn btn-danger btn-rollback"
              onClick={() => setShowRollbackConfirm(true)}
              disabled={rollbackInProgress}
            >
              <span className="btn-icon">↶</span>
              {rollbackInProgress ? 'Rolling back...' : 'Rollback Changes'}
            </button>
          )}
        </div>
      </div>

      {/* Error Alert */}
      {error && (
        <div className="alert alert-error">
          <span className="alert-icon">⚠️</span>
          <div className="alert-content">
            <strong>Error:</strong> {error}
          </div>
          <button
            className="alert-close"
            onClick={() => setError(null)}
            aria-label="Close"
          >
            ×
          </button>
        </div>
      )}

      {/* Progress Bar */}
      {hardeningStatus === 'running' && (
        <div className="progress-section">
          <div className="progress-header">
            <span className="progress-label">
              Applying rules... ({currentRuleIndex + 1}/{selectedRules.length})
            </span>
            <span className="progress-percentage">{progress}%</span>
          </div>
          <div className="progress-bar">
            <div
              className="progress-fill"
              style={{ width: `${progress}%` }}
            >
              <div className="progress-animation"></div>
            </div>
          </div>
        </div>
      )}

      {/* Summary Statistics */}
      {hardeningStatus !== 'idle' && (
        <div className="summary-stats">
          <div className="stat-item">
            <span className="stat-label">Total:</span>
            <span className="stat-value">{summaryStats.total}</span>
          </div>
          <div className="stat-item stat-success">
            <span className="stat-label">Success:</span>
            <span className="stat-value">{summaryStats.success}</span>
          </div>
          {summaryStats.failed > 0 && (
            <div className="stat-item stat-failed">
              <span className="stat-label">Failed:</span>
              <span className="stat-value">{summaryStats.failed}</span>
            </div>
          )}
          {summaryStats.inProgress > 0 && (
            <div className="stat-item stat-progress">
              <span className="stat-label">In Progress:</span>
              <span className="stat-value">{summaryStats.inProgress}</span>
            </div>
          )}
        </div>
      )}

      {/* Rules List */}
      <div className="rules-list">
        {selectedRules.map((rule, index) => {
          const status = ruleStatuses[rule.id] || {};
          const isActive = hardeningStatus === 'running' && index === currentRuleIndex;

          return (
            <div
              key={rule.id}
              className={`rule-item ${status.status || 'pending'} ${isActive ? 'active' : ''}`}
            >
              <div className="rule-status-icon">
                {getStatusIcon(status.status)}
              </div>

              <div className="rule-details">
                <div className="rule-header-row">
                  <h4 className="rule-name">{rule.name}</h4>
                  <span className={getSeverityClass(rule.severity)}>
                    {rule.severity || 'medium'}
                  </span>
                </div>

                <p className="rule-description">{rule.description}</p>

                {/* Configuration Details */}
                <div className="rule-config">
                  <span className="config-item">
                    <strong>Parameter:</strong> {rule.parameter}
                  </span>
                  <span className="config-item">
                    <strong>Value:</strong> {rule.expected_value}
                  </span>
                  {rule.file && (
                    <span className="config-item">
                      <strong>File:</strong> <code>{rule.file}</code>
                    </span>
                  )}
                </div>

                {/* Status Message */}
                <div className="rule-status-message">
                  {status.message && (
                    <div className={`status-text status-${status.status}`}>
                      {status.message}
                    </div>
                  )}

                  {/* Before/After Values */}
                  {status.before !== undefined && (
                    <div className="value-comparison">
                      <span className="value-before">
                        Before: <code>{status.before || '(not set)'}</code>
                      </span>
                      <span className="value-arrow">→</span>
                      <span className="value-after">
                        After: <code>{status.after || rule.expected_value}</code>
                      </span>
                    </div>
                  )}

                  {/* Warnings */}
                  {status.warnings && status.warnings.length > 0 && (
                    <div className="rule-warnings">
                      {status.warnings.map((warning, idx) => (
                        <div key={idx} className="warning-item">
                          ⚠️ {warning}
                        </div>
                      ))}
                    </div>
                  )}

                  {/* Duration */}
                  {status.duration !== undefined && (
                    <div className="rule-duration">
                      Completed in {status.duration.toFixed(2)}s
                    </div>
                  )}
                </div>
              </div>
            </div>
          );
        })}
      </div>

      {/* Success Message */}
      {hardeningStatus === 'success' && (
        <div className="alert alert-success">
          <span className="alert-icon">✓</span>
          <div className="alert-content">
            <strong>Success!</strong> All hardening rules applied successfully.
            {checkpointId && (
              <div className="checkpoint-info">
                Checkpoint ID: <code>{checkpointId}</code>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Rollback Confirmation Modal */}
      {showRollbackConfirm && (
        <div className="modal-overlay" onClick={() => setShowRollbackConfirm(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h3>Confirm Rollback</h3>
              <button
                className="modal-close"
                onClick={() => setShowRollbackConfirm(false)}
              >
                ×
              </button>
            </div>
            <div className="modal-body">
              <p>
                Are you sure you want to rollback all changes? This will restore
                the system to its state before applying these hardening rules.
              </p>
              {checkpointId && (
                <p className="checkpoint-info">
                  Checkpoint ID: <code>{checkpointId}</code>
                </p>
              )}
            </div>
            <div className="modal-footer">
              <button
                className="btn btn-secondary"
                onClick={() => setShowRollbackConfirm(false)}
                disabled={rollbackInProgress}
              >
                Cancel
              </button>
              <button
                className="btn btn-danger"
                onClick={handleRollback}
                disabled={rollbackInProgress}
              >
                {rollbackInProgress ? 'Rolling back...' : 'Confirm Rollback'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default HardeningPanel;
