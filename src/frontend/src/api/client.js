/**
 * API Client for System Hardening Tool
 * Handles all communication with the Flask backend
 */

const API_BASE_URL = '/api';

/**
 * Helper function to handle fetch responses
 * @param {Response} response - Fetch response object
 * @returns {Promise<any>} Parsed JSON data
 * @throws {Error} If response is not ok
 */
async function handleResponse(response) {
  if (!response.ok) {
    let errorMessage = `HTTP error! status: ${response.status}`;

    try {
      const errorData = await response.json();
      errorMessage = errorData.error || errorData.message || errorMessage;
    } catch (e) {
      // If JSON parsing fails, use the default error message
    }

    throw new Error(errorMessage);
  }

  return await response.json();
}

/**
 * Get system information
 * @returns {Promise<Object>} System information including OS, platform, etc.
 */
export async function getSystemInfo() {
  try {
    const response = await fetch(`${API_BASE_URL}/system-info`, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
      },
    });

    return await handleResponse(response);
  } catch (error) {
    console.error('Error fetching system info:', error);
    throw new Error(`Failed to get system information: ${error.message}`);
  }
}

/**
 * Run a security scan on the system
 * @returns {Promise<Object>} Scan results with vulnerabilities and recommendations
 */
export async function runScan() {
  try {
    const response = await fetch(`${API_BASE_URL}/scan`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
    });

    return await handleResponse(response);
  } catch (error) {
    console.error('Error running scan:', error);
    throw new Error(`Failed to run security scan: ${error.message}`);
  }
}

/**
 * Apply hardening rules to the system
 * @param {Array<string>} rules - Array of rule IDs to apply
 * @returns {Promise<Object>} Results of applying hardening rules
 */
export async function applyHardening(rules) {
  if (!Array.isArray(rules)) {
    throw new Error('Rules must be an array');
  }

  try {
    const response = await fetch(`${API_BASE_URL}/harden`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ rules }),
    });

    return await handleResponse(response);
  } catch (error) {
    console.error('Error applying hardening:', error);
    throw new Error(`Failed to apply hardening rules: ${error.message}`);
  }
}

/**
 * Generate a security report
 * @param {Object} options - Report generation options
 * @param {string} options.format - Report format (e.g., 'json', 'html', 'pdf')
 * @param {string} options.title - Report title
 * @param {Object} options.scan_results - Scan results data
 * @param {Object} options.hardening_session - Hardening session data
 * @param {Object} options.before_scan - Before scan results
 * @param {Object} options.after_scan - After scan results
 * @returns {Promise<Blob|Object>} Generated report (Blob for PDF/HTML, Object for JSON)
 */
export async function generateReport(options = {}) {
  const {
    format = 'pdf',
    title = 'Security Report',
    scan_results,
    hardening_session,
    before_scan,
    after_scan
  } = options;

  try {
    const response = await fetch(`${API_BASE_URL}/report`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        format,
        title,
        scan_results,
        hardening_session,
        before_scan,
        after_scan
      }),
    });

    // For all downloadable formats (not JSON), return the blob for download
    if (format !== 'json') {
      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.message || `HTTP error! status: ${response.status}`);
      }
      return await response.blob();
    }

    // For JSON format only, return the parsed object
    return await handleResponse(response);
  } catch (error) {
    console.error('Error generating report:', error);
    throw new Error(`Failed to generate report: ${error.message}`);
  }
}

/**
 * Check backend health status
 * @returns {Promise<Object>} Health status of the backend
 */
export async function checkHealth() {
  try {
    const response = await fetch(`${API_BASE_URL}/health`, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
      },
    });

    return await handleResponse(response);
  } catch (error) {
    console.error('Error checking backend health:', error);
    throw new Error(`Failed to check backend health: ${error.message}`);
  }
}

/**
 * Rollback to a specific checkpoint
 * @param {string} checkpointId - ID of the checkpoint to restore
 * @returns {Promise<Object>} Rollback operation result
 */
export async function rollbackCheckpoint(checkpointId) {
  if (!checkpointId) {
    throw new Error('Checkpoint ID is required');
  }

  try {
    const response = await fetch(`${API_BASE_URL}/rollback`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ checkpoint_id: checkpointId }),
    });

    return await handleResponse(response);
  } catch (error) {
    console.error('Error rolling back:', error);
    throw new Error(`Failed to rollback: ${error.message}`);
  }
}

/**
 * Get list of available checkpoints
 * @returns {Promise<Array>} List of checkpoints
 */
export async function getCheckpoints() {
  try {
    const response = await fetch(`${API_BASE_URL}/checkpoints`, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
      },
    });

    return await handleResponse(response);
  } catch (error) {
    console.error('Error fetching checkpoints:', error);
    throw new Error(`Failed to get checkpoints: ${error.message}`);
  }
}

// ========================
// Real-time Monitoring API
// ========================

/**
 * Get current system monitoring status
 * @returns {Promise<Object>} Current monitoring status
 */
export async function getMonitoringStatus() {
  try {
    const response = await fetch(`${API_BASE_URL}/monitoring/status`, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
      },
    });

    return await handleResponse(response);
  } catch (error) {
    console.error('Error getting monitoring status:', error);
    throw new Error(`Failed to get monitoring status: ${error.message}`);
  }
}

/**
 * Get current system metrics
 * @returns {Promise<Object>} Current system metrics
 */
export async function getCurrentMetrics() {
  try {
    const response = await fetch(`${API_BASE_URL}/monitoring/metrics`, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
      },
    });

    return await handleResponse(response);
  } catch (error) {
    console.error('Error getting current metrics:', error);
    throw new Error(`Failed to get current metrics: ${error.message}`);
  }
}

/**
 * Get metrics history
 * @param {number} limit - Optional limit on number of historical entries
 * @returns {Promise<Object>} Metrics history
 */
export async function getMetricsHistory(limit) {
  try {
    const url = limit
      ? `${API_BASE_URL}/monitoring/history?limit=${limit}`
      : `${API_BASE_URL}/monitoring/history`;

    const response = await fetch(url, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
      },
    });

    return await handleResponse(response);
  } catch (error) {
    console.error('Error getting metrics history:', error);
    throw new Error(`Failed to get metrics history: ${error.message}`);
  }
}

/**
 * Start real-time monitoring
 * @param {number} interval - Monitoring interval in seconds (default: 5)
 * @returns {Promise<Object>} Start monitoring result
 */
export async function startMonitoring(interval = 5) {
  try {
    const response = await fetch(`${API_BASE_URL}/monitoring/start`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ interval }),
    });

    return await handleResponse(response);
  } catch (error) {
    console.error('Error starting monitoring:', error);
    throw new Error(`Failed to start monitoring: ${error.message}`);
  }
}

/**
 * Stop real-time monitoring
 * @returns {Promise<Object>} Stop monitoring result
 */
export async function stopMonitoring() {
  try {
    const response = await fetch(`${API_BASE_URL}/monitoring/stop`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
    });

    return await handleResponse(response);
  } catch (error) {
    console.error('Error stopping monitoring:', error);
    throw new Error(`Failed to stop monitoring: ${error.message}`);
  }
}

/**
 * Set monitoring threshold
 * @param {string} metric - Metric name
 * @param {number} value - Threshold value
 * @returns {Promise<Object>} Set threshold result
 */
export async function setMonitoringThreshold(metric, value) {
  try {
    const response = await fetch(`${API_BASE_URL}/monitoring/thresholds`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ metric, value }),
    });

    return await handleResponse(response);
  } catch (error) {
    console.error('Error setting threshold:', error);
    throw new Error(`Failed to set threshold: ${error.message}`);
  }
}

// ========================
// Compliance Framework API
// ========================

/**
 * Check CIS Benchmarks compliance
 * @param {number} level - CIS level (1 or 2)
 * @returns {Promise<Object>} CIS compliance results
 */
export async function checkCISCompliance(level = 1) {
  try {
    const response = await fetch(`${API_BASE_URL}/compliance/cis?level=${level}`, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
      },
    });

    return await handleResponse(response);
  } catch (error) {
    console.error('Error checking CIS compliance:', error);
    throw new Error(`Failed to check CIS compliance: ${error.message}`);
  }
}

/**
 * Check NIST 800-53 compliance
 * @returns {Promise<Object>} NIST compliance results
 */
export async function checkNISTCompliance() {
  try {
    const response = await fetch(`${API_BASE_URL}/compliance/nist`, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
      },
    });

    return await handleResponse(response);
  } catch (error) {
    console.error('Error checking NIST compliance:', error);
    throw new Error(`Failed to check NIST compliance: ${error.message}`);
  }
}

/**
 * Check PCI-DSS compliance
 * @returns {Promise<Object>} PCI-DSS compliance results
 */
export async function checkPCIDSSCompliance() {
  try {
    const response = await fetch(`${API_BASE_URL}/compliance/pci-dss`, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
      },
    });

    return await handleResponse(response);
  } catch (error) {
    console.error('Error checking PCI-DSS compliance:', error);
    throw new Error(`Failed to check PCI-DSS compliance: ${error.message}`);
  }
}

/**
 * Check HIPAA compliance
 * @returns {Promise<Object>} HIPAA compliance results
 */
export async function checkHIPAACompliance() {
  try {
    const response = await fetch(`${API_BASE_URL}/compliance/hipaa`, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
      },
    });

    return await handleResponse(response);
  } catch (error) {
    console.error('Error checking HIPAA compliance:', error);
    throw new Error(`Failed to check HIPAA compliance: ${error.message}`);
  }
}

/**
 * Check SOC 2 compliance
 * @returns {Promise<Object>} SOC 2 compliance results
 */
export async function checkSOC2Compliance() {
  try {
    const response = await fetch(`${API_BASE_URL}/compliance/soc2`, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
      },
    });

    return await handleResponse(response);
  } catch (error) {
    console.error('Error checking SOC 2 compliance:', error);
    throw new Error(`Failed to check SOC 2 compliance: ${error.message}`);
  }
}

/**
 * Check all compliance frameworks
 * @returns {Promise<Object>} All compliance results
 */
export async function checkAllCompliance() {
  try {
    const response = await fetch(`${API_BASE_URL}/compliance/all`, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
      },
    });

    return await handleResponse(response);
  } catch (error) {
    console.error('Error checking all compliance:', error);
    throw new Error(`Failed to check all compliance: ${error.message}`);
  }
}

// ========================
// Automated Remediation API
// ========================

/**
 * Auto-fix a vulnerability
 * @param {string} vulnerabilityId - Vulnerability ID to fix
 * @param {string} severity - Severity level
 * @param {boolean} requiresApproval - Whether approval is required
 * @returns {Promise<Object>} Auto-fix result
 */
export async function autoFixVulnerability(vulnerabilityId, severity = 'medium', requiresApproval = true) {
  try {
    const response = await fetch(`${API_BASE_URL}/remediation/auto-fix`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        vulnerability_id: vulnerabilityId,
        severity,
        requires_approval: requiresApproval
      }),
    });

    return await handleResponse(response);
  } catch (error) {
    console.error('Error auto-fixing vulnerability:', error);
    throw new Error(`Failed to auto-fix vulnerability: ${error.message}`);
  }
}

/**
 * Create a system checkpoint
 * @param {string} description - Checkpoint description
 * @returns {Promise<Object>} Checkpoint creation result
 */
export async function createCheckpoint(description = 'Manual checkpoint') {
  try {
    const response = await fetch(`${API_BASE_URL}/remediation/checkpoint`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ description }),
    });

    return await handleResponse(response);
  } catch (error) {
    console.error('Error creating checkpoint:', error);
    throw new Error(`Failed to create checkpoint: ${error.message}`);
  }
}

/**
 * Rollback to a checkpoint
 * @param {string} checkpointId - Checkpoint ID
 * @returns {Promise<Object>} Rollback result
 */
export async function rollbackToCheckpoint(checkpointId) {
  try {
    const response = await fetch(`${API_BASE_URL}/remediation/rollback`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ checkpoint_id: checkpointId }),
    });

    return await handleResponse(response);
  } catch (error) {
    console.error('Error rolling back:', error);
    throw new Error(`Failed to rollback: ${error.message}`);
  }
}

/**
 * Get pending remediation approvals
 * @returns {Promise<Object>} Pending approvals
 */
export async function getPendingApprovals() {
  try {
    const response = await fetch(`${API_BASE_URL}/remediation/pending`, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
      },
    });

    return await handleResponse(response);
  } catch (error) {
    console.error('Error getting pending approvals:', error);
    throw new Error(`Failed to get pending approvals: ${error.message}`);
  }
}

/**
 * Approve a remediation
 * @param {string} remediationId - Remediation ID
 * @returns {Promise<Object>} Approval result
 */
export async function approveRemediation(remediationId) {
  try {
    const response = await fetch(`${API_BASE_URL}/remediation/approve/${remediationId}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
    });

    return await handleResponse(response);
  } catch (error) {
    console.error('Error approving remediation:', error);
    throw new Error(`Failed to approve remediation: ${error.message}`);
  }
}

/**
 * Reject a remediation
 * @param {string} remediationId - Remediation ID
 * @param {string} reason - Rejection reason
 * @returns {Promise<Object>} Rejection result
 */
export async function rejectRemediation(remediationId, reason = 'Rejected by user') {
  try {
    const response = await fetch(`${API_BASE_URL}/remediation/reject/${remediationId}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ reason }),
    });

    return await handleResponse(response);
  } catch (error) {
    console.error('Error rejecting remediation:', error);
    throw new Error(`Failed to reject remediation: ${error.message}`);
  }
}

/**
 * Get remediation history
 * @param {number} limit - Optional limit on number of entries
 * @returns {Promise<Object>} Remediation history
 */
export async function getRemediationHistory(limit) {
  try {
    const url = limit
      ? `${API_BASE_URL}/remediation/history?limit=${limit}`
      : `${API_BASE_URL}/remediation/history`;

    const response = await fetch(url, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
      },
    });

    return await handleResponse(response);
  } catch (error) {
    console.error('Error getting remediation history:', error);
    throw new Error(`Failed to get remediation history: ${error.message}`);
  }
}

/**
 * Schedule a maintenance window
 * @param {string} startTime - Start time in ISO format
 * @param {number} durationHours - Duration in hours
 * @param {string} description - Window description
 * @returns {Promise<Object>} Scheduling result
 */
export async function scheduleMaintenanceWindow(startTime, durationHours = 4, description = 'Scheduled maintenance') {
  try {
    const response = await fetch(`${API_BASE_URL}/remediation/maintenance-window`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        start_time: startTime,
        duration_hours: durationHours,
        description
      }),
    });

    return await handleResponse(response);
  } catch (error) {
    console.error('Error scheduling maintenance window:', error);
    throw new Error(`Failed to schedule maintenance window: ${error.message}`);
  }
}

// ========================
// Historical Tracking API
// ========================

/**
 * Get scan history
 * @param {number} limit - Optional limit on number of scans
 * @param {number} offset - Optional offset for pagination
 * @returns {Promise<Object>} Scan history
 */
export async function getScanHistory(limit, offset = 0) {
  try {
    const params = new URLSearchParams();
    if (limit) params.append('limit', limit);
    if (offset) params.append('offset', offset);

    const url = `${API_BASE_URL}/history/scans${params.toString() ? '?' + params.toString() : ''}`;

    const response = await fetch(url, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
      },
    });

    return await handleResponse(response);
  } catch (error) {
    console.error('Error getting scan history:', error);
    throw new Error(`Failed to get scan history: ${error.message}`);
  }
}

/**
 * Get scan details by ID
 * @param {string} scanId - Scan ID
 * @returns {Promise<Object>} Scan details
 */
export async function getScanDetails(scanId) {
  try {
    const response = await fetch(`${API_BASE_URL}/history/scans/${scanId}`, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
      },
    });

    return await handleResponse(response);
  } catch (error) {
    console.error('Error getting scan details:', error);
    throw new Error(`Failed to get scan details: ${error.message}`);
  }
}

/**
 * Get hardening session history
 * @param {number} limit - Optional limit on number of sessions
 * @param {number} offset - Optional offset for pagination
 * @returns {Promise<Object>} Hardening history
 */
export async function getHardeningHistory(limit, offset = 0) {
  try {
    const params = new URLSearchParams();
    if (limit) params.append('limit', limit);
    if (offset) params.append('offset', offset);

    const url = `${API_BASE_URL}/history/hardening${params.toString() ? '?' + params.toString() : ''}`;

    const response = await fetch(url, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
      },
    });

    return await handleResponse(response);
  } catch (error) {
    console.error('Error getting hardening history:', error);
    throw new Error(`Failed to get hardening history: ${error.message}`);
  }
}

/**
 * Get vulnerability trends
 * @param {number} days - Number of days to look back (default: 30)
 * @returns {Promise<Object>} Trend data
 */
export async function getVulnerabilityTrends(days = 30) {
  try {
    const response = await fetch(`${API_BASE_URL}/history/trends?days=${days}`, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
      },
    });

    return await handleResponse(response);
  } catch (error) {
    console.error('Error getting vulnerability trends:', error);
    throw new Error(`Failed to get vulnerability trends: ${error.message}`);
  }
}

/**
 * Get overall statistics
 * @returns {Promise<Object>} Statistics
 */
export async function getStatistics() {
  try {
    const response = await fetch(`${API_BASE_URL}/history/stats`, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
      },
    });

    return await handleResponse(response);
  } catch (error) {
    console.error('Error getting statistics:', error);
    throw new Error(`Failed to get statistics: ${error.message}`);
  }
}

/**
 * Get risk score trends over time
 * @param {number} days - Number of days to look back (default: 30)
 * @returns {Promise<Object>} Risk trend data
 */
export async function getRiskTrends(days = 30) {
  try {
    const url = `${API_BASE_URL}/risk/trends?days=${days}`;
    const response = await fetch(url, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
      },
    });

    return await handleResponse(response);
  } catch (error) {
    console.error('Error getting risk trends:', error);
    throw new Error(`Failed to get risk trends: ${error.message}`);
  }
}

/**
 * Get current risk distribution
 * @returns {Promise<Object>} Risk distribution by level
 */
export async function getRiskDistribution() {
  try {
    const url = `${API_BASE_URL}/risk/distribution`;
    const response = await fetch(url, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
      },
    });

    return await handleResponse(response);
  } catch (error) {
    console.error('Error getting risk distribution:', error);
    throw new Error(`Failed to get risk distribution: ${error.message}`);
  }
}

/**
 * Get highest risk vulnerabilities
 * @param {number} limit - Maximum number of vulnerabilities to return (default: 10)
 * @returns {Promise<Object>} High risk vulnerabilities
 */
export async function getHighRiskVulnerabilities(limit = 10) {
  try {
    const url = `${API_BASE_URL}/risk/high-risk?limit=${limit}`;
    const response = await fetch(url, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
      },
    });

    return await handleResponse(response);
  } catch (error) {
    console.error('Error getting high risk vulnerabilities:', error);
    throw new Error(`Failed to get high risk vulnerabilities: ${error.message}`);
  }
}

/**
 * Get prioritized risk recommendations
 * @param {Array} vulnerabilities - Array of vulnerability objects
 * @returns {Promise<Object>} Prioritized recommendations
 */
export async function getRiskRecommendations(vulnerabilities) {
  try {
    const url = `${API_BASE_URL}/risk/recommendations`;
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ vulnerabilities }),
    });

    return await handleResponse(response);
  } catch (error) {
    console.error('Error getting risk recommendations:', error);
    throw new Error(`Failed to get risk recommendations: ${error.message}`);
  }
}
