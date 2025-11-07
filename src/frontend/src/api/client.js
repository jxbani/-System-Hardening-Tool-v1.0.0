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
 * @returns {Promise<Object>} Generated report data
 */
export async function generateReport(options = {}) {
  const { format = 'json' } = options;

  try {
    const response = await fetch(`${API_BASE_URL}/report`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ format }),
    });

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
