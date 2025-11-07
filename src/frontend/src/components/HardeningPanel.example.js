/**
 * Example Usage of HardeningPanel Component
 *
 * This file demonstrates how to use the HardeningPanel component
 * in your React application.
 */

import React, { useState } from 'react';
import HardeningPanel from './HardeningPanel';

function HardeningExample() {
  // Example hardening rules
  const [selectedRules] = useState([
    {
      id: 'ssh_root_login',
      name: 'Disable Root Login',
      description: 'Root login via SSH should be disabled for security',
      severity: 'critical',
      parameter: 'PermitRootLogin',
      expected_value: 'no',
      file: '/etc/ssh/sshd_config'
    },
    {
      id: 'ssh_password_auth',
      name: 'Disable Password Authentication',
      description: 'Password authentication should be disabled in favor of key-based authentication',
      severity: 'high',
      parameter: 'PasswordAuthentication',
      expected_value: 'no',
      file: '/etc/ssh/sshd_config'
    },
    {
      id: 'pass_max_days',
      name: 'Set Password Maximum Age',
      description: 'Maximum password age should be limited to 90 days',
      severity: 'medium',
      parameter: 'PASS_MAX_DAYS',
      expected_value: '90',
      file: '/etc/login.defs'
    },
    {
      id: 'ssh_x11_forwarding',
      name: 'Disable X11 Forwarding',
      description: 'X11 forwarding should be disabled unless specifically required',
      severity: 'medium',
      parameter: 'X11Forwarding',
      expected_value: 'no',
      file: '/etc/ssh/sshd_config'
    }
  ]);

  const handleComplete = (result) => {
    console.log('Hardening completed:', result);
    // Handle completion - maybe navigate to results page or show summary
  };

  return (
    <div className="app-container">
      <h1>System Hardening</h1>
      <HardeningPanel
        selectedRules={selectedRules}
        onComplete={handleComplete}
      />
    </div>
  );
}

export default HardeningExample;

/**
 * INTEGRATION NOTES:
 *
 * 1. Props:
 *    - selectedRules: Array of rule objects to apply
 *    - onComplete: Callback function when hardening completes
 *
 * 2. Rule Object Structure:
 *    {
 *      id: string,              // Unique rule identifier
 *      name: string,            // Display name
 *      description: string,     // Rule description
 *      severity: string,        // 'critical', 'high', 'medium', 'low'
 *      parameter: string,       // Configuration parameter name
 *      expected_value: string,  // Expected value for the parameter
 *      file: string            // Target configuration file
 *    }
 *
 * 3. Backend API Requirements:
 *    - POST /api/harden - Apply hardening rules
 *      Request: { rules: ['rule_id1', 'rule_id2'] }
 *      Response: { session: { ... }, checkpoint_id: '...' }
 *
 *    - POST /api/rollback - Rollback to checkpoint
 *      Request: { checkpoint_id: '...' }
 *      Response: { success: true, message: '...' }
 *
 *    - GET /api/checkpoints - Get available checkpoints
 *      Response: [{ checkpoint_id: '...', timestamp: '...', ... }]
 *
 * 4. State Management:
 *    The component manages its own internal state for:
 *    - Hardening status (idle, running, success, error)
 *    - Individual rule statuses
 *    - Progress tracking
 *    - Error handling
 *    - Rollback confirmation
 *
 * 5. Features:
 *    ✓ Real-time progress bar
 *    ✓ Individual rule status tracking
 *    ✓ Before/after value display
 *    ✓ Error handling with detailed messages
 *    ✓ Rollback functionality with confirmation
 *    ✓ Responsive design
 *    ✓ Severity-based styling
 *    ✓ Duration tracking
 *    ✓ Warning messages display
 */
