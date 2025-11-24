import React, { useState, useEffect } from 'react';
import {
  getPlaybooks,
  getPlaybook,
  createRemediationPlan,
  estimateRemediationEffort,
  getHighRiskVulnerabilities,
  getScanHistory
} from '../api/client';

function RemediationWizard() {
  const [step, setStep] = useState(1); // 1: Select, 2: Plan, 3: Execute
  const [playbooks, setPlaybooks] = useState([]);
  const [vulnerabilities, setVulnerabilities] = useState([]);
  const [selectedVulns, setSelectedVulns] = useState([]);
  const [remediationPlan, setRemediationPlan] = useState(null);
  const [effortEstimate, setEffortEstimate] = useState(null);
  const [selectedPlaybook, setSelectedPlaybook] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    fetchInitialData();
  }, []);

  const fetchInitialData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [playbooksData, vulnsData] = await Promise.all([
        getPlaybooks(),
        getHighRiskVulnerabilities(20)
      ]);

      setPlaybooks(playbooksData.playbooks || []);
      setVulnerabilities(vulnsData.vulnerabilities || []);
    } catch (error) {
      console.error('Error fetching data:', error);
      setError('Failed to load remediation data. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const handleVulnToggle = (vuln) => {
    setSelectedVulns(prev => {
      const exists = prev.find(v => v.id === vuln.id);
      if (exists) {
        return prev.filter(v => v.id !== vuln.id);
      } else {
        return [...prev, vuln];
      }
    });
  };

  const handleCreatePlan = async () => {
    if (selectedVulns.length === 0) {
      setError('Please select at least one vulnerability to remediate.');
      return;
    }

    setLoading(true);
    setError(null);
    try {
      const [plan, estimate] = await Promise.all([
        createRemediationPlan(selectedVulns),
        estimateRemediationEffort(selectedVulns)
      ]);

      setRemediationPlan(plan.plan);
      setEffortEstimate(estimate.estimate);
      setStep(2);
    } catch (error) {
      console.error('Error creating plan:', error);
      setError('Failed to create remediation plan. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const handlePlaybookClick = async (playbookId) => {
    setLoading(true);
    try {
      const data = await getPlaybook(playbookId);
      setSelectedPlaybook(data.playbook);
    } catch (error) {
      console.error('Error fetching playbook:', error);
      setError('Failed to load playbook details.');
    } finally {
      setLoading(false);
    }
  };

  const getRiskColor = (score) => {
    if (score >= 9.0) return '#dc3545';
    if (score >= 7.0) return '#fd7e14';
    if (score >= 4.0) return '#ffc107';
    return '#28a745';
  };

  const getSeverityColor = (severity) => {
    const sev = severity?.toLowerCase() || 'low';
    if (sev === 'critical') return '#dc3545';
    if (sev === 'high') return '#fd7e14';
    if (sev === 'warning' || sev === 'medium') return '#ffc107';
    return '#28a745';
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
    stepIndicator: {
      display: 'flex',
      justifyContent: 'center',
      marginBottom: '30px',
      gap: '20px',
    },
    stepItem: {
      display: 'flex',
      alignItems: 'center',
      gap: '10px',
    },
    stepCircle: {
      width: '40px',
      height: '40px',
      borderRadius: '50%',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      fontSize: '18px',
      fontWeight: '600',
      backgroundColor: '#e9ecef',
      color: '#6c757d',
    },
    stepCircleActive: {
      backgroundColor: '#007bff',
      color: '#ffffff',
    },
    stepCircleCompleted: {
      backgroundColor: '#28a745',
      color: '#ffffff',
    },
    stepLabel: {
      fontSize: '14px',
      fontWeight: '500',
      color: '#6c757d',
    },
    card: {
      backgroundColor: '#ffffff',
      borderRadius: '8px',
      padding: '24px',
      boxShadow: '0 2px 8px rgba(0,0,0,0.1)',
      marginBottom: '20px',
    },
    cardTitle: {
      fontSize: '18px',
      fontWeight: '600',
      color: '#2c3e50',
      marginBottom: '20px',
      borderBottom: '2px solid #e9ecef',
      paddingBottom: '10px',
    },
    grid: {
      display: 'grid',
      gridTemplateColumns: 'repeat(auto-fill, minmax(300px, 1fr))',
      gap: '15px',
    },
    playbookCard: {
      padding: '15px',
      border: '2px solid #e9ecef',
      borderRadius: '8px',
      cursor: 'pointer',
      transition: 'all 0.2s',
    },
    playbookCardHover: {
      borderColor: '#007bff',
      boxShadow: '0 4px 12px rgba(0,123,255,0.15)',
    },
    playbookTitle: {
      fontSize: '16px',
      fontWeight: '600',
      color: '#2c3e50',
      marginBottom: '8px',
    },
    playbookCategory: {
      fontSize: '12px',
      color: '#007bff',
      fontWeight: '500',
      marginBottom: '8px',
    },
    playbookDescription: {
      fontSize: '13px',
      color: '#495057',
      marginBottom: '12px',
    },
    playbookMeta: {
      display: 'flex',
      gap: '12px',
      flexWrap: 'wrap',
      fontSize: '12px',
    },
    badge: {
      padding: '4px 8px',
      borderRadius: '4px',
      fontSize: '11px',
      fontWeight: '600',
    },
    vulnList: {
      listStyle: 'none',
      padding: 0,
      margin: 0,
    },
    vulnItem: {
      padding: '15px',
      borderBottom: '1px solid #e9ecef',
      display: 'flex',
      alignItems: 'center',
      gap: '15px',
      cursor: 'pointer',
      transition: 'background-color 0.2s',
    },
    vulnItemHover: {
      backgroundColor: '#f8f9fa',
    },
    checkbox: {
      width: '20px',
      height: '20px',
      cursor: 'pointer',
    },
    vulnContent: {
      flex: 1,
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
    vulnDescription: {
      fontSize: '13px',
      color: '#495057',
      marginBottom: '8px',
    },
    riskBadge: {
      padding: '4px 12px',
      borderRadius: '12px',
      fontSize: '12px',
      fontWeight: '600',
      color: '#ffffff',
    },
    phaseCard: {
      padding: '20px',
      border: '2px solid #e9ecef',
      borderRadius: '8px',
      marginBottom: '15px',
    },
    phaseHeader: {
      display: 'flex',
      justifyContent: 'space-between',
      alignItems: 'center',
      marginBottom: '15px',
    },
    phaseTitle: {
      fontSize: '18px',
      fontWeight: '600',
      color: '#2c3e50',
    },
    phasePriority: {
      padding: '6px 12px',
      borderRadius: '6px',
      fontSize: '12px',
      fontWeight: '600',
      textTransform: 'uppercase',
    },
    estimateCard: {
      display: 'grid',
      gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))',
      gap: '15px',
      padding: '20px',
      backgroundColor: '#f8f9fa',
      borderRadius: '8px',
      marginBottom: '20px',
    },
    estimateItem: {
      textAlign: 'center',
    },
    estimateValue: {
      fontSize: '24px',
      fontWeight: '700',
      color: '#007bff',
    },
    estimateLabel: {
      fontSize: '12px',
      color: '#6c757d',
      marginTop: '4px',
    },
    button: {
      padding: '12px 24px',
      borderRadius: '6px',
      border: 'none',
      fontSize: '14px',
      fontWeight: '600',
      cursor: 'pointer',
      transition: 'all 0.2s',
    },
    buttonPrimary: {
      backgroundColor: '#007bff',
      color: '#ffffff',
    },
    buttonSecondary: {
      backgroundColor: '#6c757d',
      color: '#ffffff',
    },
    buttonSuccess: {
      backgroundColor: '#28a745',
      color: '#ffffff',
    },
    buttonGroup: {
      display: 'flex',
      gap: '10px',
      justifyContent: 'flex-end',
      marginTop: '20px',
    },
    error: {
      padding: '15px',
      backgroundColor: '#f8d7da',
      color: '#721c24',
      borderRadius: '6px',
      marginBottom: '20px',
      border: '1px solid #f5c6cb',
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
    playbookDetail: {
      marginTop: '20px',
    },
    stepsList: {
      listStyle: 'none',
      padding: 0,
      margin: '20px 0',
    },
    stepListItem: {
      padding: '15px',
      backgroundColor: '#f8f9fa',
      borderRadius: '6px',
      marginBottom: '10px',
      borderLeft: '4px solid #007bff',
    },
    stepNumber: {
      fontSize: '14px',
      fontWeight: '700',
      color: '#007bff',
      marginBottom: '5px',
    },
    stepDescription: {
      fontSize: '14px',
      color: '#2c3e50',
      marginBottom: '8px',
    },
    stepType: {
      fontSize: '12px',
      color: '#6c757d',
      fontStyle: 'italic',
    },
  };

  const renderStepIndicator = () => (
    <div style={styles.stepIndicator}>
      <div style={styles.stepItem}>
        <div style={{
          ...styles.stepCircle,
          ...(step === 1 ? styles.stepCircleActive : step > 1 ? styles.stepCircleCompleted : {})
        }}>
          1
        </div>
        <span style={styles.stepLabel}>Select Vulnerabilities</span>
      </div>
      <div style={styles.stepItem}>
        <div style={{
          ...styles.stepCircle,
          ...(step === 2 ? styles.stepCircleActive : step > 2 ? styles.stepCircleCompleted : {})
        }}>
          2
        </div>
        <span style={styles.stepLabel}>Review Plan</span>
      </div>
      <div style={styles.stepItem}>
        <div style={{
          ...styles.stepCircle,
          ...(step === 3 ? styles.stepCircleActive : {})
        }}>
          3
        </div>
        <span style={styles.stepLabel}>Execute</span>
      </div>
    </div>
  );

  const renderStep1 = () => (
    <>
      <div style={styles.card}>
        <h3 style={styles.cardTitle}>Available Remediation Playbooks ({playbooks.length})</h3>
        {playbooks.length > 0 ? (
          <div style={styles.grid}>
            {playbooks.map((playbook) => (
              <div
                key={playbook.id}
                style={styles.playbookCard}
                onClick={() => handlePlaybookClick(playbook.id)}
                onMouseEnter={(e) => {
                  e.currentTarget.style.borderColor = '#007bff';
                  e.currentTarget.style.boxShadow = '0 4px 12px rgba(0,123,255,0.15)';
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.borderColor = '#e9ecef';
                  e.currentTarget.style.boxShadow = 'none';
                }}
              >
                <div style={styles.playbookCategory}>{playbook.category}</div>
                <div style={styles.playbookTitle}>{playbook.name}</div>
                <div style={styles.playbookDescription}>{playbook.description}</div>
                <div style={styles.playbookMeta}>
                  <span style={{...styles.badge, backgroundColor: getSeverityColor(playbook.severity)}}>
                    {playbook.severity}
                  </span>
                  <span style={{...styles.badge, backgroundColor: '#17a2b8', color: '#fff'}}>
                    {playbook.estimated_time}
                  </span>
                  <span style={{...styles.badge, backgroundColor: '#6c757d', color: '#fff'}}>
                    Risk: {playbook.risk_level}
                  </span>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div style={styles.emptyState}>No playbooks available</div>
        )}
      </div>

      {selectedPlaybook && (
        <div style={styles.card}>
          <h3 style={styles.cardTitle}>{selectedPlaybook.name}</h3>
          <div style={styles.playbookDetail}>
            <p><strong>Category:</strong> {selectedPlaybook.category}</p>
            <p><strong>Description:</strong> {selectedPlaybook.description}</p>
            <p><strong>Estimated Time:</strong> {selectedPlaybook.estimated_time}</p>
            <p><strong>Risk Level:</strong> {selectedPlaybook.risk_level}</p>

            <h4 style={{marginTop: '20px', marginBottom: '10px'}}>Remediation Steps:</h4>
            <ul style={styles.stepsList}>
              {selectedPlaybook.steps?.map((step) => (
                <li key={step.id} style={styles.stepListItem}>
                  <div style={styles.stepNumber}>Step {step.id}</div>
                  <div style={styles.stepDescription}>{step.description}</div>
                  <div style={styles.stepType}>Type: {step.type}</div>
                </li>
              ))}
            </ul>

            {selectedPlaybook.success_criteria && (
              <>
                <h4 style={{marginTop: '20px', marginBottom: '10px'}}>Success Criteria:</h4>
                <ul>
                  {selectedPlaybook.success_criteria.map((criteria, idx) => (
                    <li key={idx}>{criteria}</li>
                  ))}
                </ul>
              </>
            )}
          </div>
        </div>
      )}

      <div style={styles.card}>
        <h3 style={styles.cardTitle}>
          Select Vulnerabilities to Remediate ({selectedVulns.length} selected)
        </h3>
        {vulnerabilities.length > 0 ? (
          <ul style={styles.vulnList}>
            {vulnerabilities.map((vuln) => (
              <li
                key={vuln.id}
                style={styles.vulnItem}
                onClick={() => handleVulnToggle(vuln)}
                onMouseEnter={(e) => e.currentTarget.style.backgroundColor = '#f8f9fa'}
                onMouseLeave={(e) => e.currentTarget.style.backgroundColor = 'transparent'}
              >
                <input
                  type="checkbox"
                  style={styles.checkbox}
                  checked={selectedVulns.some(v => v.id === vuln.id)}
                  onChange={() => {}}
                />
                <div style={styles.vulnContent}>
                  <div style={styles.vulnHeader}>
                    <span style={styles.vulnCategory}>{vuln.category}</span>
                    <span style={{
                      ...styles.riskBadge,
                      backgroundColor: getRiskColor(vuln.risk_score || 0)
                    }}>
                      {vuln.risk_score?.toFixed(1)} - {vuln.risk_level}
                    </span>
                  </div>
                  <div style={styles.vulnDescription}>{vuln.description}</div>
                </div>
              </li>
            ))}
          </ul>
        ) : (
          <div style={styles.emptyState}>No vulnerabilities found. Run a security scan first.</div>
        )}

        <div style={styles.buttonGroup}>
          <button
            style={{...styles.button, ...styles.buttonPrimary}}
            onClick={handleCreatePlan}
            disabled={selectedVulns.length === 0}
          >
            Create Remediation Plan →
          </button>
        </div>
      </div>
    </>
  );

  const renderStep2 = () => (
    <>
      {effortEstimate && (
        <div style={styles.card}>
          <h3 style={styles.cardTitle}>Remediation Effort Estimate</h3>
          <div style={styles.estimateCard}>
            <div style={styles.estimateItem}>
              <div style={styles.estimateValue}>{effortEstimate.total_vulnerabilities}</div>
              <div style={styles.estimateLabel}>Total Vulnerabilities</div>
            </div>
            <div style={styles.estimateItem}>
              <div style={styles.estimateValue}>{effortEstimate.remediable_count}</div>
              <div style={styles.estimateLabel}>Remediable</div>
            </div>
            <div style={styles.estimateItem}>
              <div style={styles.estimateValue}>{effortEstimate.estimated_time_human}</div>
              <div style={styles.estimateLabel}>Estimated Time</div>
            </div>
            <div style={styles.estimateItem}>
              <div style={styles.estimateValue}>{effortEstimate.requires_restart ? 'Yes' : 'No'}</div>
              <div style={styles.estimateLabel}>Requires Restart</div>
            </div>
          </div>
        </div>
      )}

      {remediationPlan && (
        <div style={styles.card}>
          <h3 style={styles.cardTitle}>Phased Remediation Plan</h3>
          {remediationPlan.phases?.map((phase) => (
            <div key={phase.phase} style={styles.phaseCard}>
              <div style={styles.phaseHeader}>
                <div style={styles.phaseTitle}>
                  Phase {phase.phase}: {phase.name}
                </div>
                <div style={{
                  ...styles.phasePriority,
                  backgroundColor: phase.priority === 'immediate' ? '#dc3545' :
                                 phase.priority === 'urgent' ? '#fd7e14' :
                                 phase.priority === 'scheduled' ? '#ffc107' : '#6c757d',
                  color: '#ffffff'
                }}>
                  {phase.priority}
                </div>
              </div>
              <p><strong>Vulnerabilities:</strong> {phase.vulnerabilities?.length || 0}</p>
              <p><strong>Playbooks available:</strong> {phase.playbooks?.length || 0}</p>
              {phase.playbooks && phase.playbooks.length > 0 && (
                <div style={{marginTop: '10px'}}>
                  <strong>Recommended playbooks:</strong>
                  <ul>
                    {phase.playbooks.map((pb, idx) => pb && (
                      <li key={idx}>{pb.name} ({pb.estimated_time})</li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          ))}

          <div style={styles.buttonGroup}>
            <button
              style={{...styles.button, ...styles.buttonSecondary}}
              onClick={() => setStep(1)}
            >
              ← Back
            </button>
            <button
              style={{...styles.button, ...styles.buttonSuccess}}
              onClick={() => setStep(3)}
            >
              Start Execution →
            </button>
          </div>
        </div>
      )}
    </>
  );

  const renderStep3 = () => (
    <div style={styles.card}>
      <h3 style={styles.cardTitle}>Execute Remediation</h3>
      <div style={{textAlign: 'center', padding: '40px'}}>
        <p style={{fontSize: '18px', color: '#2c3e50', marginBottom: '20px'}}>
          Playbook execution feature coming soon!
        </p>
        <p style={{color: '#6c757d'}}>
          This will allow you to execute remediation playbooks step-by-step with real-time validation and rollback capabilities.
        </p>
        <div style={styles.buttonGroup}>
          <button
            style={{...styles.button, ...styles.buttonSecondary}}
            onClick={() => setStep(2)}
          >
            ← Back to Plan
          </button>
          <button
            style={{...styles.button, ...styles.buttonPrimary}}
            onClick={() => {
              setStep(1);
              setSelectedVulns([]);
              setRemediationPlan(null);
              setEffortEstimate(null);
            }}
          >
            Start New Remediation
          </button>
        </div>
      </div>
    </div>
  );

  if (loading && !playbooks.length) {
    return (
      <div style={styles.container}>
        <div style={styles.loading}>Loading remediation wizard...</div>
      </div>
    );
  }

  return (
    <div style={styles.container}>
      <div style={styles.header}>
        <h1 style={styles.title}>Guided Remediation Wizard</h1>
        <p style={styles.subtitle}>Step-by-step vulnerability remediation with automated playbooks</p>
      </div>

      {error && (
        <div style={styles.error}>
          {error}
        </div>
      )}

      {renderStepIndicator()}

      {step === 1 && renderStep1()}
      {step === 2 && renderStep2()}
      {step === 3 && renderStep3()}
    </div>
  );
}

export default RemediationWizard;
