#!/usr/bin/env python3
"""
System Hardening Tool - Backend API
Main Flask application with REST API endpoints for system security hardening.
"""

import os
import logging
from datetime import datetime
from flask import Flask, jsonify, request
from flask_cors import CORS
from dotenv import load_dotenv
import psutil
import platform

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)

# Configure CORS
CORS(app, resources={
    r"/api/*": {
        "origins": os.getenv("ALLOWED_ORIGINS", "*"),
        "methods": ["GET", "POST", "PUT", "DELETE"],
        "allow_headers": ["Content-Type", "Authorization"]
    }
})

# Configure logging
log_dir = os.path.join(os.path.dirname(__file__), '..', '..', 'logs')
os.makedirs(log_dir, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(log_dir, 'app.log')),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

# Configuration
app.config['DEBUG'] = os.getenv('DEBUG', 'False').lower() == 'true'
app.config['PORT'] = int(os.getenv('PORT', 5000))


# ========================
# Utility Functions
# ========================

def get_system_info():
    """Gather system information using psutil."""
    try:
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')

        return {
            "platform": platform.system(),
            "platform_release": platform.release(),
            "platform_version": platform.version(),
            "architecture": platform.machine(),
            "hostname": platform.node(),
            "processor": platform.processor(),
            "cpu_count": psutil.cpu_count(),
            "cpu_percent": cpu_percent,
            "memory_total": memory.total,
            "memory_available": memory.available,
            "memory_percent": memory.percent,
            "disk_total": disk.total,
            "disk_used": disk.used,
            "disk_percent": disk.percent,
            "boot_time": datetime.fromtimestamp(psutil.boot_time()).isoformat()
        }
    except Exception as e:
        logger.error(f"Error gathering system info: {str(e)}")
        raise


# ========================
# API Routes
# ========================

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint to verify API is running."""
    logger.info("Health check requested")
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "service": "System Hardening Tool API",
        "version": "1.0.0"
    }), 200


@app.route('/api/system-info', methods=['GET'])
def system_info():
    """Get current system information."""
    logger.info("System info requested")
    try:
        info = get_system_info()
        return jsonify({
            "status": "success",
            "data": info,
            "timestamp": datetime.now().isoformat()
        }), 200
    except Exception as e:
        logger.error(f"Failed to retrieve system info: {str(e)}")
        return jsonify({
            "status": "error",
            "message": "Failed to retrieve system information",
            "error": str(e)
        }), 500


@app.route('/api/scan', methods=['POST'])
def scan_system():
    """
    Scan system for security vulnerabilities and misconfigurations.
    Expects JSON body with scan options.
    """
    logger.info("Security scan requested")
    try:
        # Use force=True and silent=True to handle JSON parsing more gracefully
        data = request.get_json(force=True, silent=True) or {}
        scan_type = data.get('type', 'full')

        # Mock scan results with realistic data
        scan_results = {
            "scan_id": f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            "scan_type": scan_type,
            "timestamp": datetime.now().isoformat(),
            "status": "completed",
            "totalVulnerabilities": 3,
            "complianceScore": 78,
            "criticalIssues": 1,
            "warnings": 2,
            "findings": [
                {
                    "id": 1,
                    "category": "Network Security",
                    "severity": "Critical",
                    "description": "SSH service allows password authentication",
                    "status": "Open",
                    "timestamp": datetime.now().isoformat(),
                    "recommendation": "Disable password authentication and use key-based authentication"
                },
                {
                    "id": 2,
                    "category": "File System",
                    "severity": "Warning",
                    "description": "World-writable files detected in /tmp",
                    "status": "Open",
                    "timestamp": datetime.now().isoformat(),
                    "recommendation": "Review and restrict permissions on temporary files"
                },
                {
                    "id": 3,
                    "category": "System Updates",
                    "severity": "Medium",
                    "description": "System packages require updates",
                    "status": "Open",
                    "timestamp": datetime.now().isoformat(),
                    "recommendation": "Run system update to patch security vulnerabilities"
                }
            ]
        }

        logger.info(f"Scan completed: {scan_results['scan_id']}")
        return jsonify(scan_results), 200

    except Exception as e:
        logger.error(f"Scan failed: {str(e)}")
        return jsonify({
            "status": "error",
            "message": "Security scan failed",
            "error": str(e)
        }), 500


@app.route('/api/harden', methods=['POST'])
def harden_system():
    """
    Apply security hardening configurations to the system.
    Expects JSON body with hardening options and policies.
    """
    logger.info("Hardening request received")
    try:
        data = request.get_json(force=True, silent=True) or {}
        policy = data.get('policy', 'default')
        dry_run = data.get('dry_run', True)
        rules = data.get('rules', [])

        if not dry_run:
            logger.warning("Live hardening requested - requires elevated privileges")

        # Mock hardening results
        hardening_results = {
            "operation_id": f"harden_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            "policy": policy,
            "dry_run": dry_run,
            "timestamp": datetime.now().isoformat(),
            "status": "completed",
            "changes_applied": len(rules) if rules else 3,
            "changes": [
                {
                    "id": 1,
                    "category": "Network Security",
                    "action": "Disabled SSH password authentication",
                    "status": "applied"
                },
                {
                    "id": 2,
                    "category": "File System",
                    "action": "Fixed file permissions on /tmp",
                    "status": "applied"
                },
                {
                    "id": 3,
                    "category": "System Updates",
                    "action": "Initiated system package updates",
                    "status": "applied"
                }
            ]
        }

        logger.info(f"Hardening operation completed: {hardening_results['operation_id']}")
        return jsonify(hardening_results), 200

    except Exception as e:
        logger.error(f"Hardening failed: {str(e)}")
        return jsonify({
            "status": "error",
            "message": "Hardening operation failed",
            "error": str(e)
        }), 500


@app.route('/api/report', methods=['POST'])
def generate_security_report():
    """
    Generate a security report in the specified format.
    Expects JSON body with report options.
    """
    logger.info("Report generation requested")
    try:
        data = request.get_json(force=True, silent=True) or {}
        report_format = data.get('format', 'json')

        # Mock report generation
        report_data = {
            "report_id": f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            "format": report_format,
            "timestamp": datetime.now().isoformat(),
            "status": "generated",
            "summary": {
                "total_vulnerabilities": 3,
                "critical": 1,
                "high": 0,
                "medium": 1,
                "low": 1,
                "compliance_score": 78
            },
            "message": f"PDF report would be generated here. Format: {report_format}",
            "note": "Full PDF generation to be implemented with reportlab or similar library"
        }

        logger.info(f"Report generated: {report_data['report_id']}")
        return jsonify(report_data), 200

    except Exception as e:
        logger.error(f"Report generation failed: {str(e)}")
        return jsonify({
            "status": "error",
            "message": "Report generation failed",
            "error": str(e)
        }), 500


# ========================
# Error Handlers
# ========================

@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors."""
    logger.warning(f"404 error: {request.url}")
    return jsonify({
        "status": "error",
        "message": "Resource not found",
        "path": request.path
    }), 404


@app.errorhandler(405)
def method_not_allowed(error):
    """Handle 405 errors."""
    logger.warning(f"405 error: {request.method} {request.url}")
    return jsonify({
        "status": "error",
        "message": "Method not allowed",
        "method": request.method,
        "path": request.path
    }), 405


@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors."""
    logger.error(f"500 error: {str(error)}")
    return jsonify({
        "status": "error",
        "message": "Internal server error",
        "error": str(error)
    }), 500


@app.errorhandler(Exception)
def handle_exception(error):
    """Handle uncaught exceptions."""
    logger.error(f"Unhandled exception: {str(error)}", exc_info=True)
    return jsonify({
        "status": "error",
        "message": "An unexpected error occurred",
        "error": str(error)
    }), 500


# ========================
# Application Entry Point
# ========================

if __name__ == '__main__':
    logger.info("Starting System Hardening Tool API...")
    logger.info(f"Debug mode: {app.config['DEBUG']}")
    logger.info(f"Port: {app.config['PORT']}")

    app.run(
        host='0.0.0.0',
        port=app.config['PORT'],
        debug=app.config['DEBUG']
    )
