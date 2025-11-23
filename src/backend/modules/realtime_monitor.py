#!/usr/bin/env python3
"""
Real-time Monitoring Module
Provides live security status updates and system health metrics
"""

import psutil
import logging
import time
import threading
from datetime import datetime
from typing import Dict, Any, List, Optional, Callable
from collections import deque

logger = logging.getLogger(__name__)


class RealtimeMonitor:
    """
    Real-time system monitoring with threat detection and health metrics.
    """

    def __init__(self):
        """Initialize the real-time monitor."""
        self.monitoring = False
        self.monitor_thread = None
        self.alert_callbacks = []
        self.metrics_history = deque(maxlen=100)  # Store last 100 metrics
        self.threat_threshold = {
            'cpu_percent': 90,
            'memory_percent': 85,
            'disk_percent': 90,
            'failed_logins': 5,
            'open_ports': 100
        }
        logger.info("RealtimeMonitor initialized")

    def register_alert_callback(self, callback: Callable):
        """
        Register a callback function for alerts.

        Args:
            callback: Function to call when alert is triggered
        """
        self.alert_callbacks.append(callback)
        logger.info(f"Alert callback registered: {callback.__name__}")

    def start_monitoring(self, interval: int = 5):
        """
        Start continuous monitoring.

        Args:
            interval: Monitoring interval in seconds
        """
        if self.monitoring:
            logger.warning("Monitoring already running")
            return

        self.monitoring = True
        self.monitor_thread = threading.Thread(
            target=self._monitor_loop,
            args=(interval,),
            daemon=True
        )
        self.monitor_thread.start()
        logger.info(f"Real-time monitoring started (interval: {interval}s)")

    def stop_monitoring(self):
        """Stop continuous monitoring."""
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=2)
        logger.info("Real-time monitoring stopped")

    def _monitor_loop(self, interval: int):
        """
        Main monitoring loop.

        Args:
            interval: Sleep interval between checks
        """
        while self.monitoring:
            try:
                metrics = self.get_current_metrics()
                self.metrics_history.append(metrics)

                # Check for threats
                threats = self._detect_threats(metrics)
                if threats:
                    self._trigger_alerts(threats)

            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}", exc_info=True)

            time.sleep(interval)

    def get_current_metrics(self) -> Dict[str, Any]:
        """
        Get current system health metrics.

        Returns:
            Dictionary with current system metrics
        """
        try:
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            network = psutil.net_io_counters()

            # Get process count
            process_count = len(psutil.pids())

            # Get network connections
            try:
                connections = psutil.net_connections(kind='inet')
                open_ports = len([c for c in connections if c.status == 'LISTEN'])
            except (psutil.AccessDenied, PermissionError):
                open_ports = 0

            metrics = {
                'timestamp': datetime.now().isoformat(),
                'cpu': {
                    'percent': cpu_percent,
                    'count': psutil.cpu_count(),
                    'status': 'critical' if cpu_percent > 90 else 'warning' if cpu_percent > 75 else 'normal'
                },
                'memory': {
                    'total': memory.total,
                    'available': memory.available,
                    'percent': memory.percent,
                    'used': memory.used,
                    'status': 'critical' if memory.percent > 90 else 'warning' if memory.percent > 75 else 'normal'
                },
                'disk': {
                    'total': disk.total,
                    'used': disk.used,
                    'free': disk.free,
                    'percent': disk.percent,
                    'status': 'critical' if disk.percent > 90 else 'warning' if disk.percent > 80 else 'normal'
                },
                'network': {
                    'bytes_sent': network.bytes_sent,
                    'bytes_recv': network.bytes_recv,
                    'packets_sent': network.packets_sent,
                    'packets_recv': network.packets_recv,
                    'errors': network.errin + network.errout,
                    'drops': network.dropin + network.dropout
                },
                'processes': {
                    'count': process_count,
                    'open_ports': open_ports
                },
                'uptime': self._get_uptime()
            }

            return metrics

        except Exception as e:
            logger.error(f"Error getting metrics: {e}", exc_info=True)
            return {'error': str(e), 'timestamp': datetime.now().isoformat()}

    def _get_uptime(self) -> Dict[str, Any]:
        """
        Get system uptime.

        Returns:
            Dictionary with uptime information
        """
        try:
            boot_time = psutil.boot_time()
            uptime_seconds = time.time() - boot_time

            days = int(uptime_seconds // 86400)
            hours = int((uptime_seconds % 86400) // 3600)
            minutes = int((uptime_seconds % 3600) // 60)

            return {
                'seconds': int(uptime_seconds),
                'formatted': f"{days}d {hours}h {minutes}m",
                'boot_time': datetime.fromtimestamp(boot_time).isoformat()
            }
        except Exception as e:
            logger.error(f"Error getting uptime: {e}")
            return {'error': str(e)}

    def _detect_threats(self, metrics: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Detect potential threats based on metrics.

        Args:
            metrics: Current system metrics

        Returns:
            List of detected threats
        """
        threats = []

        try:
            # Check CPU usage
            if metrics['cpu']['percent'] > self.threat_threshold['cpu_percent']:
                threats.append({
                    'type': 'high_cpu_usage',
                    'severity': 'high',
                    'message': f"CPU usage at {metrics['cpu']['percent']}%",
                    'timestamp': metrics['timestamp'],
                    'metric': 'cpu',
                    'value': metrics['cpu']['percent']
                })

            # Check memory usage
            if metrics['memory']['percent'] > self.threat_threshold['memory_percent']:
                threats.append({
                    'type': 'high_memory_usage',
                    'severity': 'high',
                    'message': f"Memory usage at {metrics['memory']['percent']}%",
                    'timestamp': metrics['timestamp'],
                    'metric': 'memory',
                    'value': metrics['memory']['percent']
                })

            # Check disk usage
            if metrics['disk']['percent'] > self.threat_threshold['disk_percent']:
                threats.append({
                    'type': 'high_disk_usage',
                    'severity': 'critical',
                    'message': f"Disk usage at {metrics['disk']['percent']}%",
                    'timestamp': metrics['timestamp'],
                    'metric': 'disk',
                    'value': metrics['disk']['percent']
                })

            # Check for excessive open ports
            if metrics['processes']['open_ports'] > self.threat_threshold['open_ports']:
                threats.append({
                    'type': 'excessive_open_ports',
                    'severity': 'medium',
                    'message': f"{metrics['processes']['open_ports']} open ports detected",
                    'timestamp': metrics['timestamp'],
                    'metric': 'open_ports',
                    'value': metrics['processes']['open_ports']
                })

            # Check network errors
            if metrics['network']['errors'] > 100:
                threats.append({
                    'type': 'network_errors',
                    'severity': 'medium',
                    'message': f"{metrics['network']['errors']} network errors detected",
                    'timestamp': metrics['timestamp'],
                    'metric': 'network_errors',
                    'value': metrics['network']['errors']
                })

        except Exception as e:
            logger.error(f"Error detecting threats: {e}", exc_info=True)

        return threats

    def _trigger_alerts(self, threats: List[Dict[str, Any]]):
        """
        Trigger alerts for detected threats.

        Args:
            threats: List of detected threats
        """
        for threat in threats:
            logger.warning(f"Threat detected: {threat['type']} - {threat['message']}")

            # Call registered callbacks
            for callback in self.alert_callbacks:
                try:
                    callback(threat)
                except Exception as e:
                    logger.error(f"Error in alert callback: {e}", exc_info=True)

    def get_metrics_history(self, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """
        Get historical metrics.

        Args:
            limit: Maximum number of metrics to return

        Returns:
            List of historical metrics
        """
        history = list(self.metrics_history)
        if limit:
            history = history[-limit:]
        return history

    def get_system_status(self) -> Dict[str, Any]:
        """
        Get overall system status.

        Returns:
            Dictionary with system status
        """
        current = self.get_current_metrics()

        # Determine overall status
        statuses = [
            current.get('cpu', {}).get('status', 'unknown'),
            current.get('memory', {}).get('status', 'unknown'),
            current.get('disk', {}).get('status', 'unknown')
        ]

        if 'critical' in statuses:
            overall_status = 'critical'
        elif 'warning' in statuses:
            overall_status = 'warning'
        else:
            overall_status = 'healthy'

        return {
            'status': overall_status,
            'monitoring': self.monitoring,
            'metrics': current,
            'timestamp': datetime.now().isoformat()
        }

    def set_threshold(self, metric: str, value: float):
        """
        Set custom threshold for threat detection.

        Args:
            metric: Metric name (cpu_percent, memory_percent, etc.)
            value: Threshold value
        """
        if metric in self.threat_threshold:
            self.threat_threshold[metric] = value
            logger.info(f"Threshold updated: {metric} = {value}")
        else:
            logger.warning(f"Unknown threshold metric: {metric}")


# Example usage
if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    print("=" * 70)
    print("Real-time System Monitor - Test")
    print("=" * 70)

    monitor = RealtimeMonitor()

    # Define alert callback
    def alert_handler(threat):
        print(f"\n🚨 ALERT: {threat['message']}")
        print(f"   Severity: {threat['severity']}")
        print(f"   Type: {threat['type']}")

    monitor.register_alert_callback(alert_handler)

    # Get current metrics
    print("\n📊 Current System Metrics:")
    metrics = monitor.get_current_metrics()
    print(f"   CPU: {metrics['cpu']['percent']}% ({metrics['cpu']['status']})")
    print(f"   Memory: {metrics['memory']['percent']}% ({metrics['memory']['status']})")
    print(f"   Disk: {metrics['disk']['percent']}% ({metrics['disk']['status']})")
    print(f"   Open Ports: {metrics['processes']['open_ports']}")
    print(f"   Uptime: {metrics['uptime']['formatted']}")

    # Get overall status
    print("\n🔍 System Status:")
    status = monitor.get_system_status()
    print(f"   Overall: {status['status'].upper()}")
    print(f"   Monitoring: {'Active' if status['monitoring'] else 'Inactive'}")

    print("\n" + "=" * 70)
    print("✓ Real-time monitor test complete")
    print("=" * 70)
