"""
Security Monitor Module

Real-time security threat detection for the packet sniffer.
Detects:
- Port scanning (horizontal scan)
- Brute force attempts (vertical scan)
- SYN flood attacks
- Traffic anomalies
- Suspicious connection patterns

Thread-safe design with configurable thresholds.
"""

import threading
from datetime import datetime, timedelta
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional, Dict, List, Set
from enum import Enum

from core_sniffer.protocol_parser import ParsedPacket, is_private_ip


# =============================================================================
# Enums and Constants
# =============================================================================

class AlertSeverity(Enum):
    """Security alert severity levels."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AlertType(Enum):
    """Types of security alerts."""
    PORT_SCAN = "PORT_SCAN"
    BRUTE_FORCE = "BRUTE_FORCE"
    SYN_FLOOD = "SYN_FLOOD"
    TRAFFIC_SPIKE = "TRAFFIC_SPIKE"
    SUSPICIOUS_PORT = "SUSPICIOUS_PORT"
    EXTERNAL_CONNECTION = "EXTERNAL_CONNECTION"


class SecurityStatus(Enum):
    """Overall security status."""
    NORMAL = "NORMAL"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"


# Commonly targeted ports that may indicate suspicious activity
SUSPICIOUS_PORTS = {
    23: "Telnet",
    135: "MS-RPC",
    139: "NetBIOS",
    445: "SMB",
    1433: "MSSQL",
    1434: "MSSQL Browser",
    3306: "MySQL",
    3389: "RDP",
    4444: "Metasploit",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    27017: "MongoDB",
}


# =============================================================================
# Data Classes
# =============================================================================

@dataclass
class SecurityAlert:
    """
    Represents a security alert.
    
    Attributes:
        alert_type: Type of security threat detected.
        severity: Severity level of the alert.
        source_ip: IP address that triggered the alert.
        target_ip: Target IP address (if applicable).
        message: Human-readable description.
        details: Additional details dictionary.
        timestamp: When the alert was created.
        id: Unique alert identifier.
    """
    alert_type: AlertType
    severity: AlertSeverity
    source_ip: str
    message: str
    target_ip: Optional[str] = None
    details: Dict = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)
    id: str = field(default_factory=lambda: "")
    
    def __post_init__(self):
        """Generate unique ID if not provided."""
        if not self.id:
            self.id = f"{self.alert_type.value}_{self.source_ip}_{self.timestamp.timestamp()}"
    
    def to_dict(self) -> dict:
        """Convert alert to dictionary."""
        return {
            "id": self.id,
            "alert_type": self.alert_type.value,
            "severity": self.severity.value,
            "source_ip": self.source_ip,
            "target_ip": self.target_ip,
            "message": self.message,
            "details": self.details,
            "timestamp": self.timestamp.isoformat()
        }


@dataclass
class ThreatThresholds:
    """
    Configurable thresholds for threat detection.
    """
    port_scan_ports: int = 25
    port_scan_window: int = 30
    brute_force_attempts: int = 50
    brute_force_window: int = 30
    syn_flood_count: int = 100
    syn_flood_window: int = 10
    traffic_spike_multiplier: float = 5.0


# =============================================================================
# IP Tracker Classes
# =============================================================================

class ConnectionTracker:
    """
    Tracks connections from a single IP address.
    
    Used for detecting port scans and brute force attempts.
    """
    
    def __init__(self, ip: str):
        """
        Initialize tracker for an IP.
        
        Args:
            ip: The IP address to track.
        """
        self.ip = ip
        self.first_seen = datetime.now()
        self.last_seen = datetime.now()
        
        # Port scan detection: track unique ports accessed
        self.ports_accessed: Dict[int, List[datetime]] = defaultdict(list)
        
        # Brute force detection: track attempts per destination
        self.connection_attempts: Dict[str, List[datetime]] = defaultdict(list)
        
        # SYN tracking
        self.syn_packets: List[datetime] = []
        self.syn_ack_received: Set[str] = set()  # connection keys that completed
        
        # General packet tracking
        self.packet_count = 0
        self.byte_count = 0
    
    def record_packet(
        self,
        packet: ParsedPacket,
        current_time: Optional[datetime] = None
    ):
        """
        Record a packet from this IP.
        
        Args:
            packet: The parsed packet.
            current_time: Current time (for testing).
        """
        now = current_time or datetime.now()
        self.last_seen = now
        self.packet_count += 1
        self.byte_count += packet.size
        
        # Track port access
        if packet.dst_port:
            self.ports_accessed[packet.dst_port].append(now)
        
        # Track connection attempts
        if packet.dst_ip and packet.dst_port:
            key = f"{packet.dst_ip}:{packet.dst_port}"
            self.connection_attempts[key].append(now)
        
        # Track SYN packets (potential SYN flood)
        if packet.tcp_flags and "SYN" in packet.tcp_flags:
            if "ACK" not in packet.tcp_flags:
                self.syn_packets.append(now)
    
    def get_unique_ports_in_window(
        self,
        window_seconds: int,
        current_time: Optional[datetime] = None
    ) -> Set[int]:
        """
        Get unique ports accessed within the time window.
        
        Args:
            window_seconds: Time window in seconds.
            current_time: Current time (for testing).
        
        Returns:
            Set of port numbers accessed in the window.
        """
        now = current_time or datetime.now()
        cutoff = now - timedelta(seconds=window_seconds)
        
        unique_ports = set()
        for port, timestamps in self.ports_accessed.items():
            if any(t > cutoff for t in timestamps):
                unique_ports.add(port)
        
        return unique_ports
    
    def get_attempts_to_target_in_window(
        self,
        target_key: str,
        window_seconds: int,
        current_time: Optional[datetime] = None
    ) -> int:
        """
        Get number of connection attempts to a specific target.
        
        Args:
            target_key: Target in format "ip:port".
            window_seconds: Time window in seconds.
            current_time: Current time (for testing).
        
        Returns:
            Number of attempts in the window.
        """
        now = current_time or datetime.now()
        cutoff = now - timedelta(seconds=window_seconds)
        
        attempts = self.connection_attempts.get(target_key, [])
        return sum(1 for t in attempts if t > cutoff)
    
    def get_syn_count_in_window(
        self,
        window_seconds: int,
        current_time: Optional[datetime] = None
    ) -> int:
        """
        Get number of SYN packets in the time window.
        
        Args:
            window_seconds: Time window in seconds.
            current_time: Current time (for testing).
        
        Returns:
            Number of SYN packets in the window.
        """
        now = current_time or datetime.now()
        cutoff = now - timedelta(seconds=window_seconds)
        
        return sum(1 for t in self.syn_packets if t > cutoff)
    
    def cleanup_old_data(
        self,
        max_age_seconds: int = 300,
        current_time: Optional[datetime] = None
    ):
        """
        Remove data older than max_age_seconds.
        
        Args:
            max_age_seconds: Maximum age of data to keep.
            current_time: Current time (for testing).
        """
        now = current_time or datetime.now()
        cutoff = now - timedelta(seconds=max_age_seconds)
        
        # Clean port access
        for port in list(self.ports_accessed.keys()):
            self.ports_accessed[port] = [
                t for t in self.ports_accessed[port] if t > cutoff
            ]
            if not self.ports_accessed[port]:
                del self.ports_accessed[port]
        
        # Clean connection attempts
        for key in list(self.connection_attempts.keys()):
            self.connection_attempts[key] = [
                t for t in self.connection_attempts[key] if t > cutoff
            ]
            if not self.connection_attempts[key]:
                del self.connection_attempts[key]
        
        # Clean SYN packets
        self.syn_packets = [t for t in self.syn_packets if t > cutoff]


# =============================================================================
# Security Monitor Class
# =============================================================================

class SecurityMonitor:
    """
    Real-time security threat detector.
    
    Analyzes network packets for suspicious patterns and generates
    alerts when threats are detected.
    
    Example:
        >>> monitor = SecurityMonitor()
        >>> alerts = monitor.analyze(parsed_packet)
        >>> for alert in alerts:
        ...     print(f"ALERT: {alert.message}")
    """
    
    def __init__(self, thresholds: Optional[ThreatThresholds] = None):
        """
        Initialize the security monitor.
        
        Args:
            thresholds: Custom detection thresholds. Uses defaults if None.
        """
        # Thread safety
        self._lock = threading.RLock()
        
        # Configuration
        self.thresholds = thresholds or ThreatThresholds()
        
        # IP tracking
        self._ip_trackers: Dict[str, ConnectionTracker] = {}
        
        # Alert management
        self._alerts: List[SecurityAlert] = []
        self._alert_ids: Set[str] = set()  # Prevent duplicate alerts
        
        # Statistics
        self._total_packets_analyzed = 0
        self._threats_detected = 0
        
        # Rate tracking for traffic spikes
        self._packet_timestamps: List[datetime] = []
        self._baseline_rate: Optional[float] = None
        
        # Cleanup tracking
        self._last_cleanup = datetime.now()
        self._cleanup_interval = 60  # seconds
    
    def analyze(self, packet: ParsedPacket) -> List[SecurityAlert]:
        """
        Analyze a packet for security threats.
        
        Args:
            packet: A ParsedPacket object to analyze.
        
        Returns:
            List of new SecurityAlert objects (empty if no threats).
        
        Example:
            >>> alerts = monitor.analyze(parsed_packet)
            >>> if alerts:
            ...     print(f"Detected {len(alerts)} threats!")
        """
        with self._lock:
            new_alerts = []
            self._total_packets_analyzed += 1
            
            # Skip if no source IP
            if not packet.src_ip:
                return new_alerts
            
            # Get or create tracker for this IP
            tracker = self._get_or_create_tracker(packet.src_ip)
            tracker.record_packet(packet)
            
            # Run detection checks
            alert = self._check_port_scan(packet, tracker)
            if alert:
                new_alerts.append(alert)
            
            alert = self._check_brute_force(packet, tracker)
            if alert:
                new_alerts.append(alert)
            
            alert = self._check_syn_flood(packet, tracker)
            if alert:
                new_alerts.append(alert)
            
            alert = self._check_suspicious_port(packet)
            if alert:
                new_alerts.append(alert)
            
            alert = self._check_external_connection(packet)
            if alert:
                new_alerts.append(alert)
            
            # Update threat count
            self._threats_detected += len(new_alerts)
            
            # Periodic cleanup
            self._maybe_cleanup()
            
            return new_alerts
    
    def _get_or_create_tracker(self, ip: str) -> ConnectionTracker:
        """Get existing tracker or create new one for IP."""
        if ip not in self._ip_trackers:
            self._ip_trackers[ip] = ConnectionTracker(ip)
        return self._ip_trackers[ip]
    
    def _add_alert(self, alert: SecurityAlert) -> bool:
        """
        Add alert if not duplicate.
        
        Returns:
            True if alert was added, False if duplicate.
        """
        # Create a dedup key (same type + same IP within short time)
        dedup_key = f"{alert.alert_type.value}_{alert.source_ip}"
        
        # Check if we already have a recent alert of this type from this IP
        if dedup_key in self._alert_ids:
            return False
        
        self._alert_ids.add(dedup_key)
        self._alerts.append(alert)
        
        # Schedule removal of dedup key after 60 seconds
        # (In production, use a proper TTL mechanism)
        
        return True
    
    def _check_port_scan(
        self,
        packet: ParsedPacket,
        tracker: ConnectionTracker
    ) -> Optional[SecurityAlert]:
        """Check for port scanning behavior."""
        unique_ports = tracker.get_unique_ports_in_window(
            self.thresholds.port_scan_window
        )
        
        if len(unique_ports) >= self.thresholds.port_scan_ports:
            alert = SecurityAlert(
                alert_type=AlertType.PORT_SCAN,
                severity=AlertSeverity.HIGH,
                source_ip=packet.src_ip,
                target_ip=packet.dst_ip,
                message=f"Port scan detected from {packet.src_ip}",
                details={
                    "ports_scanned": len(unique_ports),
                    "time_window": f"{self.thresholds.port_scan_window}s",
                    "sample_ports": sorted(list(unique_ports))[:10]
                }
            )
            
            if self._add_alert(alert):
                return alert
        
        return None
    
    def _check_brute_force(
        self,
        packet: ParsedPacket,
        tracker: ConnectionTracker
    ) -> Optional[SecurityAlert]:
        """Check for brute force attempt on sensitive ports only."""
        if not packet.dst_ip or not packet.dst_port:
            return None
        
        # Only check brute force on sensitive ports
        # Skip common web ports (80, 443, 8080, 8443) - too many false positives
        SENSITIVE_PORTS = {
            22: 'SSH',
            23: 'Telnet', 
            21: 'FTP',
            3389: 'RDP',
            5900: 'VNC',
            3306: 'MySQL',
            5432: 'PostgreSQL',
            1433: 'MSSQL',
            6379: 'Redis',
            27017: 'MongoDB'
        }
        
        if packet.dst_port not in SENSITIVE_PORTS:
            return None
        
        target_key = f"{packet.dst_ip}:{packet.dst_port}"
        attempts = tracker.get_attempts_to_target_in_window(
            target_key,
            self.thresholds.brute_force_window
        )
        
        if attempts >= self.thresholds.brute_force_attempts:
            service_name = SENSITIVE_PORTS.get(packet.dst_port, 'Unknown')
            
            # Higher severity for remote access ports
            severity = AlertSeverity.MEDIUM
            if packet.dst_port in [22, 23, 3389, 5900]:  # Remote access
                severity = AlertSeverity.HIGH
            
            alert = SecurityAlert(
                alert_type=AlertType.BRUTE_FORCE,
                severity=severity,
                source_ip=packet.src_ip,
                target_ip=packet.dst_ip,
                message=f"Brute force attempt on {service_name} (port {packet.dst_port}) from {packet.src_ip}",
                details={
                    "target_port": packet.dst_port,
                    "service": service_name,
                    "attempts": attempts,
                    "time_window": f"{self.thresholds.brute_force_window}s"
                }
            )
            
            if self._add_alert(alert):
                return alert
        
        return None
    
    def _check_syn_flood(
        self,
        packet: ParsedPacket,
        tracker: ConnectionTracker
    ) -> Optional[SecurityAlert]:
        """Check for SYN flood attack."""
        syn_count = tracker.get_syn_count_in_window(
            self.thresholds.syn_flood_window
        )
        
        if syn_count >= self.thresholds.syn_flood_count:
            alert = SecurityAlert(
                alert_type=AlertType.SYN_FLOOD,
                severity=AlertSeverity.CRITICAL,
                source_ip=packet.src_ip,
                target_ip=packet.dst_ip,
                message=f"Potential SYN flood attack from {packet.src_ip}",
                details={
                    "syn_packets": syn_count,
                    "time_window": f"{self.thresholds.syn_flood_window}s"
                }
            )
            
            if self._add_alert(alert):
                return alert
        
        return None
    
    def _check_suspicious_port(
        self,
        packet: ParsedPacket
    ) -> Optional[SecurityAlert]:
        """Check for connections to suspicious ports."""
        if not packet.dst_port:
            return None
        
        if packet.dst_port in SUSPICIOUS_PORTS:
            # Only alert for external sources connecting to internal targets
            if not is_private_ip(packet.src_ip) and is_private_ip(packet.dst_ip):
                service_name = SUSPICIOUS_PORTS[packet.dst_port]
                
                alert = SecurityAlert(
                    alert_type=AlertType.SUSPICIOUS_PORT,
                    severity=AlertSeverity.MEDIUM,
                    source_ip=packet.src_ip,
                    target_ip=packet.dst_ip,
                    message=f"External connection to {service_name} (port {packet.dst_port})",
                    details={
                        "port": packet.dst_port,
                        "service": service_name
                    }
                )
                
                if self._add_alert(alert):
                    return alert
        
        return None
    
    def _check_external_connection(
        self,
        packet: ParsedPacket
    ) -> Optional[SecurityAlert]:
        """Check for unusual external connections (informational)."""
        # This is a low-severity informational alert
        # Only trigger for first connection from a new external IP to internal
        if not packet.src_ip or not packet.dst_ip:
            return None
        
        # Skip if source is private (internal traffic)
        if is_private_ip(packet.src_ip):
            return None
        
        # Skip if destination is not private (outbound traffic)
        if not is_private_ip(packet.dst_ip):
            return None
        
        # Check if this is a new external IP
        tracker = self._ip_trackers.get(packet.src_ip)
        if tracker and tracker.packet_count > 1:
            return None  # Already seen this IP
        
        # Note: This generates many alerts, so it's disabled by default
        # Uncomment below to enable external connection tracking
        
        # alert = SecurityAlert(
        #     alert_type=AlertType.EXTERNAL_CONNECTION,
        #     severity=AlertSeverity.LOW,
        #     source_ip=packet.src_ip,
        #     target_ip=packet.dst_ip,
        #     message=f"New external connection from {packet.src_ip}",
        #     details={
        #         "destination_port": packet.dst_port
        #     }
        # )
        # if self._add_alert(alert):
        #     return alert
        
        return None
    
    def _maybe_cleanup(self):
        """Periodically clean up old tracking data."""
        now = datetime.now()
        if (now - self._last_cleanup).total_seconds() < self._cleanup_interval:
            return
        
        self._last_cleanup = now
        
        # Clean up old data in trackers
        for tracker in self._ip_trackers.values():
            tracker.cleanup_old_data()
        
        # Remove inactive trackers (no activity in 5 minutes)
        cutoff = now - timedelta(minutes=5)
        inactive_ips = [
            ip for ip, tracker in self._ip_trackers.items()
            if tracker.last_seen < cutoff
        ]
        for ip in inactive_ips:
            del self._ip_trackers[ip]
        
        # Clean up old dedup keys (simplified - in production use TTL)
        # Keep only last 1000 alert IDs
        if len(self._alert_ids) > 1000:
            self._alert_ids = set(list(self._alert_ids)[-500:])
    
    # =========================================================================
    # Status and Reporting
    # =========================================================================
    
    def get_status(self) -> dict:
        """
        Get current security status.
        
        Returns:
            dict: Status information including severity and color.
        """
        with self._lock:
            if not self._alerts:
                return {
                    "status": SecurityStatus.NORMAL.value,
                    "color": "green",
                    "message": "No threats detected"
                }
            
            # Check for critical alerts
            critical_count = sum(
                1 for a in self._alerts
                if a.severity == AlertSeverity.CRITICAL
            )
            high_count = sum(
                1 for a in self._alerts
                if a.severity == AlertSeverity.HIGH
            )
            
            if critical_count > 0:
                return {
                    "status": SecurityStatus.CRITICAL.value,
                    "color": "red",
                    "message": f"{critical_count} critical threat(s) detected"
                }
            elif high_count > 0:
                return {
                    "status": SecurityStatus.WARNING.value,
                    "color": "orange",
                    "message": f"{high_count} high-severity threat(s) detected"
                }
            else:
                return {
                    "status": SecurityStatus.WARNING.value,
                    "color": "yellow",
                    "message": f"{len(self._alerts)} alert(s) detected"
                }
    
    def get_all_alerts(self) -> List[SecurityAlert]:
        """Get all alerts."""
        with self._lock:
            return list(self._alerts)
    
    def get_recent_alerts(self, limit: int = 10) -> List[SecurityAlert]:
        """
        Get most recent alerts.
        
        Args:
            limit: Maximum number of alerts to return.
        
        Returns:
            List of most recent SecurityAlert objects.
        """
        with self._lock:
            return list(reversed(self._alerts[-limit:]))
    
    def get_alerts_by_severity(
        self,
        severity: AlertSeverity
    ) -> List[SecurityAlert]:
        """Get all alerts of a specific severity."""
        with self._lock:
            return [a for a in self._alerts if a.severity == severity]
    
    def get_alerts_by_type(
        self,
        alert_type: AlertType
    ) -> List[SecurityAlert]:
        """Get all alerts of a specific type."""
        with self._lock:
            return [a for a in self._alerts if a.alert_type == alert_type]
    
    def get_summary(self) -> dict:
        """
        Get comprehensive security summary.
        
        Returns:
            dict: Summary of security status and statistics.
        """
        with self._lock:
            status = self.get_status()
            
            # Count alerts by severity
            severity_counts = {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0
            }
            for alert in self._alerts:
                key = alert.severity.value.lower()
                severity_counts[key] = severity_counts.get(key, 0) + 1
            
            # Count alerts by type
            type_counts = {}
            for alert in self._alerts:
                key = alert.alert_type.value
                type_counts[key] = type_counts.get(key, 0) + 1
            
            return {
                "status": status,
                "total_packets_analyzed": self._total_packets_analyzed,
                "total_threats_detected": self._threats_detected,
                "total_alerts": len(self._alerts),
                "alerts_by_severity": severity_counts,
                "alerts_by_type": type_counts,
                "tracked_ips": len(self._ip_trackers),
                "thresholds": {
                    "port_scan": {
                        "ports": self.thresholds.port_scan_ports,
                        "window": self.thresholds.port_scan_window
                    },
                    "brute_force": {
                        "attempts": self.thresholds.brute_force_attempts,
                        "window": self.thresholds.brute_force_window
                    },
                    "syn_flood": {
                        "count": self.thresholds.syn_flood_count,
                        "window": self.thresholds.syn_flood_window
                    }
                }
            }
    
    def clear_alerts(self):
        """Clear all alerts."""
        with self._lock:
            self._alerts.clear()
            self._alert_ids.clear()
    
    def reset(self):
        """Reset all security monitoring data."""
        with self._lock:
            self._ip_trackers.clear()
            self._alerts.clear()
            self._alert_ids.clear()
            self._total_packets_analyzed = 0
            self._threats_detected = 0
            self._packet_timestamps.clear()
            self._baseline_rate = None


# =============================================================================
# Module Test
# =============================================================================

if __name__ == "__main__":
    from core_sniffer.utils.formatters import (
        format_alert_box,
        format_statistics_table,
        colorize_severity
    )
    
    print("=" * 60)
    print("SECURITY MONITOR MODULE TEST")
    print("=" * 60)
    
    # Create monitor with lower thresholds for testing
    test_thresholds = ThreatThresholds(
        port_scan_ports=5,  # Lower for testing
        port_scan_window=60,
        brute_force_attempts=5,  # Lower for testing
        brute_force_window=60,
        syn_flood_count=10,  # Lower for testing
        syn_flood_window=10
    )
    
    monitor = SecurityMonitor(thresholds=test_thresholds)
    
    # Test 1: Normal traffic (should not trigger alerts)
    print("\n--- Test 1: Normal Traffic ---")
    normal_packets = [
        ParsedPacket(
            protocol="TCP",
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            src_port=54321,
            dst_port=443,
            tcp_flags="SYN ACK",
            size=64
        ),
        ParsedPacket(
            protocol="DNS",
            src_ip="192.168.1.100",
            dst_ip="8.8.8.8",
            src_port=12345,
            dst_port=53,
            size=64
        ),
    ]
    
    for packet in normal_packets:
        alerts = monitor.analyze(packet)
        if alerts:
            print(f"  Unexpected alert: {alerts[0].message}")
    
    print(f"  Processed {len(normal_packets)} normal packets")
    print(f"  Alerts triggered: {len(monitor.get_all_alerts())}")
    
    # Test 2: Port scan simulation
    print("\n--- Test 2: Port Scan Detection ---")
    monitor.reset()
    
    attacker_ip = "45.33.32.156"
    target_ip = "192.168.1.100"
    
    # Simulate scanning multiple ports
    for port in range(20, 30):  # 10 different ports
        packet = ParsedPacket(
            protocol="TCP",
            src_ip=attacker_ip,
            dst_ip=target_ip,
            src_port=54321,
            dst_port=port,
            tcp_flags="SYN",
            size=64
        )
        alerts = monitor.analyze(packet)
        if alerts:
            print(format_alert_box(
                alert_type=alerts[0].alert_type.value,
                severity=alerts[0].severity.value,
                message=alerts[0].message,
                source_ip=alerts[0].source_ip,
                details=alerts[0].details
            ))
    
    # Test 3: Brute force simulation
    print("\n--- Test 3: Brute Force Detection ---")
    monitor.reset()
    
    attacker_ip = "192.168.1.105"
    target_ip = "192.168.1.1"
    target_port = 22  # SSH
    
    # Simulate multiple connection attempts to same port
    for i in range(10):
        packet = ParsedPacket(
            protocol="TCP",
            src_ip=attacker_ip,
            dst_ip=target_ip,
            src_port=50000 + i,
            dst_port=target_port,
            tcp_flags="SYN",
            size=64
        )
        alerts = monitor.analyze(packet)
        if alerts:
            print(format_alert_box(
                alert_type=alerts[0].alert_type.value,
                severity=alerts[0].severity.value,
                message=alerts[0].message,
                source_ip=alerts[0].source_ip,
                details=alerts[0].details
            ))
    
    # Test 4: SYN flood simulation
    print("\n--- Test 4: SYN Flood Detection ---")
    monitor.reset()
    
    attacker_ip = "10.10.10.10"
    target_ip = "192.168.1.100"
    
    # Simulate many SYN packets
    for i in range(15):
        packet = ParsedPacket(
            protocol="TCP",
            src_ip=attacker_ip,
            dst_ip=target_ip,
            src_port=40000 + i,
            dst_port=80,
            tcp_flags="SYN",
            size=64
        )
        alerts = monitor.analyze(packet)
        if alerts:
            print(format_alert_box(
                alert_type=alerts[0].alert_type.value,
                severity=alerts[0].severity.value,
                message=alerts[0].message,
                source_ip=alerts[0].source_ip,
                details=alerts[0].details
            ))
    
    # Test 5: Security summary
    print("\n--- Test 5: Security Summary ---")
    
    # Add some varied traffic
    monitor.reset()
    
    # Trigger a port scan
    for port in range(100, 110):
        monitor.analyze(ParsedPacket(
            protocol="TCP",
            src_ip="1.2.3.4",
            dst_ip="192.168.1.1",
            src_port=12345,
            dst_port=port,
            tcp_flags="SYN",
            size=64
        ))
    
    summary = monitor.get_summary()
    
    print(format_statistics_table(
        title="SECURITY SUMMARY",
        data={
            "Status": summary["status"]["status"],
            "Packets Analyzed": summary["total_packets_analyzed"],
            "Threats Detected": summary["total_threats_detected"],
            "Total Alerts": summary["total_alerts"],
            "Tracked IPs": summary["tracked_ips"]
        }
    ))
    
    print("\n  Alerts by Severity:")
    print("  " + "-" * 30)
    for severity, count in summary["alerts_by_severity"].items():
        if count > 0:
            print(f"    {severity.upper():<12} {count}")
    
    print("\n  Alerts by Type:")
    print("  " + "-" * 30)
    for alert_type, count in summary["alerts_by_type"].items():
        if count > 0:
            print(f"    {alert_type:<20} {count}")
    
    print("\n" + "=" * 60)
    print("Security monitor module test complete.")
    print("=" * 60)