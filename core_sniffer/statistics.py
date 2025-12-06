"""
Statistics Module

Real-time traffic statistics tracking for the packet sniffer.
Provides:
- Packet and byte counters
- Rate calculations (packets/sec, bytes/sec)
- Protocol distribution
- Top talkers (most active IPs)
- Port usage statistics
- Session timing

Thread-safe design for concurrent packet processing.
"""

import time
import threading
from datetime import datetime
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional, Dict, List, Tuple

from core_sniffer.protocol_parser import ParsedPacket


# =============================================================================
# Data Classes
# =============================================================================

@dataclass
class RateCalculator:
    """
    Calculates rolling average rates over a time window.
    
    Attributes:
        window_size: Time window in seconds for rate calculation.
        samples: List of (timestamp, value) tuples.
    """
    window_size: float = 1.0
    samples: list = field(default_factory=list)
    
    def __post_init__(self):
        """Initialize the lock after dataclass creation."""
        self._lock = threading.Lock()
    
    def add_sample(self, value: int = 1):
        """Add a sample with the current timestamp."""
        now = time.time()
        with self._lock:
            self.samples.append((now, value))
            self._cleanup(now)
    
    def _cleanup(self, now: float):
        """Remove samples outside the time window."""
        cutoff = now - self.window_size
        self.samples = [(t, v) for t, v in self.samples if t > cutoff]
    
    def get_rate(self) -> float:
        """
        Calculate the current rate (sum of values / window_size).
        
        Returns:
            float: Current rate per second.
        """
        now = time.time()
        with self._lock:
            self._cleanup(now)
            if not self.samples:
                return 0.0
            total = sum(v for _, v in self.samples)
            return total / self.window_size


@dataclass
class SessionInfo:
    """
    Session timing information.
    
    Attributes:
        start_time: When the session started.
        end_time: When the session ended (None if ongoing).
    """
    start_time: datetime = field(default_factory=datetime.now)
    end_time: Optional[datetime] = None
    
    @property
    def duration_seconds(self) -> float:
        """Get session duration in seconds."""
        end = self.end_time or datetime.now()
        return (end - self.start_time).total_seconds()
    
    @property
    def is_active(self) -> bool:
        """Check if session is still active."""
        return self.end_time is None
    
    def stop(self):
        """Mark the session as ended."""
        self.end_time = datetime.now()


# =============================================================================
# Traffic Statistics Class
# =============================================================================

class TrafficStatistics:
    """
    Comprehensive traffic statistics tracker.
    
    Tracks packets, bytes, protocols, IPs, and ports in real-time.
    Thread-safe for concurrent packet processing.
    
    Example:
        >>> stats = TrafficStatistics()
        >>> stats.update(parsed_packet)
        >>> print(stats.get_summary())
    """
    
    def __init__(self, rate_window: float = 1.0):
        """
        Initialize the statistics tracker.
        
        Args:
            rate_window: Time window in seconds for rate calculations.
        """
        # Thread safety - Use RLock to allow reentrant locking
        self._lock = threading.RLock()
        
        # Session timing
        self.session = SessionInfo()
        
        # Counters
        self._total_packets: int = 0
        self._total_bytes: int = 0
        
        # Rate calculators
        self._packet_rate = RateCalculator(window_size=rate_window)
        self._byte_rate = RateCalculator(window_size=rate_window)
        
        # Protocol statistics
        self._protocols: Dict[str, int] = defaultdict(int)
        self._protocol_bytes: Dict[str, int] = defaultdict(int)
        
        # IP statistics
        self._source_ips: Dict[str, int] = defaultdict(int)
        self._dest_ips: Dict[str, int] = defaultdict(int)
        self._ip_bytes: Dict[str, int] = defaultdict(int)
        
        # Port statistics
        self._source_ports: Dict[int, int] = defaultdict(int)
        self._dest_ports: Dict[int, int] = defaultdict(int)
        
        # Connection tracking (src_ip:src_port -> dst_ip:dst_port)
        self._connections: Dict[str, int] = defaultdict(int)
        
        # Packet size distribution
        self._size_buckets: Dict[str, int] = defaultdict(int)
        
        # Error tracking
        self._parse_errors: int = 0
    
    def update(self, packet: ParsedPacket):
        """
        Update statistics with a parsed packet.
        
        Args:
            packet: A ParsedPacket object from the protocol parser.
        
        Example:
            >>> parsed = parser.parse(raw_packet)
            >>> stats.update(parsed)
        """
        with self._lock:
            # Basic counters
            self._total_packets += 1
            self._total_bytes += packet.size
            
            # Rate tracking
            self._packet_rate.add_sample(1)
            self._byte_rate.add_sample(packet.size)
            
            # Protocol tracking
            protocol = packet.protocol or "UNKNOWN"
            self._protocols[protocol] += 1
            self._protocol_bytes[protocol] += packet.size
            
            # IP tracking
            if packet.src_ip:
                self._source_ips[packet.src_ip] += 1
                self._ip_bytes[packet.src_ip] = \
                    self._ip_bytes.get(packet.src_ip, 0) + packet.size
            
            if packet.dst_ip:
                self._dest_ips[packet.dst_ip] += 1
                self._ip_bytes[packet.dst_ip] = \
                    self._ip_bytes.get(packet.dst_ip, 0) + packet.size
            
            # Port tracking
            if packet.src_port:
                self._source_ports[packet.src_port] += 1
            
            if packet.dst_port:
                self._dest_ports[packet.dst_port] += 1
            
            # Connection tracking
            if packet.src_ip and packet.dst_ip:
                conn_key = self._make_connection_key(
                    packet.src_ip, 
                    packet.src_port,
                    packet.dst_ip, 
                    packet.dst_port
                )
                self._connections[conn_key] += 1
            
            # Size distribution
            size_bucket = self._get_size_bucket(packet.size)
            self._size_buckets[size_bucket] += 1
            
            # Error tracking
            if packet.warnings:
                self._parse_errors += 1
    
    def _make_connection_key(
        self, 
        src_ip: str, 
        src_port: Optional[int],
        dst_ip: str, 
        dst_port: Optional[int]
    ) -> str:
        """Create a unique key for a connection."""
        src = f"{src_ip}:{src_port}" if src_port else src_ip
        dst = f"{dst_ip}:{dst_port}" if dst_port else dst_ip
        return f"{src} -> {dst}"
    
    def _get_size_bucket(self, size: int) -> str:
        """Categorize packet size into buckets."""
        if size <= 64:
            return "0-64"
        elif size <= 128:
            return "65-128"
        elif size <= 256:
            return "129-256"
        elif size <= 512:
            return "257-512"
        elif size <= 1024:
            return "513-1024"
        elif size <= 1500:
            return "1025-1500"
        else:
            return "1500+"
    
    # =========================================================================
    # Getters - Basic Statistics
    # =========================================================================
    
    @property
    def total_packets(self) -> int:
        """Get total number of packets captured."""
        with self._lock:
            return self._total_packets
    
    @property
    def total_bytes(self) -> int:
        """Get total bytes captured."""
        with self._lock:
            return self._total_bytes
    
    @property
    def packets_per_second(self) -> float:
        """Get current packets per second rate."""
        return self._packet_rate.get_rate()
    
    @property
    def bytes_per_second(self) -> float:
        """Get current bytes per second rate."""
        return self._byte_rate.get_rate()
    
    @property
    def duration(self) -> float:
        """Get session duration in seconds."""
        return self.session.duration_seconds
    
    def _get_average_packet_size_unlocked(self) -> float:
        """Get average packet size (internal, assumes lock is held)."""
        if self._total_packets == 0:
            return 0.0
        return self._total_bytes / self._total_packets
    
    @property
    def average_packet_size(self) -> float:
        """Get average packet size in bytes."""
        with self._lock:
            return self._get_average_packet_size_unlocked()
    
    # =========================================================================
    # Getters - Protocol Statistics
    # =========================================================================
    
    def get_protocol_counts(self) -> Dict[str, int]:
        """
        Get packet counts by protocol.
        
        Returns:
            dict: Protocol name -> packet count.
        """
        with self._lock:
            return dict(self._protocols)
    
    def get_protocol_bytes(self) -> Dict[str, int]:
        """
        Get byte counts by protocol.
        
        Returns:
            dict: Protocol name -> byte count.
        """
        with self._lock:
            return dict(self._protocol_bytes)
    
    def get_protocol_percentages(self) -> Dict[str, float]:
        """
        Get protocol distribution as percentages.
        
        Returns:
            dict: Protocol name -> percentage of total packets.
        """
        with self._lock:
            if self._total_packets == 0:
                return {}
            
            return {
                proto: (count / self._total_packets) * 100
                for proto, count in self._protocols.items()
            }
    
    # =========================================================================
    # Getters - IP Statistics
    # =========================================================================
    
    def get_top_sources(self, limit: int = 10) -> List[Tuple[str, int]]:
        """
        Get top source IPs by packet count.
        
        Args:
            limit: Maximum number of results.
        
        Returns:
            list: List of (ip, count) tuples, sorted by count descending.
        """
        with self._lock:
            sorted_ips = sorted(
                self._source_ips.items(),
                key=lambda x: x[1],
                reverse=True
            )
            return sorted_ips[:limit]
    
    def get_top_destinations(self, limit: int = 10) -> List[Tuple[str, int]]:
        """
        Get top destination IPs by packet count.
        
        Args:
            limit: Maximum number of results.
        
        Returns:
            list: List of (ip, count) tuples, sorted by count descending.
        """
        with self._lock:
            sorted_ips = sorted(
                self._dest_ips.items(),
                key=lambda x: x[1],
                reverse=True
            )
            return sorted_ips[:limit]
    
    def get_top_talkers(self, limit: int = 10) -> List[Tuple[str, int]]:
        """
        Get top IPs by total bytes (combined send + receive).
        
        Args:
            limit: Maximum number of results.
        
        Returns:
            list: List of (ip, bytes) tuples, sorted by bytes descending.
        """
        with self._lock:
            sorted_ips = sorted(
                self._ip_bytes.items(),
                key=lambda x: x[1],
                reverse=True
            )
            return sorted_ips[:limit]
    
    def get_unique_source_count(self) -> int:
        """Get count of unique source IPs."""
        with self._lock:
            return len(self._source_ips)
    
    def get_unique_dest_count(self) -> int:
        """Get count of unique destination IPs."""
        with self._lock:
            return len(self._dest_ips)
    
    # =========================================================================
    # Getters - Port Statistics
    # =========================================================================
    
    def get_top_dest_ports(self, limit: int = 10) -> List[Tuple[int, int]]:
        """
        Get top destination ports by packet count.
        
        Args:
            limit: Maximum number of results.
        
        Returns:
            list: List of (port, count) tuples, sorted by count descending.
        """
        with self._lock:
            sorted_ports = sorted(
                self._dest_ports.items(),
                key=lambda x: x[1],
                reverse=True
            )
            return sorted_ports[:limit]
    
    def get_top_source_ports(self, limit: int = 10) -> List[Tuple[int, int]]:
        """
        Get top source ports by packet count.
        
        Args:
            limit: Maximum number of results.
        
        Returns:
            list: List of (port, count) tuples, sorted by count descending.
        """
        with self._lock:
            sorted_ports = sorted(
                self._source_ports.items(),
                key=lambda x: x[1],
                reverse=True
            )
            return sorted_ports[:limit]
    
    # =========================================================================
    # Getters - Connection Statistics
    # =========================================================================
    
    def get_top_connections(self, limit: int = 10) -> List[Tuple[str, int]]:
        """
        Get top connections by packet count.
        
        Args:
            limit: Maximum number of results.
        
        Returns:
            list: List of (connection_key, count) tuples.
        """
        with self._lock:
            sorted_conns = sorted(
                self._connections.items(),
                key=lambda x: x[1],
                reverse=True
            )
            return sorted_conns[:limit]
    
    def get_connection_count(self) -> int:
        """Get total number of unique connections observed."""
        with self._lock:
            return len(self._connections)
    
    # =========================================================================
    # Getters - Size Distribution
    # =========================================================================
    
    def get_size_distribution(self) -> Dict[str, int]:
        """
        Get packet size distribution.
        
        Returns:
            dict: Size bucket -> count.
        """
        with self._lock:
            # Return in order
            bucket_order = [
                "0-64", "65-128", "129-256", "257-512",
                "513-1024", "1025-1500", "1500+"
            ]
            return {
                bucket: self._size_buckets.get(bucket, 0)
                for bucket in bucket_order
            }
    
    # =========================================================================
    # Summary Methods
    # =========================================================================
    
    def get_summary(self) -> dict:
        """
        Get a comprehensive summary of all statistics.
        
        Returns:
            dict: Complete statistics summary.
        """
        with self._lock:
            return {
                "session": {
                    "start_time": self.session.start_time.isoformat(),
                    "duration_seconds": self.session.duration_seconds,
                    "is_active": self.session.is_active
                },
                "totals": {
                    "packets": self._total_packets,
                    "bytes": self._total_bytes,
                    "average_packet_size": self._get_average_packet_size_unlocked()
                },
                "rates": {
                    "packets_per_second": self._packet_rate.get_rate(),
                    "bytes_per_second": self._byte_rate.get_rate()
                },
                "protocols": dict(self._protocols),
                "protocol_bytes": dict(self._protocol_bytes),
                "unique_ips": {
                    "sources": len(self._source_ips),
                    "destinations": len(self._dest_ips)
                },
                "connections": len(self._connections),
                "parse_errors": self._parse_errors
            }
    
    def get_display_summary(self) -> dict:
        """
        Get summary formatted for display.
        
        Returns:
            dict: Display-ready statistics.
        """
        with self._lock:
            return {
                "Total Packets": self._total_packets,
                "Total Bytes": self._total_bytes,
                "Duration": f"{self.session.duration_seconds:.1f}s",
                "Packets/sec": f"{self._packet_rate.get_rate():.1f}",
                "Bytes/sec": f"{self._byte_rate.get_rate():.1f}",
                "Avg Packet Size": f"{self._get_average_packet_size_unlocked():.1f} bytes",
                "Unique Sources": len(self._source_ips),
                "Unique Destinations": len(self._dest_ips),
                "Connections": len(self._connections)
            }
    
    def stop(self):
        """Stop the session and finalize timing."""
        self.session.stop()
    
    def reset(self):
        """Reset all statistics to initial state."""
        with self._lock:
            self.session = SessionInfo()
            self._total_packets = 0
            self._total_bytes = 0
            self._protocols.clear()
            self._protocol_bytes.clear()
            self._source_ips.clear()
            self._dest_ips.clear()
            self._ip_bytes.clear()
            self._source_ports.clear()
            self._dest_ports.clear()
            self._connections.clear()
            self._size_buckets.clear()
            self._parse_errors = 0


# =============================================================================
# Module Test
# =============================================================================

if __name__ == "__main__":
    from core_sniffer.utils.formatters import (
        format_bytes,
        format_duration,
        format_statistics_table,
        format_protocol_distribution
    )
    
    print("=" * 60)
    print("STATISTICS MODULE TEST")
    print("=" * 60)
    
    # Create statistics tracker
    stats = TrafficStatistics()
    
    # Simulate some packets
    print("\nSimulating packet captures...")
    
    test_packets = [
        ParsedPacket(
            protocol="TCP",
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            src_port=54321,
            dst_port=443,
            size=1500
        ),
        ParsedPacket(
            protocol="TCP",
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            src_port=54321,
            dst_port=443,
            size=1200
        ),
        ParsedPacket(
            protocol="UDP",
            src_ip="192.168.1.100",
            dst_ip="8.8.8.8",
            src_port=12345,
            dst_port=53,
            size=64
        ),
        ParsedPacket(
            protocol="DNS",
            src_ip="8.8.8.8",
            dst_ip="192.168.1.100",
            src_port=53,
            dst_port=12345,
            size=128
        ),
        ParsedPacket(
            protocol="HTTP",
            src_ip="192.168.1.100",
            dst_ip="93.184.216.34",
            src_port=54322,
            dst_port=80,
            size=800
        ),
        ParsedPacket(
            protocol="ICMP",
            src_ip="192.168.1.1",
            dst_ip="192.168.1.100",
            size=64
        ),
        ParsedPacket(
            protocol="TCP",
            src_ip="192.168.1.101",
            dst_ip="10.0.0.1",
            src_port=54323,
            dst_port=22,
            size=256
        ),
        ParsedPacket(
            protocol="TCP",
            src_ip="192.168.1.102",
            dst_ip="10.0.0.2",
            src_port=54324,
            dst_port=443,
            size=1400
        ),
    ]
    
    for packet in test_packets:
        stats.update(packet)
    
    print(f"  Processed {len(test_packets)} packets")
    
    # Display summary
    print("\n" + format_statistics_table(
        title="SESSION SUMMARY",
        data=stats.get_display_summary()
    ))
    
    # Protocol distribution
    print("\n" + format_protocol_distribution(
        stats.get_protocol_counts(),
        stats.total_packets
    ))
    
    # Top sources
    print("\n  Top Source IPs:")
    print("  " + "-" * 40)
    for ip, count in stats.get_top_sources(5):
        print(f"    {ip:<20} {count:>6} packets")
    
    # Top destination ports
    print("\n  Top Destination Ports:")
    print("  " + "-" * 40)
    for port, count in stats.get_top_dest_ports(5):
        from core_sniffer.protocol_parser import get_service_name
        service = get_service_name(port)
        print(f"    {port:>5} ({service:<10}) {count:>6} packets")
    
    # Size distribution
    print("\n  Packet Size Distribution:")
    print("  " + "-" * 40)
    for bucket, count in stats.get_size_distribution().items():
        if count > 0:
            print(f"    {bucket:>12} bytes: {count:>6} packets")
    
    # Full summary (JSON-like)
    print("\n  Full Summary (for API):")
    print("  " + "-" * 40)
    summary = stats.get_summary()
    print(f"    Total Packets: {summary['totals']['packets']}")
    print(f"    Total Bytes:   {format_bytes(summary['totals']['bytes'])}")
    print(f"    Duration:      {format_duration(summary['session']['duration_seconds'])}")
    print(f"    Protocols:     {len(summary['protocols'])}")
    print(f"    Connections:   {summary['connections']}")
    
    print("\n" + "=" * 60)
    print("Statistics module test complete.")
    print("=" * 60)