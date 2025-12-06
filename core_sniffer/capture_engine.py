"""
Capture Engine Module

The core packet capture engine that orchestrates all sniffer components.
Responsibilities:
- Raw packet capture via Scapy
- Packet parsing and analysis
- Statistics collection
- Security monitoring
- Callback management for real-time processing

Thread-safe design with graceful start/stop handling.
"""

import threading
import time
from datetime import datetime
from typing import Optional, Callable, List, Any
from dataclasses import dataclass, field
from enum import Enum

from core_sniffer.protocol_parser import ProtocolParser, ParsedPacket
from core_sniffer.statistics import TrafficStatistics
from core_sniffer.security_monitor import SecurityMonitor, SecurityAlert, ThreatThresholds
from core_sniffer.utils.platform_detect import (
    get_os_info,
    get_default_interface,
    check_permissions,
    get_platform_summary
)

# Web integration (optional)
try:
    from core_sniffer.utils.web_integration import WebIntegration
    WEB_INTEGRATION_AVAILABLE = True
except ImportError:
    WEB_INTEGRATION_AVAILABLE = False


# =============================================================================
# Enums and Types
# =============================================================================

class EngineState(Enum):
    """Capture engine states."""
    STOPPED = "STOPPED"
    STARTING = "STARTING"
    RUNNING = "RUNNING"
    STOPPING = "STOPPING"
    ERROR = "ERROR"


# Type alias for packet callbacks
PacketCallback = Callable[[ParsedPacket], None]
AlertCallback = Callable[[SecurityAlert], None]


# =============================================================================
# Configuration
# =============================================================================

@dataclass
class CaptureConfig:
    """
    Configuration for the capture engine.

    """
    interface: Optional[str] = None
    packet_count: int = 0
    timeout: Optional[float] = None
    bpf_filter: Optional[str] = None
    promiscuous: bool = True  #false = your traffic, true = all traffic
    store_packets: bool = False 
    max_stored_packets: int = 10000
    enable_security: bool = True
    security_thresholds: Optional[ThreatThresholds] = None
    enable_web: bool = True
    web_url: str = "http://127.0.0.1:8000"

# =============================================================================
# Capture Engine Class
# =============================================================================

class CaptureEngine:
    """
    Main packet capture engine.
    
    Orchestrates packet capture, parsing, statistics, and security monitoring.
    Provides a clean interface for starting, stopping, and monitoring captures.
    
    Example:
        >>> engine = CaptureEngine()
        >>> engine.add_packet_callback(my_handler)
        >>> engine.start()
        >>> # ... capture runs ...
        >>> engine.stop()
        >>> print(engine.statistics.get_summary())
    """
    
    def __init__(self, config: Optional[CaptureConfig] = None):
        """
        Initialize the capture engine.
        
        Args:
            config: Capture configuration. Uses defaults if None.
        """
        # Configuration
        self.config = config or CaptureConfig()
        
        # State management
        self._state = EngineState.STOPPED
        self._state_lock = threading.Lock()
        
        # Core components
        self.parser = ProtocolParser()
        self.statistics = TrafficStatistics()
        self.security: Optional[SecurityMonitor] = None
        self.web_integration: Optional['WebIntegration'] = None
        
        if self.config.enable_security:
            self.security = SecurityMonitor(
                thresholds=self.config.security_thresholds
            )
        
        # Interface
        self._interface = self.config.interface or get_default_interface()
        
        # Packet storage
        self._stored_packets: List[ParsedPacket] = []
        self._storage_lock = threading.Lock()
        
        # Callbacks
        self._packet_callbacks: List[PacketCallback] = []
        self._alert_callbacks: List[AlertCallback] = []
        self._callbacks_lock = threading.Lock()
        
        # Capture thread
        self._capture_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        
        # Error tracking
        self._last_error: Optional[str] = None
        
        # Timing
        self._start_time: Optional[datetime] = None
        self._stop_time: Optional[datetime] = None

        # Web integration
        self.web_integration: Optional[WebIntegration] = None
        if self.config.enable_web and WEB_INTEGRATION_AVAILABLE:
            self.web_integration = WebIntegration(
                base_url=self.config.web_url,
                enabled=True,
                verbose=False
            )
        
        # Import Scapy (deferred to avoid import errors if not installed)
        self._scapy_sniff = None
        self._import_scapy()
    
    def _import_scapy(self):
        """Import Scapy sniff function."""
        try:
            from scapy.all import sniff
            self._scapy_sniff = sniff
        except ImportError:
            self._last_error = "Scapy is not installed. Run: pip install scapy"
            self._state = EngineState.ERROR
    
    # =========================================================================
    # State Management
    # =========================================================================
    
    @property
    def state(self) -> EngineState:
        """Get current engine state."""
        with self._state_lock:
            return self._state
    
    @property
    def is_running(self) -> bool:
        """Check if engine is currently capturing."""
        return self.state == EngineState.RUNNING
    
    @property
    def interface(self) -> str:
        """Get the network interface being used."""
        return self._interface
    
    @property
    def last_error(self) -> Optional[str]:
        """Get the last error message, if any."""
        return self._last_error
    
    # =========================================================================
    # Callback Management
    # =========================================================================
    
    def add_packet_callback(self, callback: PacketCallback):
        """
        Add a callback to be called for each captured packet.
        
        Args:
            callback: Function that takes a ParsedPacket as argument.
        
        Example:
            >>> def my_handler(packet: ParsedPacket):
            ...     print(f"Got packet: {packet.protocol}")
            >>> engine.add_packet_callback(my_handler)
        """
        with self._callbacks_lock:
            self._packet_callbacks.append(callback)
    
    def remove_packet_callback(self, callback: PacketCallback):
        """Remove a packet callback."""
        with self._callbacks_lock:
            if callback in self._packet_callbacks:
                self._packet_callbacks.remove(callback)
    
    def add_alert_callback(self, callback: AlertCallback):
        """
        Add a callback to be called for each security alert.
        
        Args:
            callback: Function that takes a SecurityAlert as argument.
        
        Example:
            >>> def alert_handler(alert: SecurityAlert):
            ...     print(f"ALERT: {alert.message}")
            >>> engine.add_alert_callback(alert_handler)
        """
        with self._callbacks_lock:
            self._alert_callbacks.append(callback)
    
    def remove_alert_callback(self, callback: AlertCallback):
        """Remove an alert callback."""
        with self._callbacks_lock:
            if callback in self._alert_callbacks:
                self._alert_callbacks.remove(callback)
    
    def _notify_packet_callbacks(self, packet: ParsedPacket):
        """Notify all packet callbacks."""
        with self._callbacks_lock:
            callbacks = list(self._packet_callbacks)
        
        for callback in callbacks:
            try:
                callback(packet)
            except Exception as e:
                # Don't let callback errors stop the capture
                pass
    
    def _notify_alert_callbacks(self, alert: SecurityAlert):
        """Notify all alert callbacks."""
        with self._callbacks_lock:
            callbacks = list(self._alert_callbacks)
        
        for callback in callbacks:
            try:
                callback(alert)
            except Exception as e:
                # Don't let callback errors stop the capture
                pass
    
    # =========================================================================
    # Packet Processing
    # =========================================================================
    
    def _process_packet(self, raw_packet) -> Optional[ParsedPacket]:
        """
        Process a raw Scapy packet.
        """
        try:
            # Parse the packet
            parsed = self.parser.parse(raw_packet)
            
            # Update statistics
            self.statistics.update(parsed)
            
            # Security analysis
            is_malicious = False
            if self.security:
                alerts = self.security.analyze(parsed)
                if alerts:
                    is_malicious = True
                    for alert in alerts:
                        self._notify_alert_callbacks(alert)
                        # Send alert to web platform
                        if self.web_integration:
                            self.web_integration.send_alert(alert)
            
            # Store packet if enabled
            if self.config.store_packets:
                self._store_packet(parsed)
            
            # Notify callbacks
            self._notify_packet_callbacks(parsed)

            # Send to web platform
            if self.web_integration:
                self.web_integration.send_packet(parsed, is_malicious = is_malicious)
            
            return parsed
            
        except Exception as e:
            # Log error but continue capturing
            return None
    
    def _store_packet(self, packet: ParsedPacket):
        """Store a packet in memory."""
        with self._storage_lock:
            self._stored_packets.append(packet)
            
            # Remove oldest packets if over limit
            while len(self._stored_packets) > self.config.max_stored_packets:
                self._stored_packets.pop(0)
    
    def get_stored_packets(self) -> List[ParsedPacket]:
        """Get all stored packets."""
        with self._storage_lock:
            return list(self._stored_packets)
    
    def clear_stored_packets(self):
        """Clear all stored packets."""
        with self._storage_lock:
            self._stored_packets.clear()
    
    # =========================================================================
    # Capture Control
    # =========================================================================
    
    def start(self, blocking: bool = False) -> bool:
        """
        Start packet capture.
        
        Args:
            blocking: If True, blocks until capture stops.
                     If False, runs capture in background thread.
        
        Returns:
            True if capture started successfully, False otherwise.
        
        Example:
            >>> engine = CaptureEngine()
            >>> engine.start()  # Non-blocking
            >>> # ... do other things ...
            >>> engine.stop()
            
            >>> engine.start(blocking=True)  # Blocking
        """
        with self._state_lock:
            if self._state not in [EngineState.STOPPED, EngineState.ERROR]:
                return False
            self._state = EngineState.STARTING
        
        # Check for Scapy
        if self._scapy_sniff is None:
            self._state = EngineState.ERROR
            self._last_error = "Scapy not available"
            return False
        
        # Reset state
        self._stop_event.clear()
        self._last_error = None
        self._start_time = datetime.now()
        self._stop_time = None
        
        # Reset statistics
        self.statistics.reset()
        if self.security:
            self.security.reset()
        
        # Start web integration
        if self.web_integration:
            self.web_integration.start()
        
        if blocking:
            # Run capture in current thread
            self._run_capture()
            return True
        else:
            # Run capture in background thread
            self._capture_thread = threading.Thread(
                target=self._run_capture,
                daemon=True
            )
            self._capture_thread.start()
            
            # Wait for capture to actually start
            timeout = 5.0
            start = time.time()
            while self._state == EngineState.STARTING:
                if time.time() - start > timeout:
                    self._last_error = "Capture start timeout"
                    self._state = EngineState.ERROR
                    return False
                time.sleep(0.1)
            
            return self._state == EngineState.RUNNING
    
    def _run_capture(self):
        """Internal capture loop."""
        try:
            with self._state_lock:
                self._state = EngineState.RUNNING
            
            # Build sniff arguments
            sniff_kwargs = {
                "iface": self._interface,
                "prn": lambda pkt: (self._process_packet(pkt), None)[1],
                "store": False,
                "stop_filter": lambda p: self._stop_event.is_set()
            }
            
            if self.config.packet_count > 0:
                sniff_kwargs["count"] = self.config.packet_count
            
            if self.config.timeout:
                sniff_kwargs["timeout"] = self.config.timeout
            
            if self.config.bpf_filter:
                sniff_kwargs["filter"] = self.config.bpf_filter
            
            # Run capture
            self._scapy_sniff(**sniff_kwargs)
            
        except PermissionError:
            self._last_error = (
                "Permission denied. "
                "Run with sudo (macOS/Linux) or as Administrator (Windows)."
            )
            with self._state_lock:
                self._state = EngineState.ERROR
                
        except OSError as e:
            if "No such device" in str(e):
                self._last_error = f"Interface '{self._interface}' not found."
            else:
                self._last_error = f"OS error: {str(e)}"
            with self._state_lock:
                self._state = EngineState.ERROR
                
        except Exception as e:
            self._last_error = f"Capture error: {str(e)}"
            with self._state_lock:
                self._state = EngineState.ERROR
                
        finally:
            self._stop_time = datetime.now()
            self.statistics.stop()
            with self._state_lock:
                if self._state == EngineState.RUNNING:
                    self._state = EngineState.STOPPED
    
    def stop(self, timeout: float = 5.0) -> bool:
        """
        Stop packet capture.
        
        Args:
            timeout: Maximum seconds to wait for capture to stop.
        
        Returns:
            True if stopped successfully, False if timeout.
        
        Example:
            >>> engine.stop()
        """
        with self._state_lock:
            if self._state != EngineState.RUNNING:
                return True
            self._state = EngineState.STOPPING
        
        # Signal capture to stop
        self._stop_event.set()
        
        # Wait for capture thread
        if self._capture_thread and self._capture_thread.is_alive():
            self._capture_thread.join(timeout=timeout)
            
            if self._capture_thread.is_alive():
                # Thread didn't stop in time
                self._last_error = "Capture thread did not stop in time"
                return False
        
        # Stop web integration
        if self.web_integration:
            self.web_integration.stop()
        
        with self._state_lock:
            self._state = EngineState.STOPPED
        
        return True
    
    # =========================================================================
    # Status and Reporting
    # =========================================================================
    
    def get_status(self) -> dict:
        """
        Get current engine status.
        
        Returns:
            dict: Complete status information.
        """
        duration = 0.0
        if self._start_time:
            end = self._stop_time or datetime.now()
            duration = (end - self._start_time).total_seconds()
        
        status = {
            "state": self.state.value,
            "interface": str(self._interface) if self._interface else None,
            "duration_seconds": duration,
            "packets_captured": self.statistics.total_packets,
            "bytes_captured": self.statistics.total_bytes,
            "packets_per_second": self.statistics.packets_per_second,
            "bytes_per_second": self.statistics.bytes_per_second,
            "error": self._last_error
        }
        
        if self.security:
            security_status = self.security.get_status()
            status["security_status"] = security_status["status"]
            status["security_alerts"] = len(self.security.get_all_alerts())
        
        if self.web_integration:
            status["web_integration"] = self.web_integration.get_status()
        
        return status
    
    def get_summary(self) -> dict:
        """
        Get comprehensive capture summary.
        
        Returns:
            dict: Complete capture summary including stats and security.
        """
        summary = {
            "engine": self.get_status(),
            "statistics": self.statistics.get_summary(),
        }
        
        if self.security:
            summary["security"] = self.security.get_summary()
        
        return summary
    
    def get_protocol_distribution(self) -> dict:
        """Get protocol distribution from statistics."""
        return self.statistics.get_protocol_counts()
    
    def get_top_talkers(self, limit: int = 10) -> list:
        """Get top talking IPs."""
        return self.statistics.get_top_talkers(limit)
    
    def get_recent_alerts(self, limit: int = 10) -> list:
        """Get recent security alerts."""
        if self.security:
            return [a.to_dict() for a in self.security.get_recent_alerts(limit)]
        return []


# =============================================================================
# Convenience Functions
# =============================================================================

def create_engine(
    interface: Optional[str] = None,
    enable_security: bool = True,
    store_packets: bool = False,
    bpf_filter: Optional[str] = None
) -> CaptureEngine:
    """
    Create a capture engine with common settings.
    
    Args:
        interface: Network interface. None for auto-detect.
        enable_security: Whether to enable security monitoring.
        store_packets: Whether to store packets in memory.
        bpf_filter: Optional BPF filter string.
    
    Returns:
        Configured CaptureEngine instance.
    
    Example:
        >>> engine = create_engine(enable_security=True)
        >>> engine.start()
    """
    config = CaptureConfig(
        interface=interface,
        enable_security=enable_security,
        store_packets=store_packets,
        bpf_filter=bpf_filter
    )
    return CaptureEngine(config)


def quick_capture(
    count: int = 10,
    interface: Optional[str] = None,
    timeout: Optional[float] = None
) -> List[ParsedPacket]:
    """
    Quickly capture a specific number of packets.
    
    Args:
        count: Number of packets to capture.
        interface: Network interface. None for auto-detect.
        timeout: Capture timeout in seconds.
    
    Returns:
        List of ParsedPacket objects.
    
    Example:
        >>> packets = quick_capture(count=100, timeout=10)
        >>> print(f"Captured {len(packets)} packets")
    """
    config = CaptureConfig(
        interface=interface,
        packet_count=count,
        timeout=timeout,
        store_packets=True,
        enable_security=False
    )
    
    engine = CaptureEngine(config)
    engine.start(blocking=True)
    
    return engine.get_stored_packets()


# =============================================================================
# Module Test
# =============================================================================

if __name__ == "__main__":
    from core_sniffer.utils.formatters import (
        format_statistics_table,
        format_protocol_distribution,
        colorize,
        Color
    )
    
    print("=" * 60)
    print("CAPTURE ENGINE MODULE TEST")
    print("=" * 60)
    
    # Show platform info
    print(get_platform_summary())
    
    # Check permissions
    permissions = check_permissions()
    
    if not permissions["has_permission"]:
        print(f"\n{colorize('⚠️  Permission Check Failed', Color.YELLOW)}")
        print(f"   {permissions['message']}")
        print("\n" + "-" * 60)
        print("To test the capture engine, run this command:")
        print(f"   sudo python3 -m core_sniffer.capture_engine")
        print("-" * 60)
        
        # Still test engine creation
        print("\n--- Testing Engine Creation (without capture) ---")
        
        engine = create_engine()
        print(f"  Engine created: ✓")
        print(f"  State: {engine.state.value}")
        print(f"  Interface: {engine.interface}")
        print(f"  Security enabled: {engine.security is not None}")
        
        print("\n" + "=" * 60)
        print("Engine creation test complete.")
        print("Run with sudo to test actual packet capture.")
        print("=" * 60)
        
    else:
        print(f"\n{colorize('✓ Permission Check Passed', Color.GREEN)}")
        
        # Test actual capture
        print("\n--- Testing Packet Capture ---")
        print("Capturing 10 packets (or 10 second timeout)...")
        print("Generate some network traffic (browse web, ping, etc.)")
        print("-" * 40)
        
        # Create engine with packet storage
        config = CaptureConfig(
            packet_count=10,
            timeout=10.0,
            store_packets=True,
            enable_security=True
        )
        
        engine = CaptureEngine(config)
        
        # Add a simple callback to show packets
        def print_packet(packet: ParsedPacket):
            proto = packet.protocol
            src = f"{packet.src_ip or '?'}:{packet.src_port or ''}"
            dst = f"{packet.dst_ip or '?'}:{packet.dst_port or ''}"
            print(f"  [{proto:6}] {src:25} -> {dst:25}")
        
        def print_alert(alert: SecurityAlert):
            print(f"  {colorize(f'🚨 ALERT: {alert.message}', Color.RED)}")
        
        engine.add_packet_callback(print_packet)
        engine.add_alert_callback(print_alert)
        
        # Start capture (blocking)
        print("\nStarting capture...")
        engine.start(blocking=True)
        
        # Show results
        print("\n" + "-" * 40)
        print(f"Capture complete!")
        print(f"  State: {engine.state.value}")
        
        if engine.last_error:
            print(f"  Error: {engine.last_error}")
        
        # Statistics
        print("\n" + format_statistics_table(
            title="CAPTURE SUMMARY",
            data=engine.statistics.get_display_summary()
        ))
        
        # Protocol distribution
        protocols = engine.get_protocol_distribution()
        if protocols:
            print("\n" + format_protocol_distribution(
                protocols,
                engine.statistics.total_packets
            ))
        
        # Security status
        if engine.security:
            print("\n  Security Status:")
            print("  " + "-" * 40)
            status = engine.security.get_status()
            alerts = engine.security.get_all_alerts()
            print(f"    Status: {status['status']}")
            print(f"    Alerts: {len(alerts)}")
        
        print("\n" + "=" * 60)
        print("Capture engine test complete.")
        print("=" * 60)


