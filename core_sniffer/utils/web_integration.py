"""
Web Integration Module

Sends captured packets and alerts to the web platform via HTTP POST.
Runs in a background thread to avoid blocking packet capture.
"""

import threading
import queue
import time
import json
from typing import Optional, Dict, Any
from datetime import datetime

# Try to import requests, handle if not installed
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


# =============================================================================
# Configuration
# =============================================================================

DEFAULT_WEB_URL = "http://127.0.0.1:8000"
INGEST_ENDPOINT = "/api/ingest"
BATCH_SIZE = 10
BATCH_TIMEOUT = 0.5  # seconds
MAX_QUEUE_SIZE = 1000
REQUEST_TIMEOUT = 2  # seconds


# =============================================================================
# Web Integration Class
# =============================================================================

class WebIntegration:
    """
    Handles communication between core sniffer and web platform.
    
    Batches packets and sends them asynchronously to avoid
    blocking the packet capture loop.
    
    Example:
        >>> web = WebIntegration("http://localhost:8000")
        >>> web.start()
        >>> web.send_packet(parsed_packet)
        >>> web.stop()
    """
    
    def __init__(
        self,
        base_url: str = DEFAULT_WEB_URL,
        enabled: bool = True,
        verbose: bool = False
    ):
        """
        Initialize web integration.
        
        Args:
            base_url: Base URL of the web platform.
            enabled: Whether to actually send data.
            verbose: Whether to print status messages.
        """
        self.base_url = base_url.rstrip('/')
        self.ingest_url = f"{self.base_url}{INGEST_ENDPOINT}"
        self.enabled = enabled and REQUESTS_AVAILABLE
        self.verbose = verbose
        
        # Queue for outgoing packets
        self.packet_queue = queue.Queue(maxsize=MAX_QUEUE_SIZE)
        self.alert_queue = queue.Queue(maxsize=100)
        
        # Worker thread
        self._worker_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        
        # Statistics
        self.packets_sent = 0
        self.packets_failed = 0
        self.alerts_sent = 0
        self.last_error: Optional[str] = None
        self.connected = False
        
        # Check if requests is available
        if not REQUESTS_AVAILABLE:
            self.last_error = "requests library not installed. Run: pip install requests"
    
    def start(self) -> bool:
        """
        Start the background sender thread.
        
        Returns:
            True if started successfully.
        """
        if not self.enabled:
            return False
        
        if self._worker_thread and self._worker_thread.is_alive():
            return True  # Already running
        
        self._stop_event.clear()
        self._worker_thread = threading.Thread(
            target=self._worker_loop,
            daemon=True,
            name="WebIntegration-Worker"
        )
        self._worker_thread.start()
        
        # Test connection
        self._test_connection()
        
        return True
    
    def stop(self):
        """Stop the background sender thread."""
        self._stop_event.set()
        
        if self._worker_thread and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=2.0)
    
    def _test_connection(self):
        """Test if web platform is reachable."""
        try:
            response = requests.get(
                f"{self.base_url}/api/mode",
                timeout=REQUEST_TIMEOUT
            )
            self.connected = response.status_code == 200
        except Exception:
            self.connected = False
    
    def _worker_loop(self):
        """Background worker that sends batched packets."""
        batch = []
        last_send_time = time.time()
        
        while not self._stop_event.is_set():
            try:
                # Try to get a packet (with timeout)
                try:
                    packet = self.packet_queue.get(timeout=0.1)
                    batch.append(packet)
                except queue.Empty:
                    pass
                
                # Send batch if full or timeout reached
                current_time = time.time()
                should_send = (
                    len(batch) >= BATCH_SIZE or
                    (len(batch) > 0 and current_time - last_send_time >= BATCH_TIMEOUT)
                )
                
                if should_send:
                    self._send_batch(batch)
                    batch = []
                    last_send_time = current_time
                
                # Check for alerts (higher priority)
                self._process_alerts()
                
            except Exception as e:
                self.last_error = str(e)
                time.sleep(0.1)
        
        # Send remaining packets before stopping
        if batch:
            self._send_batch(batch)
    
    def _send_batch(self, packets: list):
        """Send a batch of packets to the web platform."""
        if not packets:
            return
        
        try:
            response = requests.post(
                self.ingest_url,
                json={"packets": packets},
                timeout=REQUEST_TIMEOUT,
                headers={"Content-Type": "application/json"}
            )
            
            if response.status_code == 200:
                self.packets_sent += len(packets)
                self.connected = True
            else:
                self.packets_failed += len(packets)
                self.last_error = f"HTTP {response.status_code}"
                
        except requests.exceptions.ConnectionError:
            self.packets_failed += len(packets)
            self.connected = False
            self.last_error = "Connection refused - is web platform running?"
            
        except requests.exceptions.Timeout:
            self.packets_failed += len(packets)
            self.last_error = "Request timeout"
            
        except Exception as e:
            self.packets_failed += len(packets)
            self.last_error = str(e)
    
    def _process_alerts(self):
        """Process and send any queued alerts."""
        while not self.alert_queue.empty():
            try:
                alert = self.alert_queue.get_nowait()
                self._send_alert(alert)
            except queue.Empty:
                break
    
    def _send_alert(self, alert: dict):
        """Send a single alert to the web platform."""
        try:
            response = requests.post(
                self.ingest_url,
                json={"alert": alert},
                timeout=REQUEST_TIMEOUT,
                headers={"Content-Type": "application/json"}
            )
            
            if response.status_code == 200:
                self.alerts_sent += 1
                
        except Exception as e:
            self.last_error = str(e)
    
    def send_packet(self, parsed_packet, is_malicious = False) -> bool:
        """
        Queue a packet for sending to web platform.
        """
        if not self.enabled:
            return False
        
        try:
            # Convert ParsedPacket to dict for JSON serialization
            packet_dict = self._packet_to_dict(parsed_packet)
            packet_dict['is_malicious'] = is_malicious
            
            # Try to add to queue (non-blocking)
            self.packet_queue.put_nowait(packet_dict)
            return True
            
        except queue.Full:
            # Queue is full, drop packet
            return False
        except Exception:
            return False
    
    def send_alert(self, alert) -> bool:
        """
        Queue an alert for sending to web platform.
        
        Args:
            alert: SecurityAlert object.
        
        Returns:
            True if queued successfully.
        """
        if not self.enabled:
            return False
        
        try:
            # Convert alert to dict
            if hasattr(alert, 'to_dict'):
                alert_dict = alert.to_dict()
            else:
                alert_dict = dict(alert)
            
            self.alert_queue.put_nowait(alert_dict)
            return True
            
        except queue.Full:
            return False
        except Exception:
            return False
    
    def _packet_to_dict(self, packet) -> dict:
        """Convert ParsedPacket to JSON-serializable dict."""
        
        # Determine service from port
        service = self._get_service_name(packet.dst_port or packet.src_port)
        
        return {
            "timestamp": packet.timestamp.isoformat() if hasattr(packet.timestamp, 'isoformat') else str(packet.timestamp),
            "protocol": packet.protocol or "UNKNOWN",
            "src_ip": packet.src_ip or "0.0.0.0",
            "dst_ip": packet.dst_ip or "0.0.0.0",
            "src_port": packet.src_port or 0,
            "dst_port": packet.dst_port or 0,
            "size": packet.size or 0,
            "packets": 1,
            "info": packet.info or "",
            "service": service,
        }
    
    def _get_service_name(self, port: Optional[int]) -> str:
        """Get service name from port number."""
        if not port:
            return "--"
        
        services = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            143: "IMAP",
            443: "HTTPS",
            993: "IMAPS",
            995: "POP3S",
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL",
            8080: "HTTP",
            8443: "HTTPS"
        }
        
        return services.get(port, "--")
    
    def get_status(self) -> dict:
        """Get integration status."""
        return {
            "enabled": self.enabled,
            "connected": self.connected,
            "base_url": self.base_url,
            "packets_sent": self.packets_sent,
            "packets_failed": self.packets_failed,
            "alerts_sent": self.alerts_sent,
            "queue_size": self.packet_queue.qsize(),
            "last_error": self.last_error
        }


# =============================================================================
# Convenience Functions
# =============================================================================

def create_web_integration(
    base_url: str = DEFAULT_WEB_URL,
    enabled: bool = True,
    verbose: bool = False
) -> WebIntegration:
    """
    Create and start a web integration instance.
    
    Args:
        base_url: Web platform URL.
        enabled: Whether to enable sending.
        verbose: Whether to print status.
    
    Returns:
        Started WebIntegration instance.
    """
    integration = WebIntegration(
        base_url=base_url,
        enabled=enabled,
        verbose=verbose
    )
    integration.start()
    return integration


# =============================================================================
# Module Test
# =============================================================================

if __name__ == "__main__":
    print("=" * 60)
    print("WEB INTEGRATION MODULE TEST")
    print("=" * 60)
    
    if not REQUESTS_AVAILABLE:
        print("\n[ERROR] requests library not installed")
        print("Run: pip install requests")
        exit(1)
    
    print("\nTesting connection to web platform...")
    
    integration = WebIntegration(verbose=True)
    integration.start()
    
    print(f"\nStatus: {integration.get_status()}")
    
    if integration.connected:
        print("\nSending test packet...")
        
        # Create a fake packet for testing
        class FakePacket:
            timestamp = datetime.now()
            protocol = "TCP"
            src_ip = "192.168.1.100"
            dst_ip = "8.8.8.8"
            src_port = 54321
            dst_port = 443
            size = 1500
            info = "Test packet from web_integration module"
        
        integration.send_packet(FakePacket())
        time.sleep(1)  # Wait for send
        
        print(f"Final status: {integration.get_status()}")
    else:
        print("\n[WARNING] Web platform not reachable")
        print("Make sure web platform is running:")
        print("  cd web_platform && python app.py")
    
    integration.stop()
    
    print("\n" + "=" * 60)
    print("Test complete.")
    print("=" * 60)