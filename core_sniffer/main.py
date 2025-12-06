"""
Main Entry Point

Command-line interface for the Cross-Platform Packet Sniffer.
Run with: sudo python3 -m core_sniffer.main

Features:
- Real-time packet display with color coding
- Live statistics
- Security alert notifications
- Web platform integration
- Graceful shutdown with Ctrl+C
- Session summary on exit
"""

import sys
import signal
import argparse
from datetime import datetime
from typing import Optional

from core_sniffer.capture_engine import CaptureEngine, CaptureConfig
from core_sniffer.protocol_parser import ParsedPacket
from core_sniffer.security_monitor import SecurityAlert, ThreatThresholds
from core_sniffer.utils.legal import check_legal_compliance, log_session_start
from core_sniffer.utils.platform_detect import (
    get_os_info,
    get_default_interface,
    get_all_interfaces,
    check_permissions,
    check_npcap_installed
)
from core_sniffer.utils.formatters import (
    colorize,
    colorize_protocol,
    colorize_severity,
    Color,
    format_bytes,
    format_duration,
    format_packet_line,
    format_alert_box,
    format_statistics_table,
    format_protocol_distribution
)


# =============================================================================
# Constants
# =============================================================================

BANNER = """
============================================================
   PACKET SNIFFER - Cross-Platform Network Analyzer v1.0.0
============================================================
"""


# =============================================================================
# Packet Sniffer CLI Class
# =============================================================================

class PacketSnifferCLI:
    """
    Command-line interface for the packet sniffer.
    
    Handles user interaction, display formatting, and capture management.
    """
    
    def __init__(self):
        """Initialize the CLI."""
        self.engine: Optional[CaptureEngine] = None
        self.args: Optional[argparse.Namespace] = None
        self.packet_count = 0
        self.running = False
        
        # Set up signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """Handle interrupt signals gracefully."""
        if self.running:
            print(f"\n\n{colorize('Stopping capture...', Color.YELLOW)}")
            self.running = False
            if self.engine:
                self.engine.stop()
    
    def parse_arguments(self) -> argparse.Namespace:
        """Parse command-line arguments."""
        parser = argparse.ArgumentParser(
            description="Cross-Platform Packet Sniffer & Network Analyzer",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  sudo python3 -m core_sniffer.main                    # Capture on default interface
  sudo python3 -m core_sniffer.main -i en0             # Capture on specific interface
  sudo python3 -m core_sniffer.main -c 100             # Capture 100 packets
  sudo python3 -m core_sniffer.main -f "tcp port 80"   # Capture HTTP traffic only
  sudo python3 -m core_sniffer.main --no-security      # Disable security monitoring
  sudo python3 -m core_sniffer.main --no-web           # Disable web platform integration
  python3 -m core_sniffer.main --list-interfaces       # List available interfaces
            """
        )
        
        parser.add_argument(
            "-i", "--interface",
            type=str,
            default=None,
            help="Network interface to capture from (default: auto-detect)"
        )
        
        parser.add_argument(
            "-c", "--count",
            type=int,
            default=0,
            help="Number of packets to capture (default: unlimited)"
        )
        
        parser.add_argument(
            "-t", "--timeout",
            type=float,
            default=None,
            help="Capture timeout in seconds (default: none)"
        )
        
        parser.add_argument(
            "-f", "--filter",
            type=str,
            default=None,
            help="BPF filter string (e.g., 'tcp port 80')"
        )
        
        parser.add_argument(
            "--no-security",
            action="store_true",
            help="Disable security monitoring"
        )
        
        parser.add_argument(
            "--quiet",
            action="store_true",
            help="Minimal output (no banner, less verbose)"
        )
        
        parser.add_argument(
            "--list-interfaces",
            action="store_true",
            help="List available network interfaces and exit"
        )
        
        parser.add_argument(
            "--no-web",
            action="store_true",
            help="Disable sending packets to web platform"
        )
        
        parser.add_argument(
            "--web-url",
            type=str,
            default="http://127.0.0.1:8000",
            help="URL of the web platform (default: http://127.0.0.1:8000)"
        )
        parser.add_argument(
            "--accept-legal",
            action="store_true",
            help="Accept legal terms without prompting (for automation)"
        )
        
        return parser.parse_args()
    
    def print_banner(self):
        """Print the application banner."""
        if self.args.quiet:
            return
        
        print(colorize(BANNER, Color.CYAN))
    
    def list_interfaces(self):
        """List all available network interfaces."""
        print("\n" + "=" * 50)
        print("  AVAILABLE NETWORK INTERFACES")
        print("=" * 50)
        
        try:
            interfaces = get_all_interfaces()
            default = get_default_interface()
            
            for iface in interfaces:
                status = colorize("[DEFAULT]", Color.GREEN) if iface.name == default else ""
                print(f"  {iface.name:<15} {status:<20} {iface.description}")
            
            print("=" * 50)
            print(f"\n  Use: sudo python3 -m core_sniffer.main -i <interface>")
            
        except Exception as e:
            print(f"  Error listing interfaces: {e}")
    
    def check_environment(self) -> bool:
        """
        Check if the environment is ready for packet capture.
        
        Returns:
            True if ready, False otherwise.
        """
        os_info = get_os_info()
        
        print("-" * 50)
        print("  ENVIRONMENT CHECK")
        print("-" * 50)
        
        # OS Info
        print(f"  OS:           {os_info.name} ({os_info.architecture})")
        
        # Interface
        interface = self.args.interface or get_default_interface()
        print(f"  Interface:    {interface}")
        
        # Permissions
        permissions = check_permissions()
        if permissions["has_permission"]:
            print(f"  Permissions:  {colorize('OK', Color.GREEN)}")
        else:
            print(f"  Permissions:  {colorize('Required', Color.RED)}")
            print(f"\n  {colorize('Error:', Color.RED)} {permissions['message']}")
            return False
        
        # Npcap check (Windows only)
        if os_info.requires_npcap:
            npcap = check_npcap_installed()
            if npcap["installed"]:
                print(f"  Npcap:        {colorize('Installed', Color.GREEN)}")
            else:
                print(f"  Npcap:        {colorize('Required', Color.RED)}")
                print(f"\n  {colorize('Error:', Color.RED)} {npcap['message']}")
                return False
        
        # Security monitoring
        security_status = "Enabled" if not self.args.no_security else "Disabled"
        print(f"  Security:     {security_status}")
        
        # Filter
        if self.args.filter:
            print(f"  Filter:       {self.args.filter}")
        
        # Web integration
        if not self.args.no_web:
            print(f"  Web Platform: {self.args.web_url}")
        else:
            print(f"  Web Platform: Disabled")
        
        print("-" * 50)
        
        return True
    
    def packet_callback(self, packet: ParsedPacket):
        """Callback for each captured packet."""
        self.packet_count += 1
        
        # Format and print packet
        line = format_packet_line(
            protocol=packet.protocol,
            source_ip=packet.src_ip or "?",
            dest_ip=packet.dst_ip or "?",
            source_port=packet.src_port,
            dest_port=packet.dst_port,
            size=packet.size,
            info=packet.info
        )
        
        print(line)
    
    def alert_callback(self, alert: SecurityAlert):
        """Callback for security alerts."""
        print(format_alert_box(
            alert_type=alert.alert_type.value,
            severity=alert.severity.value,
            message=alert.message,
            source_ip=alert.source_ip,
            timestamp=alert.timestamp,
            details=alert.details
        ))
    
    def print_capture_header(self):
        """Print the capture session header."""
        interface = self.args.interface or get_default_interface()
        
        print("\n" + "=" * 70)
        print(f"  CAPTURING ON: {colorize(interface, Color.CYAN)}")
        print("=" * 70)
        print(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        if self.args.count > 0:
            print(f"  Packet Limit: {self.args.count}")
        
        if self.args.timeout:
            print(f"  Timeout: {self.args.timeout} seconds")
        
        if self.args.filter:
            print(f"  Filter: {self.args.filter}")
        
        # Show web integration status
        if not self.args.no_web:
            if self.engine and self.engine.web_integration:
                if self.engine.web_integration.connected:
                    print(f"  Web Platform: {colorize('Connected', Color.GREEN)}")
                else:
                    print(f"  Web Platform: {colorize('Not reachable', Color.YELLOW)}")
        
        print("=" * 70)
        print(f"  Press {colorize('Ctrl+C', Color.YELLOW)} to stop capture")
        print("=" * 70 + "\n")
    
    def print_session_summary(self):
        """Print the session summary."""
        if not self.engine:
            return
        
        print("\n")
        
        # Statistics summary
        stats = self.engine.statistics.get_display_summary()
        print(format_statistics_table(
            title="SESSION SUMMARY",
            data=stats
        ))
        
        # Protocol distribution
        protocols = self.engine.get_protocol_distribution()
        if protocols:
            print("\n" + format_protocol_distribution(
                protocols,
                self.engine.statistics.total_packets
            ))
        
        # Top sources
        top_sources = self.engine.statistics.get_top_sources(5)
        if top_sources:
            print("\n  Top Source IPs:")
            print("  " + "-" * 40)
            for ip, count in top_sources:
                print(f"    {ip:<25} {count:>8} packets")
        
        # Top destination ports
        top_ports = self.engine.statistics.get_top_dest_ports(5)
        if top_ports:
            print("\n  Top Destination Ports:")
            print("  " + "-" * 40)
            from core_sniffer.protocol_parser import get_service_name
            for port, count in top_ports:
                service = get_service_name(port)
                print(f"    {port:>5} ({service:<12}) {count:>8} packets")
        
        # Security summary
        if self.engine.security:
            alerts = self.engine.security.get_all_alerts()
            status = self.engine.security.get_status()
            
            print("\n  Security Summary:")
            print("  " + "-" * 40)
            
            status_color = {
                "NORMAL": Color.GREEN,
                "WARNING": Color.YELLOW,
                "CRITICAL": Color.RED
            }.get(status["status"], Color.WHITE)
            
            print(f"    Status: {colorize(status['status'], status_color)}")
            print(f"    Total Alerts: {len(alerts)}")
            
            if alerts:
                print("\n    Recent Alerts:")
                for alert in alerts[-3:]:
                    severity_color = {
                        "LOW": Color.GREEN,
                        "MEDIUM": Color.YELLOW,
                        "HIGH": Color.RED,
                        "CRITICAL": Color.BRIGHT_RED
                    }.get(alert.severity.value, Color.WHITE)
                    
                    print(f"      - [{colorize(alert.severity.value, severity_color)}] "
                          f"{alert.alert_type.value}: {alert.source_ip}")
        
        # Web integration summary
        if self.engine.web_integration:
            web_status = self.engine.web_integration.get_status()
            print("\n  Web Integration:")
            print("  " + "-" * 40)
            
            if web_status['connected']:
                print(f"    Connected: {colorize('Yes', Color.GREEN)}")
            else:
                print(f"    Connected: {colorize('No', Color.YELLOW)}")
            
            print(f"    Packets Sent: {web_status['packets_sent']}")
            
            if web_status['packets_failed'] > 0:
                print(f"    Packets Failed: {colorize(str(web_status['packets_failed']), Color.RED)}")
            
            if web_status['alerts_sent'] > 0:
                print(f"    Alerts Sent: {web_status['alerts_sent']}")
            
            if web_status['last_error'] and not web_status['connected']:
                print(f"    Last Error: {web_status['last_error']}")
        
        print("\n" + "=" * 50)
        print("  Capture session ended.")
        print("=" * 50 + "\n")
    
    def run(self) -> int:
        """
        Run the packet sniffer CLI.
        
        Returns:
            Exit code (0 for success, non-zero for error).
        """
        # Parse arguments
        self.args = self.parse_arguments()
        
        # List interfaces mode
        if self.args.list_interfaces:
            self.list_interfaces()
            return 0
        
        # Print banner
        self.print_banner()

        # Legal compliance check
        if not self.args.quiet:
            print()  # Add spacing
            # Skip prompt if --accept-legal flag is used
            skip_consent = self.args.accept_legal
            if not check_legal_compliance(show_full_notice=not skip_consent, require_consent=not skip_consent):
                return 1
        elif not self.args.accept_legal:
            # Quiet mode still requires --accept-legal
            print("Error: --quiet mode requires --accept-legal flag")
            return 1
        
        # Check environment
        if not self.check_environment():
            return 1
        
        # Check environment
        if not self.check_environment():
            return 1
        
        # Create capture configuration
        config = CaptureConfig(
            interface=self.args.interface,
            packet_count=self.args.count,
            timeout=self.args.timeout,
            bpf_filter=self.args.filter,
            enable_security=not self.args.no_security,
            store_packets=False,
            enable_web=not self.args.no_web,
            web_url=self.args.web_url
        )
        
        # Create engine
        self.engine = CaptureEngine(config)
        
        # Register callbacks
        self.engine.add_packet_callback(self.packet_callback)
        
        if not self.args.no_security:
            self.engine.add_alert_callback(self.alert_callback)
        
        # Print capture header
        self.print_capture_header()

        # Log session start
        interface = self.args.interface or get_default_interface()
        log_session_start(interface)
        
        # Start capture
        self.running = True
        
        try:
            success = self.engine.start(blocking=True)
            
            if not success:
                error = self.engine.last_error or "Unknown error"
                print(f"\n{colorize('Error:', Color.RED)} {error}")
                return 1
                
        except KeyboardInterrupt:
            pass
        
        finally:
            self.running = False
            
            # Ensure engine is stopped
            if self.engine and self.engine.is_running:
                self.engine.stop()
            
            # Print summary
            self.print_session_summary()
        
        return 0


# =============================================================================
# Entry Point
# =============================================================================

def main() -> int:
    """Main entry point."""
    cli = PacketSnifferCLI()
    return cli.run()


if __name__ == "__main__":
    sys.exit(main())