"""
Protocol Parser Module

Decodes network packets across multiple protocol layers:
- Layer 2: Ethernet (MAC addresses)
- Layer 3: IP (IPv4 and IPv6), ARP, ICMP, ICMPv6
- Layer 4: TCP, UDP
- Layer 7: HTTP, DNS, TLS/SSL detection

Provides structured packet data for analysis and display.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Any
from enum import Enum


# =============================================================================
# Constants
# =============================================================================

class Protocol(Enum):
    """Supported protocol identifiers."""
    UNKNOWN = "UNKNOWN"
    ETHERNET = "ETHERNET"
    ARP = "ARP"
    IP = "IP"
    IPV6 = "IPV6"
    ICMP = "ICMP"
    ICMPV6 = "ICMPV6"
    TCP = "TCP"
    UDP = "UDP"
    DNS = "DNS"
    HTTP = "HTTP"
    HTTPS = "HTTPS"
    TLS = "TLS"
    SSH = "SSH"
    FTP = "FTP"
    SMTP = "SMTP"
    DHCP = "DHCP"
    NTP = "NTP"


# Well-known port to protocol mapping
WELL_KNOWN_PORTS = {
    20: Protocol.FTP,
    21: Protocol.FTP,
    22: Protocol.SSH,
    23: "TELNET",
    25: Protocol.SMTP,
    53: Protocol.DNS,
    67: Protocol.DHCP,
    68: Protocol.DHCP,
    80: Protocol.HTTP,
    110: "POP3",
    123: Protocol.NTP,
    143: "IMAP",
    443: Protocol.HTTPS,
    465: "SMTPS",
    587: Protocol.SMTP,
    993: "IMAPS",
    995: "POP3S",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: Protocol.HTTP,
    8443: Protocol.HTTPS,
    27017: "MongoDB",
}

# ICMP type descriptions
ICMP_TYPES = {
    0: "Echo Reply",
    3: "Destination Unreachable",
    4: "Source Quench",
    5: "Redirect",
    8: "Echo Request",
    9: "Router Advertisement",
    10: "Router Solicitation",
    11: "Time Exceeded",
    12: "Parameter Problem",
    13: "Timestamp Request",
    14: "Timestamp Reply",
    17: "Address Mask Request",
    18: "Address Mask Reply",
}

# ICMPv6 type descriptions
ICMPV6_TYPES = {
    1: "Destination Unreachable",
    2: "Packet Too Big",
    3: "Time Exceeded",
    4: "Parameter Problem",
    128: "Echo Request",
    129: "Echo Reply",
    130: "Multicast Listener Query",
    131: "Multicast Listener Report",
    132: "Multicast Listener Done",
    133: "Router Solicitation",
    134: "Router Advertisement",
    135: "Neighbor Solicitation",
    136: "Neighbor Advertisement",
    137: "Redirect",
}

# TCP flag descriptions
TCP_FLAGS = {
    "F": "FIN",
    "S": "SYN",
    "R": "RST",
    "P": "PSH",
    "A": "ACK",
    "U": "URG",
    "E": "ECE",
    "C": "CWR",
}

# DNS record types
DNS_RECORD_TYPES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    255: "ANY",
}


# =============================================================================
# Data Classes
# =============================================================================

@dataclass
class ParsedPacket:
    """
    Structured representation of a parsed network packet.
    
    Attributes:
        timestamp: When the packet was captured.
        size: Total packet size in bytes.
        protocol: Highest-level protocol identified.
        
        # Layer 2 (Ethernet)
        src_mac: Source MAC address.
        dst_mac: Destination MAC address.
        
        # Layer 3 (IP)
        src_ip: Source IP address (IPv4 or IPv6).
        dst_ip: Destination IP address (IPv4 or IPv6).
        ttl: Time to live / hop limit.
        ip_version: IP version (4 or 6).
        
        # Layer 4 (TCP/UDP)
        src_port: Source port number.
        dst_port: Destination port number.
        tcp_flags: TCP flags if applicable.
        tcp_seq: TCP sequence number.
        tcp_ack: TCP acknowledgment number.
        
        # Layer 7 (Application)
        app_protocol: Application-layer protocol.
        app_data: Application-specific data.
        
        # Additional info
        info: Human-readable summary.
        raw_packet: Reference to original packet object.
        warnings: List of parsing warnings.
    """
    # Metadata
    timestamp: datetime = field(default_factory=datetime.now)
    size: int = 0
    protocol: str = "UNKNOWN"
    
    # Layer 2 - Ethernet
    src_mac: Optional[str] = None
    dst_mac: Optional[str] = None
    
    # Layer 3 - IP
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    ttl: Optional[int] = None
    ip_version: Optional[int] = None
    
    # Layer 4 - TCP/UDP
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    tcp_flags: Optional[str] = None
    tcp_seq: Optional[int] = None
    tcp_ack: Optional[int] = None
    
    # Layer 7 - Application
    app_protocol: Optional[str] = None
    app_data: Optional[dict] = None
    
    # Additional
    info: str = ""
    raw_packet: Optional[Any] = None
    warnings: list = field(default_factory=list)
    
    def to_dict(self) -> dict:
        """Convert to dictionary (excludes raw_packet)."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "size": self.size,
            "protocol": self.protocol,
            "src_mac": self.src_mac,
            "dst_mac": self.dst_mac,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "ttl": self.ttl,
            "ip_version": self.ip_version,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "tcp_flags": self.tcp_flags,
            "tcp_seq": self.tcp_seq,
            "tcp_ack": self.tcp_ack,
            "app_protocol": self.app_protocol,
            "app_data": self.app_data,
            "info": self.info,
            "warnings": self.warnings,
        }


# =============================================================================
# Protocol Parser Class
# =============================================================================

class ProtocolParser:
    """
    Multi-layer protocol parser for network packets.
    """
    
    def __init__(self):
        """Initialize the protocol parser."""
        self.supported_protocols = [
            "TCP", "UDP", "ICMP", "ICMPv6", "DNS", "HTTP", "HTTPS", "ARP", "IPv6"
        ]
        self._import_scapy_layers()
    
    def _import_scapy_layers(self):
        """Import Scapy layers for packet parsing."""
        try:
            from scapy.layers.l2 import Ether, ARP
            from scapy.layers.inet import IP, TCP, UDP, ICMP
            from scapy.layers.inet6 import IPv6, ICMPv6ND_NS, ICMPv6ND_NA, ICMPv6ND_RS, ICMPv6ND_RA
            from scapy.layers.dns import DNS, DNSQR, DNSRR
            from scapy.packet import Raw
            
            self._Ether = Ether
            self._ARP = ARP
            self._IP = IP
            self._IPv6 = IPv6
            self._TCP = TCP
            self._UDP = UDP
            self._ICMP = ICMP
            self._DNS = DNS
            self._DNSQR = DNSQR
            self._DNSRR = DNSRR
            self._Raw = Raw
            
            # ICMPv6
            self._ICMPv6ND_NS = ICMPv6ND_NS
            self._ICMPv6ND_NA = ICMPv6ND_NA
            self._ICMPv6ND_RS = ICMPv6ND_RS
            self._ICMPv6ND_RA = ICMPv6ND_RA
            
            # Import general ICMPv6 type
            try:
                from scapy.layers.inet6 import ICMPv6Unknown
                self._ICMPv6Unknown = ICMPv6Unknown
            except ImportError:
                self._ICMPv6Unknown = None
            
            self._scapy_available = True
            
        except ImportError:
            self._scapy_available = False
    
    def parse(self, packet) -> ParsedPacket:
        """
        Parse a Scapy packet and extract structured data.
        """
        if not self._scapy_available:
            return ParsedPacket(
                info="Scapy not available",
                warnings=["Scapy library not installed"]
            )
        
        result = ParsedPacket(
            timestamp=datetime.now(),
            size=len(packet),
            raw_packet=packet
        )
        
        try:
            # Parse each layer
            self._parse_ethernet(packet, result)
            self._parse_arp(packet, result)
            self._parse_ip(packet, result)
            self._parse_ipv6(packet, result)
            self._parse_icmp(packet, result)
            self._parse_icmpv6(packet, result)
            self._parse_tcp(packet, result)
            self._parse_udp(packet, result)
            self._parse_dns(packet, result)
            self._parse_http(packet, result)
            
            # Generate info string if not already set
            if not result.info:
                result.info = self._generate_info(result)
            
        except Exception as e:
            result.warnings.append(f"Parse error: {str(e)}")
        
        return result
    
    def _parse_ethernet(self, packet, result: ParsedPacket):
        """Parse Ethernet layer (Layer 2)."""
        if self._Ether in packet:
            ether = packet[self._Ether]
            result.src_mac = ether.src
            result.dst_mac = ether.dst
    
    def _parse_arp(self, packet, result: ParsedPacket):
        """Parse ARP layer."""
        if self._ARP in packet:
            arp = packet[self._ARP]
            result.protocol = "ARP"
            result.src_ip = arp.psrc
            result.dst_ip = arp.pdst
            
            # ARP operation
            if arp.op == 1:
                result.info = f"Who has {arp.pdst}? Tell {arp.psrc}"
            elif arp.op == 2:
                result.info = f"{arp.psrc} is at {arp.hwsrc}"
            else:
                result.info = f"ARP op={arp.op}"
    
    def _parse_ip(self, packet, result: ParsedPacket):
        """Parse IPv4 layer (Layer 3)."""
        if self._IP in packet:
            ip = packet[self._IP]
            result.src_ip = ip.src
            result.dst_ip = ip.dst
            result.ttl = ip.ttl
            result.ip_version = 4
            
            # Only set protocol to IP if not already set to something more specific
            if result.protocol == "UNKNOWN":
                result.protocol = "IP"
    
    def _parse_ipv6(self, packet, result: ParsedPacket):
        """Parse IPv6 layer (Layer 3)."""
        if self._IPv6 in packet:
            ipv6 = packet[self._IPv6]
            result.src_ip = ipv6.src
            result.dst_ip = ipv6.dst
            result.ttl = ipv6.hlim  # Hop limit in IPv6
            result.ip_version = 6
            
            # Only set protocol if not already set to something more specific
            if result.protocol == "UNKNOWN":
                result.protocol = "IPv6"
    
    def _parse_icmp(self, packet, result: ParsedPacket):
        """Parse ICMP layer (IPv4)."""
        if self._ICMP in packet:
            icmp = packet[self._ICMP]
            result.protocol = "ICMP"
            
            icmp_type = icmp.type
            icmp_code = icmp.code
            
            type_desc = ICMP_TYPES.get(icmp_type, f"Type {icmp_type}")
            result.info = f"{type_desc} (code={icmp_code})"
            
            result.app_data = {
                "icmp_type": icmp_type,
                "icmp_code": icmp_code,
                "type_description": type_desc
            }
    
    def _parse_icmpv6(self, packet, result: ParsedPacket):
        """Parse ICMPv6 layer (IPv6)."""
        # Check for specific ICMPv6 types
        if self._ICMPv6ND_NS in packet:
            result.protocol = "ICMPv6"
            ns = packet[self._ICMPv6ND_NS]
            result.info = f"Neighbor Solicitation for {ns.tgt}"
            result.app_data = {
                "icmpv6_type": "Neighbor Solicitation",
                "target": ns.tgt
            }
        elif self._ICMPv6ND_NA in packet:
            result.protocol = "ICMPv6"
            na = packet[self._ICMPv6ND_NA]
            result.info = f"Neighbor Advertisement for {na.tgt}"
            result.app_data = {
                "icmpv6_type": "Neighbor Advertisement",
                "target": na.tgt
            }
        elif self._ICMPv6ND_RS in packet:
            result.protocol = "ICMPv6"
            result.info = "Router Solicitation"
            result.app_data = {
                "icmpv6_type": "Router Solicitation"
            }
        elif self._ICMPv6ND_RA in packet:
            result.protocol = "ICMPv6"
            result.info = "Router Advertisement"
            result.app_data = {
                "icmpv6_type": "Router Advertisement"
            }
        else:
            # Try to detect generic ICMPv6
            try:
                # Check if packet has ICMPv6 by looking at next header in IPv6
                if self._IPv6 in packet:
                    ipv6 = packet[self._IPv6]
                    # 58 is the protocol number for ICMPv6
                    if ipv6.nh == 58:
                        result.protocol = "ICMPv6"
                        # Try to get type from payload
                        if hasattr(packet, 'type'):
                            icmpv6_type = packet.type
                            type_desc = ICMPV6_TYPES.get(icmpv6_type, f"Type {icmpv6_type}")
                            result.info = type_desc
                        else:
                            result.info = "ICMPv6"
            except Exception:
                pass
    
    def _parse_tcp(self, packet, result: ParsedPacket):
        """Parse TCP layer (Layer 4)."""
        if self._TCP in packet:
            tcp = packet[self._TCP]
            result.protocol = "TCP"
            result.src_port = tcp.sport
            result.dst_port = tcp.dport
            result.tcp_seq = tcp.seq
            result.tcp_ack = tcp.ack
            
            # Parse TCP flags
            result.tcp_flags = self._get_tcp_flags(tcp)
            
            # Check for well-known ports
            app_proto = self._identify_app_protocol(tcp.sport, tcp.dport)
            if app_proto:
                result.app_protocol = app_proto
                if app_proto in ["HTTPS", "TLS"]:
                    result.protocol = "TLS"
                elif app_proto == "HTTP":
                    result.protocol = "HTTP"
                elif app_proto == "SSH":
                    result.protocol = "SSH"
            
            # Set info to flags
            result.info = result.tcp_flags
    
    def _parse_udp(self, packet, result: ParsedPacket):
        """Parse UDP layer (Layer 4)."""
        if self._UDP in packet:
            udp = packet[self._UDP]
            
            # Only set to UDP if not already set to a higher protocol
            if result.protocol in ["IP", "IPv6", "UNKNOWN"]:
                result.protocol = "UDP"
            
            result.src_port = udp.sport
            result.dst_port = udp.dport
            
            # Check for well-known ports
            app_proto = self._identify_app_protocol(udp.sport, udp.dport)
            if app_proto:
                result.app_protocol = app_proto
            
            result.info = f"Len={len(udp.payload)}"
    
    def _parse_dns(self, packet, result: ParsedPacket):
        """Parse DNS layer (Layer 7)."""
        if self._DNS in packet:
            dns = packet[self._DNS]
            result.protocol = "DNS"
            result.app_protocol = "DNS"
            
            dns_data = {
                "id": dns.id,
                "is_response": dns.qr == 1,
                "queries": [],
                "answers": []
            }
            
            # Parse queries
            if dns.qd:
                for i in range(dns.qdcount):
                    try:
                        qname = dns.qd[i].qname.decode() if hasattr(dns.qd[i].qname, 'decode') else str(dns.qd[i].qname)
                        qtype = DNS_RECORD_TYPES.get(dns.qd[i].qtype, str(dns.qd[i].qtype))
                        dns_data["queries"].append({
                            "name": qname.rstrip('.'),
                            "type": qtype
                        })
                    except Exception:
                        pass
            
            # Parse answers
            if dns.an:
                for i in range(dns.ancount):
                    try:
                        rr = dns.an[i]
                        rrname = rr.rrname.decode() if hasattr(rr.rrname, 'decode') else str(rr.rrname)
                        rtype = DNS_RECORD_TYPES.get(rr.type, str(rr.type))
                        rdata = str(rr.rdata) if hasattr(rr, 'rdata') else ""
                        dns_data["answers"].append({
                            "name": rrname.rstrip('.'),
                            "type": rtype,
                            "data": rdata
                        })
                    except Exception:
                        pass
            
            result.app_data = dns_data
            
            # Generate info string
            if dns_data["is_response"]:
                if dns_data["answers"]:
                    ans = dns_data["answers"][0]
                    result.info = f"Response: {ans['name']} -> {ans['data']}"
                else:
                    result.info = "Response: No answers"
            else:
                if dns_data["queries"]:
                    q = dns_data["queries"][0]
                    result.info = f"Query: {q['type']} {q['name']}"
                else:
                    result.info = "Query"
    
    def _parse_http(self, packet, result: ParsedPacket):
        """Parse HTTP data from TCP payload."""
        if self._TCP not in packet:
            return
        
        if self._Raw not in packet:
            return
        
        # Only check ports 80, 8080, or if already identified as HTTP
        tcp = packet[self._TCP]
        if tcp.dport not in [80, 8080] and tcp.sport not in [80, 8080]:
            if result.app_protocol != "HTTP":
                return
        
        try:
            payload = packet[self._Raw].load
            
            # Try to decode as text
            try:
                text = payload.decode('utf-8', errors='ignore')
            except Exception:
                return
            
            if not text:
                return
            
            http_data = {}
            lines = text.split('\r\n')
            first_line = lines[0] if lines else ""
            
            # Check for HTTP request
            if any(first_line.startswith(method) for method in 
                   ['GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ', 
                    'OPTIONS ', 'PATCH ', 'CONNECT ']):
                result.protocol = "HTTP"
                parts = first_line.split(' ')
                http_data = {
                    "type": "request",
                    "method": parts[0] if len(parts) > 0 else "",
                    "path": parts[1] if len(parts) > 1 else "",
                    "version": parts[2] if len(parts) > 2 else ""
                }
                
                # Parse headers
                headers = {}
                for line in lines[1:]:
                    if ': ' in line:
                        key, value = line.split(': ', 1)
                        headers[key.lower()] = value
                
                if 'host' in headers:
                    http_data['host'] = headers['host']
                if 'user-agent' in headers:
                    http_data['user_agent'] = headers['user-agent']
                if 'content-type' in headers:
                    http_data['content_type'] = headers['content-type']
                
                result.info = f"{http_data['method']} {http_data['path']}"
                
            # Check for HTTP response
            elif first_line.startswith('HTTP/'):
                result.protocol = "HTTP"
                parts = first_line.split(' ', 2)
                http_data = {
                    "type": "response",
                    "version": parts[0] if len(parts) > 0 else "",
                    "status_code": int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0,
                    "status_text": parts[2] if len(parts) > 2 else ""
                }
                
                result.info = f"HTTP {http_data['status_code']} {http_data['status_text']}"
            
            if http_data:
                result.app_data = http_data
                result.app_protocol = "HTTP"
                
        except Exception as e:
            result.warnings.append(f"HTTP parse warning: {str(e)}")
    
    def _get_tcp_flags(self, tcp_layer) -> str:
        """
        Extract TCP flags as a readable string.
        
        Args:
            tcp_layer: Scapy TCP layer object.
        
        Returns:
            str: Space-separated flag names (e.g., "SYN ACK").
        """
        flags = []
        
        # Access flags via the flags field
        flag_value = tcp_layer.flags
        
        if flag_value & 0x01:  # FIN
            flags.append("FIN")
        if flag_value & 0x02:  # SYN
            flags.append("SYN")
        if flag_value & 0x04:  # RST
            flags.append("RST")
        if flag_value & 0x08:  # PSH
            flags.append("PSH")
        if flag_value & 0x10:  # ACK
            flags.append("ACK")
        if flag_value & 0x20:  # URG
            flags.append("URG")
        if flag_value & 0x40:  # ECE
            flags.append("ECE")
        if flag_value & 0x80:  # CWR
            flags.append("CWR")
        
        return " ".join(flags) if flags else "No Flags"
    
    def _identify_app_protocol(
        self, 
        src_port: int, 
        dst_port: int
    ) -> Optional[str]:
        """
        Identify application protocol based on port numbers.
        
        Args:
            src_port: Source port number.
            dst_port: Destination port number.
        
        Returns:
            Optional[str]: Protocol name if identified, None otherwise.
        """
        # Check destination port first (more likely to be the server)
        if dst_port in WELL_KNOWN_PORTS:
            proto = WELL_KNOWN_PORTS[dst_port]
            return proto.value if isinstance(proto, Protocol) else proto
        
        # Check source port (response from server)
        if src_port in WELL_KNOWN_PORTS:
            proto = WELL_KNOWN_PORTS[src_port]
            return proto.value if isinstance(proto, Protocol) else proto
        
        return None
    
    def _generate_info(self, result: ParsedPacket) -> str:
        """
        Generate a human-readable info string for the packet.
        
        Args:
            result: The parsed packet data.
        
        Returns:
            str: Info string.
        """
        if result.protocol == "TCP" and result.tcp_flags:
            return result.tcp_flags
        elif result.protocol == "UDP":
            return f"UDP Len={result.size}"
        elif result.protocol in ["ICMP", "ICMPv6"]:
            return result.info or result.protocol
        elif result.protocol == "ARP":
            return result.info or "ARP"
        elif result.protocol == "IPv6":
            return "IPv6 packet"
        else:
            return result.protocol
    
    def get_protocol_stats(self, packets: list) -> dict:
        """
        Calculate protocol distribution from a list of parsed packets.
        
        Args:
            packets: List of ParsedPacket objects.
        
        Returns:
            dict: Protocol name -> count mapping.
        """
        stats = {}
        for pkt in packets:
            proto = pkt.protocol
            stats[proto] = stats.get(proto, 0) + 1
        return stats


# =============================================================================
# Utility Functions
# =============================================================================

def get_service_name(port: int) -> str:
    """
    Get the service name for a well-known port.
    
    Args:
        port: Port number.
    
    Returns:
        str: Service name or port number as string.
    
    Example:
        >>> get_service_name(443)
        'HTTPS'
        >>> get_service_name(12345)
        '12345'
    """
    if port in WELL_KNOWN_PORTS:
        proto = WELL_KNOWN_PORTS[port]
        return proto.value if isinstance(proto, Protocol) else proto
    return str(port)


def is_private_ip(ip: str) -> bool:
    """
    Check if an IP address is in a private range.
    
    Args:
        ip: IP address string (IPv4 or IPv6).
    
    Returns:
        bool: True if private, False otherwise.
    
    Example:
        >>> is_private_ip("192.168.1.1")
        True
        >>> is_private_ip("8.8.8.8")
        False
        >>> is_private_ip("fe80::1")
        True
    """
    if not ip:
        return False
    
    # IPv6 private ranges
    if ':' in ip:
        # Link-local (fe80::/10)
        if ip.lower().startswith('fe80:'):
            return True
        # Unique local (fc00::/7)
        if ip.lower().startswith('fc') or ip.lower().startswith('fd'):
            return True
        # Loopback (::1)
        if ip == '::1':
            return True
        return False
    
    # IPv4 private ranges
    try:
        parts = [int(p) for p in ip.split('.')]
        if len(parts) != 4:
            return False
        
        # 10.0.0.0/8
        if parts[0] == 10:
            return True
        
        # 172.16.0.0/12
        if parts[0] == 172 and 16 <= parts[1] <= 31:
            return True
        
        # 192.168.0.0/16
        if parts[0] == 192 and parts[1] == 168:
            return True
        
        # 127.0.0.0/8 (localhost)
        if parts[0] == 127:
            return True
        
        return False
    
    except Exception:
        return False


def is_broadcast_mac(mac: str) -> bool:
    """
    Check if a MAC address is a broadcast address.
    
    Args:
        mac: MAC address string.
    
    Returns:
        bool: True if broadcast, False otherwise.
    """
    if not mac:
        return False
    return mac.lower().replace(":", "").replace("-", "") == "ffffffffffff"


def is_multicast_ip(ip: str) -> bool:
    """
    Check if an IP address is a multicast address.
    
    Args:
        ip: IP address string (IPv4 or IPv6).
    
    Returns:
        bool: True if multicast.
    """
    if not ip:
        return False
    
    # IPv6 multicast (ff00::/8)
    if ':' in ip:
        return ip.lower().startswith('ff')
    
    # IPv4 multicast (224.0.0.0 - 239.255.255.255)
    try:
        first_octet = int(ip.split('.')[0])
        return 224 <= first_octet <= 239
    except Exception:
        return False


# =============================================================================
# Module Test
# =============================================================================

if __name__ == "__main__":
    print("=" * 60)
    print("PROTOCOL PARSER MODULE TEST")
    print("=" * 60)
    
    # Test utility functions
    print("\n--- Service Name Lookup ---")
    test_ports = [22, 53, 80, 443, 3306, 8080, 12345]
    for port in test_ports:
        print(f"  Port {port:>5} = {get_service_name(port)}")
    
    print("\n--- Private IP Check ---")
    test_ips = ["192.168.1.1", "10.0.0.1", "172.16.0.1", "8.8.8.8", "127.0.0.1", 
                "fe80::1", "2001:db8::1", "::1"]
    for ip in test_ips:
        status = "Private" if is_private_ip(ip) else "Public"
        print(f"  {ip:>20} = {status}")
    
    print("\n--- Multicast IP Check ---")
    test_ips = ["224.0.0.1", "239.255.255.255", "192.168.1.1", "ff02::1", "fe80::1"]
    for ip in test_ips:
        status = "Multicast" if is_multicast_ip(ip) else "Unicast"
        print(f"  {ip:>20} = {status}")
    
    # Test ParsedPacket
    print("\n--- ParsedPacket Dataclass ---")
    test_packet = ParsedPacket(
        protocol="TCP",
        src_ip="192.168.1.100",
        dst_ip="10.0.0.1",
        src_port=54321,
        dst_port=443,
        size=1500,
        tcp_flags="SYN ACK",
        info="SYN ACK"
    )
    print(f"  Protocol: {test_packet.protocol}")
    print(f"  Source:   {test_packet.src_ip}:{test_packet.src_port}")
    print(f"  Dest:     {test_packet.dst_ip}:{test_packet.dst_port}")
    print(f"  Size:     {test_packet.size} bytes")
    print(f"  Info:     {test_packet.info}")
    
    # Test ProtocolParser initialization
    print("\n--- ProtocolParser ---")
    parser = ProtocolParser()
    print(f"  Scapy Available: {parser._scapy_available}")
    print(f"  Supported Protocols: {', '.join(parser.supported_protocols)}")
    
    print("\n" + "=" * 60)
    print("Module test complete. Now supports IPv4 and IPv6!")
    print("=" * 60)