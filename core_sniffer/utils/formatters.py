"""
Formatters Module

Provides formatting utilities for packet display, including:
- Color-coded terminal output (cross-platform)
- Packet data formatting
- Byte size formatting
- Timestamp formatting
- Table formatting for statistics

Supports:
    - macOS/Linux terminals with ANSI colors
    - Windows terminals (with colorama fallback)
"""

import sys
from datetime import datetime
from typing import Optional, Union
from dataclasses import dataclass
from enum import Enum


# =============================================================================
# Terminal Color Support
# =============================================================================

class Color(Enum):
    """
    ANSI color codes for terminal output.
    
    Usage:
        print(f"{Color.RED.value}Error!{Color.RESET.value}")
    """
    # Reset
    RESET = "\033[0m"
    
    # Regular Colors
    BLACK = "\033[30m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"
    
    # Bright/Bold Colors
    BRIGHT_BLACK = "\033[90m"
    BRIGHT_RED = "\033[91m"
    BRIGHT_GREEN = "\033[92m"
    BRIGHT_YELLOW = "\033[93m"
    BRIGHT_BLUE = "\033[94m"
    BRIGHT_MAGENTA = "\033[95m"
    BRIGHT_CYAN = "\033[96m"
    BRIGHT_WHITE = "\033[97m"
    
    # Styles
    BOLD = "\033[1m"
    DIM = "\033[2m"
    UNDERLINE = "\033[4m"


# Protocol to color mapping
PROTOCOL_COLORS = {
    "TCP": Color.BLUE,
    "UDP": Color.GREEN,
    "HTTP": Color.YELLOW,
    "HTTPS": Color.BRIGHT_YELLOW,
    "DNS": Color.MAGENTA,
    "ICMP": Color.CYAN,
    "ARP": Color.BRIGHT_CYAN,
    "TLS": Color.BRIGHT_YELLOW,
    "SSH": Color.BRIGHT_MAGENTA,
    "FTP": Color.BRIGHT_GREEN,
    "SMTP": Color.BRIGHT_BLUE,
    "UNKNOWN": Color.WHITE,
}

# Severity to color mapping
SEVERITY_COLORS = {
    "LOW": Color.GREEN,
    "MEDIUM": Color.YELLOW,
    "HIGH": Color.RED,
    "CRITICAL": Color.BRIGHT_RED,
}


def _supports_color() -> bool:
    """
    Check if the terminal supports ANSI color codes.
    
    Returns:
        bool: True if colors are supported, False otherwise.
    """
    # Check if stdout is a terminal
    if not hasattr(sys.stdout, "isatty"):
        return False
    
    if not sys.stdout.isatty():
        return False
    
    # Windows needs special handling
    if sys.platform == "win32":
        try:
            # Enable ANSI support on Windows 10+
            import ctypes
            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleMode(
                kernel32.GetStdHandle(-11),
                7
            )
            return True
        except Exception:
            return False
    
    # macOS and Linux support colors by default
    return True


# Global flag for color support
COLORS_ENABLED = _supports_color()


def colorize(text: str, color: Color) -> str:
    """
    Apply color to text if terminal supports it.
    
    Args:
        text: The text to colorize.
        color: The Color enum value to apply.
    
    Returns:
        str: Colorized text if supported, plain text otherwise.
    
    Example:
        >>> print(colorize("Hello", Color.GREEN))
        Hello  # (in green if terminal supports it)
    """
    if COLORS_ENABLED:
        return f"{color.value}{text}{Color.RESET.value}"
    return text


def colorize_protocol(protocol: str) -> str:
    """
    Apply protocol-specific color to text.
    
    Args:
        protocol: The protocol name (e.g., 'TCP', 'UDP').
    
    Returns:
        str: Colorized protocol name.
    
    Example:
        >>> print(colorize_protocol("TCP"))
        TCP  # (in blue)
    """
    color = PROTOCOL_COLORS.get(protocol.upper(), Color.WHITE)
    return colorize(protocol, color)


def colorize_severity(severity: str, text: Optional[str] = None) -> str:
    """
    Apply severity-specific color to text.
    
    Args:
        severity: The severity level ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL').
        text: Optional text to colorize. If None, colorizes the severity itself.
    
    Returns:
        str: Colorized text.
    
    Example:
        >>> print(colorize_severity("HIGH", "Warning!"))
        Warning!  # (in red)
    """
    color = SEVERITY_COLORS.get(severity.upper(), Color.WHITE)
    display_text = text if text is not None else severity
    return colorize(display_text, color)


# =============================================================================
# Size Formatting
# =============================================================================

def format_bytes(num_bytes: Union[int, float], precision: int = 2) -> str:
    """
    Convert bytes to human-readable format.
    
    Args:
        num_bytes: Number of bytes.
        precision: Decimal places for the result.
    
    Returns:
        str: Formatted string (e.g., '1.50 MB').
    
    Example:
        >>> format_bytes(1536)
        '1.50 KB'
        >>> format_bytes(1048576)
        '1.00 MB'
    """
    if num_bytes < 0:
        return "0 B"
    
    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    unit_index = 0
    size = float(num_bytes)
    
    while size >= 1024 and unit_index < len(units) - 1:
        size /= 1024
        unit_index += 1
    
    if unit_index == 0:
        return f"{int(size)} {units[unit_index]}"
    
    return f"{size:.{precision}f} {units[unit_index]}"


def format_rate(bytes_per_second: Union[int, float], precision: int = 2) -> str:
    """
    Convert bytes per second to human-readable rate.
    
    Args:
        bytes_per_second: Data rate in bytes per second.
        precision: Decimal places for the result.
    
    Returns:
        str: Formatted string (e.g., '1.50 MB/s').
    
    Example:
        >>> format_rate(1048576)
        '1.00 MB/s'
    """
    return f"{format_bytes(bytes_per_second, precision)}/s"


# =============================================================================
# Time Formatting
# =============================================================================

def format_timestamp(
    timestamp: Optional[Union[float, datetime]] = None,
    include_date: bool = False,
    include_ms: bool = True
) -> str:
    """
    Format a timestamp for display.
    
    Args:
        timestamp: Unix timestamp or datetime object. If None, uses current time.
        include_date: Whether to include the date.
        include_ms: Whether to include milliseconds.
    
    Returns:
        str: Formatted timestamp string.
    
    Example:
        >>> format_timestamp(include_date=False, include_ms=True)
        '14:30:45.123'
    """
    if timestamp is None:
        dt = datetime.now()
    elif isinstance(timestamp, (int, float)):
        dt = datetime.fromtimestamp(timestamp)
    else:
        dt = timestamp
    
    if include_date:
        if include_ms:
            return dt.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    else:
        if include_ms:
            return dt.strftime("%H:%M:%S.%f")[:-3]
        return dt.strftime("%H:%M:%S")


def format_duration(seconds: Union[int, float]) -> str:
    """
    Format a duration in seconds to human-readable format.
    
    Args:
        seconds: Duration in seconds.
    
    Returns:
        str: Formatted duration string.
    
    Example:
        >>> format_duration(3661)
        '1h 1m 1s'
        >>> format_duration(45)
        '45s'
    """
    if seconds < 0:
        return "0s"
    
    seconds = int(seconds)
    
    hours = seconds // 3600
    minutes = (seconds % 3600) // 60
    secs = seconds % 60
    
    parts = []
    
    if hours > 0:
        parts.append(f"{hours}h")
    if minutes > 0:
        parts.append(f"{minutes}m")
    if secs > 0 or not parts:
        parts.append(f"{secs}s")
    
    return " ".join(parts)


# =============================================================================
# Network Formatting
# =============================================================================

def format_ip_port(ip: str, port: Optional[int] = None, width: int = 21) -> str:
    """
    Format an IP address with optional port.
    
    Args:
        ip: IP address string.
        port: Optional port number.
        width: Minimum width for padding.
    
    Returns:
        str: Formatted IP:port string.
    
    Example:
        >>> format_ip_port("192.168.1.1", 443)
        '192.168.1.1:443     '
    """
    if port is not None:
        result = f"{ip}:{port}"
    else:
        result = ip
    
    return result.ljust(width)


def format_mac_address(mac: str) -> str:
    """
    Normalize MAC address format.
    
    Args:
        mac: MAC address in any common format.
    
    Returns:
        str: MAC address in XX:XX:XX:XX:XX:XX format.
    
    Example:
        >>> format_mac_address("aabbccddeeff")
        'AA:BB:CC:DD:EE:FF'
    """
    # Remove common separators
    clean = mac.replace(":", "").replace("-", "").replace(".", "").upper()
    
    if len(clean) != 12:
        return mac.upper()
    
    # Insert colons
    return ":".join(clean[i:i+2] for i in range(0, 12, 2))


# =============================================================================
# Packet Formatting
# =============================================================================

@dataclass
class PacketDisplayConfig:
    """
    Configuration for packet display formatting.
    
    Attributes:
        show_timestamp: Whether to show packet timestamp.
        show_size: Whether to show packet size.
        show_info: Whether to show additional info.
        protocol_width: Width for protocol column.
        address_width: Width for address columns.
        colorize: Whether to apply colors.
    """
    show_timestamp: bool = True
    show_size: bool = True
    show_info: bool = True
    protocol_width: int = 6
    address_width: int = 21
    colorize: bool = True


# Default configuration
DEFAULT_PACKET_CONFIG = PacketDisplayConfig()


def format_packet_line(
    protocol: str,
    source_ip: str,
    dest_ip: str,
    source_port: Optional[int] = None,
    dest_port: Optional[int] = None,
    size: Optional[int] = None,
    info: Optional[str] = None,
    timestamp: Optional[Union[float, datetime]] = None,
    config: PacketDisplayConfig = DEFAULT_PACKET_CONFIG
) -> str:
    """
    Format a single packet for terminal display.
    
    Args:
        protocol: Protocol name (e.g., 'TCP').
        source_ip: Source IP address.
        dest_ip: Destination IP address.
        source_port: Optional source port.
        dest_port: Optional destination port.
        size: Packet size in bytes.
        info: Additional packet info.
        timestamp: Packet timestamp.
        config: Display configuration.
    
    Returns:
        str: Formatted packet line.
    
    Example:
        >>> print(format_packet_line(
        ...     protocol="TCP",
        ...     source_ip="192.168.1.1",
        ...     dest_ip="10.0.0.1",
        ...     source_port=54321,
        ...     dest_port=443,
        ...     size=1500,
        ...     info="SYN ACK"
        ... ))
        [TCP  ] 192.168.1.1:54321    -> 10.0.0.1:443        | 1500 B   | SYN ACK
    """
    parts = []
    
    # Timestamp
    if config.show_timestamp and timestamp is not None:
        parts.append(format_timestamp(timestamp, include_date=False, include_ms=False))
    
    # Protocol (with color)
    protocol_str = f"[{protocol.upper():<{config.protocol_width - 2}}]"
    if config.colorize and COLORS_ENABLED:
        color = PROTOCOL_COLORS.get(protocol.upper(), Color.WHITE)
        protocol_str = colorize(protocol_str, color)
    parts.append(protocol_str)
    
    # Source address
    source = format_ip_port(source_ip, source_port, config.address_width)
    parts.append(source)
    
    # Arrow
    parts.append("->")
    
    # Destination address
    dest = format_ip_port(dest_ip, dest_port, config.address_width)
    parts.append(dest)
    
    # Size
    if config.show_size and size is not None:
        size_str = f"| {format_bytes(size):>10}"
        parts.append(size_str)
    
    # Info
    if config.show_info and info:
        info_str = f"| {info}"
        parts.append(info_str)
    
    return " ".join(parts)


# =============================================================================
# Alert Formatting
# =============================================================================

def format_alert_box(
    alert_type: str,
    severity: str,
    message: str,
    source_ip: Optional[str] = None,
    timestamp: Optional[Union[float, datetime]] = None,
    details: Optional[dict] = None
) -> str:
    """
    Format a security alert as a boxed message.
    
    Args:
        alert_type: Type of alert (e.g., 'PORT_SCAN').
        severity: Severity level ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL').
        message: Alert message.
        source_ip: Source IP of the threat.
        timestamp: When the alert was triggered.
        details: Additional details dictionary.
    
    Returns:
        str: Formatted multi-line alert box.
    
    Example:
        >>> print(format_alert_box(
        ...     alert_type="PORT_SCAN",
        ...     severity="HIGH",
        ...     message="Potential port scan detected",
        ...     source_ip="45.33.32.156"
        ... ))
    """
    width = 60
    border = "=" * width
    
    # Header with severity color
    icon = "🚨" if severity in ["HIGH", "CRITICAL"] else "⚠️"
    header = f"{icon} SECURITY ALERT: {alert_type}"
    if COLORS_ENABLED:
        header = colorize_severity(severity, header)
    
    lines = [
        "",
        border,
        header,
        border,
        f"  Severity:  {severity}",
        f"  Message:   {message}",
    ]
    
    if source_ip:
        lines.append(f"  Source:    {source_ip}")
    
    if timestamp:
        lines.append(f"  Time:      {format_timestamp(timestamp, include_date=True)}")
    
    if details:
        lines.append("  Details:")
        for key, value in details.items():
            lines.append(f"    - {key}: {value}")
    
    lines.append(border)
    lines.append("")
    
    return "\n".join(lines)


# =============================================================================
# Statistics Formatting
# =============================================================================

def format_statistics_table(
    title: str,
    data: dict,
    width: int = 50
) -> str:
    """
    Format a statistics dictionary as a bordered table.
    
    Args:
        title: Table title.
        data: Dictionary of label -> value pairs.
        width: Total table width.
    
    Returns:
        str: Formatted table string.
    
    Example:
        >>> print(format_statistics_table("Stats", {"Packets": 100, "Bytes": 1500}))
    """
    border = "=" * width
    separator = "-" * width
    
    lines = [
        border,
        f"  {title}".center(width),
        border,
    ]
    
    for label, value in data.items():
        # Format value based on type
        if isinstance(value, float):
            value_str = f"{value:.2f}"
        elif isinstance(value, int) and label.lower().find("byte") >= 0:
            value_str = format_bytes(value)
        elif isinstance(value, int):
            value_str = f"{value:,}"
        else:
            value_str = str(value)
        
        label_width = width - 6 - len(value_str)
        lines.append(f"  {label:<{label_width}} {value_str}")
    
    lines.append(border)
    
    return "\n".join(lines)


def format_protocol_distribution(
    protocols: dict,
    total: Optional[int] = None,
    width: int = 40
) -> str:
    """
    Format protocol distribution as a bar chart.
    
    Args:
        protocols: Dictionary of protocol -> count.
        total: Total packet count (calculated if not provided).
        width: Width of the bar chart.
    
    Returns:
        str: Formatted bar chart string.
    
    Example:
        >>> print(format_protocol_distribution({"TCP": 60, "UDP": 30, "ICMP": 10}))
    """
    if not protocols:
        return "  No data available"
    
    if total is None:
        total = sum(protocols.values())
    
    if total == 0:
        return "  No data available"
    
    lines = ["  Protocol Distribution:", "  " + "-" * (width + 15)]
    
    # Sort by count descending
    sorted_protocols = sorted(protocols.items(), key=lambda x: x[1], reverse=True)
    
    # Calculate bar width
    bar_width = width - 20
    max_count = max(protocols.values())
    
    for protocol, count in sorted_protocols:
        percentage = (count / total) * 100
        bar_length = int((count / max_count) * bar_width) if max_count > 0 else 0
        bar = "█" * bar_length
        
        # Colorize protocol name
        proto_str = colorize_protocol(f"{protocol:<8}")
        
        lines.append(f"  {proto_str} {bar:<{bar_width}} {count:>6} ({percentage:>5.1f}%)")
    
    lines.append("  " + "-" * (width + 15))
    
    return "\n".join(lines)


# =============================================================================
# Module Test
# =============================================================================

if __name__ == "__main__":
    print("=" * 60)
    print("FORMATTERS MODULE TEST")
    print("=" * 60)
    
    # Test color support
    print(f"\nColor Support: {'Enabled' if COLORS_ENABLED else 'Disabled'}")
    
    # Test colorize
    print("\nProtocol Colors:")
    for proto in ["TCP", "UDP", "HTTP", "DNS", "ICMP"]:
        print(f"  {colorize_protocol(proto)}")
    
    # Test byte formatting
    print("\nByte Formatting:")
    for size in [500, 1536, 1048576, 1073741824]:
        print(f"  {size:>15} bytes = {format_bytes(size)}")
    
    # Test duration formatting
    print("\nDuration Formatting:")
    for secs in [45, 125, 3661, 86400]:
        print(f"  {secs:>6} seconds = {format_duration(secs)}")
    
    # Test packet line
    print("\nPacket Line:")
    print(format_packet_line(
        protocol="TCP",
        source_ip="192.168.1.100",
        dest_ip="10.0.0.1",
        source_port=54321,
        dest_port=443,
        size=1500,
        info="SYN ACK"
    ))
    
    # Test alert box
    print(format_alert_box(
        alert_type="PORT_SCAN",
        severity="HIGH",
        message="Potential port scan detected from external IP",
        source_ip="45.33.32.156",
        details={"Ports Scanned": 25, "Duration": "10 seconds"}
    ))
    
    # Test statistics table
    print(format_statistics_table(
        title="SESSION SUMMARY",
        data={
            "Total Packets": 15234,
            "Total Bytes": 25165824,
            "Duration": "5m 32s",
            "Packets/sec": 45.8
        }
    ))
    
    # Test protocol distribution
    print("\n" + format_protocol_distribution({
        "TCP": 8500,
        "UDP": 4200,
        "HTTP": 1500,
        "DNS": 800,
        "ICMP": 234
    }))