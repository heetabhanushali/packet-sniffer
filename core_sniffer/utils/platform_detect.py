"""
Platform Detection Module

Automatically detects the operating system and selects the appropriate
network interface for packet capture. Provides OS-specific guidance
for permissions and dependencies.

Supports:
    - macOS (Intel & Apple Silicon)
    - Windows (requires Npcap)
    - Linux (all distributions)
"""

import sys
import platform
import subprocess
from typing import Optional
from dataclasses import dataclass


@dataclass
class OSInfo:
    """
    Data class containing operating system information.
    
    Attributes:
        name: Human-readable OS name (e.g., 'macOS', 'Windows', 'Linux')
        platform: Raw platform identifier from sys.platform
        version: OS version string
        architecture: CPU architecture (e.g., 'arm64', 'x86_64')
        requires_sudo: Whether sudo/admin is required for packet capture
        requires_npcap: Whether Npcap installation is required (Windows only)
    """
    name: str
    platform: str
    version: str
    architecture: str
    requires_sudo: bool
    requires_npcap: bool


@dataclass
class InterfaceInfo:
    """
    Data class containing network interface information.
    
    Attributes:
        name: Interface identifier (e.g., 'en0', 'eth0', 'Wi-Fi')
        display_name: Human-readable name
        is_active: Whether the interface is currently up
        description: Additional interface details
    """
    name: str
    display_name: str
    is_active: bool
    description: str


def get_os_info() -> OSInfo:
    """
    Detect and return current operating system information.
    
    Returns:
        OSInfo: Dataclass containing OS details and requirements.
    
    Example:
        >>> info = get_os_info()
        >>> print(info.name)
        'macOS'
        >>> print(info.requires_sudo)
        True
    """
    system = sys.platform
    architecture = platform.machine()
    version = platform.version()
    
    if system == "darwin":
        # macOS (Intel or Apple Silicon)
        return OSInfo(
            name="macOS",
            platform=system,
            version=platform.mac_ver()[0],
            architecture=architecture,
            requires_sudo=True,
            requires_npcap=False
        )
    
    elif system == "win32":
        # Windows
        return OSInfo(
            name="Windows",
            platform=system,
            version=platform.win32_ver()[0],
            architecture=architecture,
            requires_sudo=False,  # Uses "Run as Administrator" instead
            requires_npcap=True
        )
    
    elif system.startswith("linux"):
        # Linux (any distribution)
        return OSInfo(
            name="Linux",
            platform=system,
            version=version,
            architecture=architecture,
            requires_sudo=True,
            requires_npcap=False
        )
    
    else:
        # Unknown/unsupported OS
        return OSInfo(
            name="Unknown",
            platform=system,
            version=version,
            architecture=architecture,
            requires_sudo=True,
            requires_npcap=False
        )


def get_default_interface() -> Optional[str]:
    """
    Automatically detect the best network interface for packet capture.
    
    Uses Scapy's built-in interface detection, which works across all
    supported operating systems.
    
    Returns:
        Optional[str]: Interface name if found, None otherwise.
    
    Raises:
        ImportError: If Scapy is not installed.
    
    Example:
        >>> iface = get_default_interface()
        >>> print(iface)
        'en0'  # On macOS
    """
    try:
        from scapy.all import conf
        return conf.iface
    except ImportError:
        raise ImportError(
            "Scapy is not installed. "
            "Please run: pip install scapy"
        )
    except Exception:
        return None


def get_all_interfaces() -> list[InterfaceInfo]:
    """
    Get a list of all available network interfaces.
    
    Returns:
        list[InterfaceInfo]: List of available interfaces with details.
    
    Raises:
        ImportError: If Scapy is not installed.
    
    Example:
        >>> interfaces = get_all_interfaces()
        >>> for iface in interfaces:
        ...     print(f"{iface.name}: {iface.display_name}")
    """
    try:
        from scapy.all import get_if_list, conf
        
        interfaces = []
        default_iface = conf.iface
        
        for iface_name in get_if_list():
            interfaces.append(InterfaceInfo(
                name=iface_name,
                display_name=iface_name,
                is_active=(iface_name == default_iface),
                description=_get_interface_description(iface_name)
            ))
        
        return interfaces
    
    except ImportError:
        raise ImportError(
            "Scapy is not installed. "
            "Please run: pip install scapy"
        )


def _get_interface_description(iface_name: str) -> str:
    """
    Get a human-readable description for a network interface.
    
    Args:
        iface_name: The interface identifier.
    
    Returns:
        str: Description of the interface type.
    """
    name_lower = iface_name.lower()
    
    # Common interface naming patterns
    if "lo" in name_lower:
        return "Loopback interface"
    elif "en" in name_lower or "eth" in name_lower:
        return "Ethernet/Wi-Fi interface"
    elif "wlan" in name_lower or "wi-fi" in name_lower:
        return "Wireless interface"
    elif "bridge" in name_lower:
        return "Bridge interface"
    elif "docker" in name_lower:
        return "Docker virtual interface"
    elif "veth" in name_lower:
        return "Virtual Ethernet interface"
    elif "utun" in name_lower or "tun" in name_lower:
        return "Tunnel interface (VPN)"
    elif "awdl" in name_lower:
        return "Apple Wireless Direct Link"
    elif "llw" in name_lower:
        return "Low Latency WLAN interface"
    else:
        return "Network interface"


def check_permissions() -> dict:
    """
    Check if the current user has sufficient permissions for packet capture.
    
    Returns:
        dict: Contains 'has_permission' boolean and 'message' string.
    
    Example:
        >>> result = check_permissions()
        >>> if not result['has_permission']:
        ...     print(result['message'])
    """
    os_info = get_os_info()
    
    if os_info.name == "Windows":
        # Check if running as Administrator on Windows
        try:
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            if is_admin:
                return {
                    "has_permission": True,
                    "message": "Running as Administrator."
                }
            else:
                return {
                    "has_permission": False,
                    "message": (
                        "Administrator privileges required.\n"
                        "Please run Command Prompt as Administrator."
                    )
                }
        except Exception:
            return {
                "has_permission": False,
                "message": "Could not verify Administrator privileges."
            }
    
    else:
        # Check if running as root on macOS/Linux
        import os
        if os.geteuid() == 0:
            return {
                "has_permission": True,
                "message": "Running with root privileges."
            }
        else:
            return {
                "has_permission": False,
                "message": (
                    "Root privileges required.\n"
                    f"Please run: sudo python3 -m core_sniffer.main"
                )
            }


def check_npcap_installed() -> dict:
    """
    Check if Npcap is installed (Windows only).
    
    Returns:
        dict: Contains 'installed' boolean and 'message' string.
    
    Example:
        >>> result = check_npcap_installed()
        >>> print(result['installed'])
        True
    """
    os_info = get_os_info()
    
    if os_info.name != "Windows":
        return {
            "installed": True,
            "message": "Npcap not required on this OS."
        }
    
    try:
        # Try to import Scapy and check if it can access interfaces
        from scapy.all import get_if_list
        interfaces = get_if_list()
        
        if interfaces:
            return {
                "installed": True,
                "message": "Npcap is installed and working."
            }
        else:
            return {
                "installed": False,
                "message": (
                    "Npcap may not be installed correctly.\n"
                    "Download from: https://npcap.com\n"
                    "Enable 'WinPcap API-compatible Mode' during installation."
                )
            }
    
    except Exception as e:
        return {
            "installed": False,
            "message": (
                f"Npcap check failed: {str(e)}\n"
                "Download from: https://npcap.com\n"
                "Enable 'WinPcap API-compatible Mode' during installation."
            )
        }


def get_platform_summary() -> str:
    """
    Get a formatted summary of the current platform configuration.
    
    Returns:
        str: Multi-line formatted string with platform details.
    
    Example:
        >>> print(get_platform_summary())
        =====================================
        PLATFORM SUMMARY
        =====================================
        OS: macOS 14.0
        ...
    """
    os_info = get_os_info()
    default_iface = get_default_interface()
    permissions = check_permissions()
    
    lines = [
        "=" * 50,
        "PLATFORM SUMMARY",
        "=" * 50,
        f"  OS:            {os_info.name} {os_info.version}",
        f"  Architecture:  {os_info.architecture}",
        f"  Interface:     {default_iface or 'Not detected'}",
        f"  Permissions:   {'✓ OK' if permissions['has_permission'] else '✗ Required'}",
    ]
    
    if os_info.requires_npcap:
        npcap = check_npcap_installed()
        lines.append(f"  Npcap:         {'✓ Installed' if npcap['installed'] else '✗ Required'}")
    
    lines.append("=" * 50)
    
    return "\n".join(lines)


# =============================================================================
# Module Test
# =============================================================================

if __name__ == "__main__":
    # Self-test when run directly
    print(get_platform_summary())
    
    print("\nAll Interfaces:")
    print("-" * 40)
    
    try:
        for iface in get_all_interfaces():
            status = "[ACTIVE]" if iface.is_active else ""
            print(f"  {iface.name:15} {status:10} {iface.description}")
    except ImportError as e:
        print(f"  Error: {e}")