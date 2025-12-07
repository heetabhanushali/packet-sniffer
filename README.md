# Cross-Platform Packet Sniffer

A real-time network traffic analyzer with an interactive web dashboard. Capture, analyze, and visualize network packets with built-in security threat detection.

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![Flask](https://img.shields.io/badge/Flask-3.0+-green.svg)
![Scapy](https://img.shields.io/badge/Scapy-2.5+-orange.svg)
![Platform](https://img.shields.io/badge/Platform-macOS%20|%20Linux%20|%20Windows-lightgrey.svg)

---

## Demo

**Live Demo (Simulated Traffic):** [https://packet-sniffer-bpub.onrender.com/dashboard](https://packet-sniffer-bpub.onrender.com/dashboard)

**Video Demo (Real Network Capture):** [Watch Video](https://drive.google.com/file/d/1O33FlX99Hey1hdfA9x1azEwLy3Ts-oXn/view?usp=drive_link)

---

## Features

### Core Capabilities
- **Real-Time Packet Capture** - Capture live network traffic with Scapy
- **Protocol Analysis** - Decode TCP, UDP, HTTP, HTTPS, DNS, ICMP, SSH, FTP, ARP, and more
- **Interactive Dashboard** - Beautiful web interface with live updates
- **Security Monitoring** - Detect port scans, brute force attempts, SYN floods, and suspicious activity

### Dashboard Features
- Live packet stream with color-coded protocols
- Protocol distribution charts
- Traffic rate visualization
- Security alert cards
- Filterable packet table
- Client connection metrics

### Security Detection
| Threat Type | Description |
|-------------|-------------|
| Port Scan | Detects sequential port scanning from single source |
| Brute Force | Identifies repeated authentication attempts |
| SYN Flood | Alerts on high volume of SYN packets |
| Suspicious Ports | Flags connections to commonly exploited ports |

### Dual Mode Operation
- **Live Mode** - Real packet capture (requires admin/root privileges)
- **Demo Mode** - Simulated traffic for demonstration and testing

---

## How to Run

### Prerequisites

- Python 3.8 or higher
- pip (Python package manager)

### Installation

```bash
# Clone the repository
git clone https://github.com/heetabhanushali/packet-sniffer.git
cd packet-sniffer

# Create virtual environment
python3 -m venv sniffer-env
source sniffer-env/bin/activate  # On Windows: sniffer-env\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Run in Demo Mode (Simulated Traffic)

```bash
python3 runner.py
```

### Run in Live Mode (Real Traffic)

```bash
# macOS/Linux
sudo python3 runner.py

# Windows (Run Command Prompt as Administrator)
python runner.py
```

The dashboard will automatically open at `http://127.0.0.1:8000`

---

## Project Structure

```
packet-sniffer/
├── runner.py                 # Single entry point
├── requirements.txt          # Python dependencies
├── README.md
│
├── core_sniffer/             # Packet capture engine
│   ├── __init__.py
│   ├── main.py               # CLI entry point
│   ├── capture_engine.py     # Main capture orchestrator
│   ├── protocol_parser.py    # Protocol decoding
│   ├── statistics.py         # Traffic statistics
│   ├── security_monitor.py   # Threat detection
│   └── utils/
│       ├── formatters.py     # Output formatting
│       ├── legal.py          # Legal compliance
│       ├── platform_detect.py # OS detection
│       └── web_integration.py # Dashboard communication
│
└── web_platform/             # Web dashboard
    ├── app.py                # Flask application
    ├── templates/
    │   ├── base.html
    │   └── dashboard.html
    └── static/
        ├── css/
        │   └── style.css
        └── js/
            ├── dashboard.js
            ├── simulation.js
            └── client_metrics.js
```

---

## Technical Details

### Supported Protocols

| Layer | Protocols |
|-------|-----------|
| Layer 2 | Ethernet, ARP |
| Layer 3 | IPv4, IPv6, ICMP, ICMPv6 |
| Layer 4 | TCP, UDP |
| Layer 7 | HTTP, HTTPS/TLS, DNS, SSH, FTP, SMTP |

### Security Thresholds (Defaults)

| Detection | Threshold | Time Window |
|-----------|-----------|-------------|
| Port Scan | 25 unique ports | 30 seconds |
| Brute Force | 50 attempts | 30 seconds |
| SYN Flood | 100 SYN packets | 10 seconds |

### API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/mode` | GET | Get current mode (live/demo) |
| `/api/packets` | GET | Get packet stream |
| `/api/statistics` | GET | Get traffic statistics |
| `/api/protocol-distribution` | GET | Get protocol counts |
| `/api/live-alerts` | GET | Get security alerts |
| `/api/sniffer/start` | POST | Start capture (live mode) |
| `/api/sniffer/stop` | POST | Stop capture (live mode) |

---

## Acknowledgments

- [Scapy](https://scapy.net/) - Packet manipulation library
- [Flask](https://flask.palletsprojects.com/) - Web framework
- [Chart.js](https://www.chartjs.org/) - Data visualization