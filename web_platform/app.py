"""
Flask Web Application

Backend server for the packet sniffer dashboard.
Supports two modes:
- LIVE: Real packet capture (requires sudo)
- DEMO: Simulated packets for demonstration
"""

import random
import time
from datetime import datetime
from collections import deque
from threading import Lock
from flask import Flask, render_template, jsonify, request, redirect, url_for


# =============================================================================
# Packet Storage (for real packets from core sniffer)
# =============================================================================

class PacketStore:
    """
    Thread-safe storage for real packets received from core sniffer.
    """
    
    def __init__(self, max_size=1000):
        self.packets = deque(maxlen=max_size)
        self.alerts = deque(maxlen=100)
        self.lock = Lock()
        self.last_packet_time = None
        self.last_alert_time = None
    
    def add_packet(self, packet):
        """Add a packet from core sniffer."""
        with self.lock:
            self.packets.append(packet)
            self.last_packet_time = time.time()
    
    def add_alert(self, alert):
        """Add a security alert from core sniffer."""
        with self.lock:
            self.alerts.append(alert)
            self.last_alert_time = time.time()
    
    def get_packets(self, count=50):
        """Get recent packets."""
        with self.lock:
            if len(self.packets) > 0:
                return list(self.packets)[-count:]
            return []
    
    def get_alerts(self, count=20):
        """Get recent alerts."""
        with self.lock:
            return list(self.alerts)[-count:]
    
    def get_stats(self):
        """Get storage statistics."""
        with self.lock:
            return {
                'packet_count': len(self.packets),
                'alert_count': len(self.alerts),
                'last_packet': self.last_packet_time
            }
    
    def clear(self):
        """Clear all stored data."""
        with self.lock:
            self.packets.clear()
            self.alerts.clear()
            self.last_packet_time = None
            self.last_alert_time = None


# Global packet store instance
packet_store = PacketStore()


# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'dev-secret-key-change-in-production'


# =============================================================================
# Helper Functions
# =============================================================================

def get_mode():
    """Get current application mode."""
    return app.config.get('SNIFFER_MODE', 'demo')


def get_sniffer_manager():
    """Get the sniffer manager instance."""
    return app.config.get('SNIFFER_MANAGER', None)


def is_live_mode():
    """Check if running in live mode."""
    return get_mode() == 'live'


# =============================================================================
# Simulated Data Generators
# =============================================================================

class DataSimulator:
    """Generates realistic network traffic that mirrors real capture patterns."""
    
    # Realistic protocol distribution (based on typical network traffic)
    PROTOCOL_WEIGHTS = {
        'TCP': 55,
        'UDP': 20,
        'HTTPS': 10,
        'DNS': 8,
        'HTTP': 3,
        'ICMP': 2,
        'SSH': 1,
        'FTP': 1
    }
    
    # Private IP ranges (your network)
    PRIVATE_IPS = [
        '192.168.1.100', '192.168.1.101', '192.168.1.102', '192.168.1.103',
        '192.168.1.1',  # Router
        '10.0.0.5', '10.0.0.10', '10.0.0.15',
    ]
    
    # Real-world public IPs (well-known services)
    PUBLIC_SERVICES = {
        'google': ['142.250.80.46', '142.250.189.206', '172.217.14.110'],
        'cloudflare': ['1.1.1.1', '1.0.0.1', '104.16.132.229'],
        'amazon': ['52.94.236.248', '54.239.28.85', '205.251.242.103'],
        'microsoft': ['13.107.42.14', '20.190.159.0', '40.126.1.145'],
        'github': ['140.82.114.4', '140.82.112.21', '192.30.255.113'],
        'facebook': ['157.240.1.35', '31.13.71.36'],
        'netflix': ['54.74.73.31', '52.209.122.14'],
        'dns_google': ['8.8.8.8', '8.8.4.4'],
        'dns_cloudflare': ['1.1.1.1', '1.0.0.1'],
    }
    
    # Flatten for random selection
    PUBLIC_IPS = [ip for ips in PUBLIC_SERVICES.values() for ip in ips]
    
    # Common ports with realistic frequency
    PORT_WEIGHTS = {
        443: 45,   # HTTPS - most common
        80: 15,    # HTTP
        53: 15,    # DNS
        22: 5,     # SSH
        993: 3,    # IMAPS
        587: 3,    # SMTP submission
        123: 3,    # NTP
        3306: 2,   # MySQL
        5432: 2,   # PostgreSQL
        8080: 2,   # HTTP alt
        21: 1,     # FTP
        25: 1,     # SMTP
        110: 1,    # POP3
        143: 1,    # IMAP
        8443: 1,   # HTTPS alt
    }
    
    # TCP flags for different connection states
    TCP_HANDSHAKE = ['SYN', 'SYN ACK', 'ACK']
    TCP_DATA = ['PSH ACK', 'ACK']
    TCP_CLOSE = ['FIN ACK', 'ACK', 'RST']
    
    # Realistic DNS queries
    DNS_DOMAINS = [
        'www.google.com', 'google.com', 'apis.google.com',
        'github.com', 'api.github.com', 'raw.githubusercontent.com',
        'www.amazon.com', 'aws.amazon.com', 's3.amazonaws.com',
        'www.microsoft.com', 'login.microsoftonline.com', 'outlook.office365.com',
        'www.facebook.com', 'graph.facebook.com',
        'www.youtube.com', 'i.ytimg.com',
        'cdn.jsdelivr.net', 'cdnjs.cloudflare.com',
        'fonts.googleapis.com', 'fonts.gstatic.com',
        'analytics.google.com', 'www.googletagmanager.com',
    ]
    
    # Attacker IPs for security alerts
    ATTACKER_IPS = [
        '45.33.32.156', '185.220.101.1', '23.129.64.100',
        '103.75.201.2', '91.240.118.50', '194.26.29.100',
        '185.56.80.65', '193.118.53.202', '45.155.205.233'
    ]
    
    # Ports commonly scanned
    SCAN_PORTS = [20, 21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 
                  993, 995, 1433, 3306, 3389, 5432, 5900, 8080, 8443]
    
    # Session tracking for realistic connections
    _active_sessions = []
    _session_counter = 0
    
    @classmethod
    def _weighted_choice(cls, weights_dict):
        """Select item based on weights."""
        items = list(weights_dict.keys())
        weights = list(weights_dict.values())
        total = sum(weights)
        r = random.uniform(0, total)
        cumulative = 0
        for item, weight in zip(items, weights):
            cumulative += weight
            if r <= cumulative:
                return item
        return items[-1]
    
    @classmethod
    def _get_realistic_size(cls, protocol, is_request=True):
        """Get realistic packet size based on protocol."""
        sizes = {
            'DNS': (60, 120) if is_request else (80, 300),
            'ICMP': (64, 84),
            'TCP': (40, 60),  # Pure ACK/control
            'HTTP': (200, 800) if is_request else (500, 1500),
            'HTTPS': (100, 400) if is_request else (200, 1500),
            'SSH': (60, 200),
            'FTP': (60, 150),
            'UDP': (50, 500),
        }
        min_size, max_size = sizes.get(protocol, (64, 1500))
        return random.randint(min_size, max_size)
    
    @classmethod
    def _create_session(cls):
        """Create a new realistic session."""
        cls._session_counter += 1
        
        src_ip = random.choice(cls.PRIVATE_IPS)
        dst_ip = random.choice(cls.PUBLIC_IPS)
        src_port = random.randint(49152, 65535)
        dst_port = cls._weighted_choice(cls.PORT_WEIGHTS)
        
        # Determine protocol based on port
        if dst_port == 443 or dst_port == 8443:
            protocol = 'HTTPS'
        elif dst_port == 80 or dst_port == 8080:
            protocol = 'HTTP'
        elif dst_port == 53:
            protocol = 'DNS'
        elif dst_port == 22:
            protocol = 'SSH'
        elif dst_port == 21:
            protocol = 'FTP'
        else:
            protocol = 'TCP'
        
        return {
            'id': cls._session_counter,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': src_port,
            'dst_port': dst_port,
            'protocol': protocol,
            'state': 'new',
            'packets_sent': 0
        }
    
    @classmethod
    def generate_packet(cls, is_attack=False, attack_type=None) -> dict:
        """Generate a single realistic packet."""
        
        if is_attack:
            return cls._generate_attack_packet(attack_type)
        
        # 70% chance to continue existing session, 30% new session
        if cls._active_sessions and random.random() < 0.7:
            session = random.choice(cls._active_sessions)
        else:
            session = cls._create_session()
            cls._active_sessions.append(session)
            
            # Limit active sessions
            if len(cls._active_sessions) > 20:
                cls._active_sessions.pop(0)
        
        # Generate packet based on session
        protocol = session['protocol']
        session['packets_sent'] += 1
        
        # Determine direction (80% outbound, 20% inbound/response)
        is_outbound = random.random() < 0.8
        
        if is_outbound:
            src_ip = session['src_ip']
            dst_ip = session['dst_ip']
            src_port = session['src_port']
            dst_port = session['dst_port']
        else:
            src_ip = session['dst_ip']
            dst_ip = session['src_ip']
            src_port = session['dst_port']
            dst_port = session['src_port']
        
        # Generate info based on protocol and state
        info = cls._generate_info(protocol, session, is_outbound)
        
        # Get realistic size
        size = cls._get_realistic_size(protocol, is_outbound)
        
        # Remove old sessions occasionally
        if session['packets_sent'] > random.randint(5, 20):
            if session in cls._active_sessions:
                cls._active_sessions.remove(session)
        
        return {
            'timestamp': datetime.now().isoformat(),
            'protocol': protocol,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': src_port,
            'dst_port': dst_port,
            'size': size,
            'packets': 1,
            'info': info,
            'is_malicious': False
        }
    
    @classmethod
    def _generate_attack_packet(cls, attack_type) -> dict:
        """Generate attack/malicious packet."""
        
        attacker_ip = random.choice(cls.ATTACKER_IPS)
        target_ip = random.choice(cls.PRIVATE_IPS)
        
        if attack_type == 'PORT_SCAN':
            return {
                'timestamp': datetime.now().isoformat(),
                'protocol': 'TCP',
                'src_ip': attacker_ip,
                'dst_ip': target_ip,
                'src_port': random.randint(49152, 65535),
                'dst_port': random.choice(cls.SCAN_PORTS),
                'size': 44,
                'packets': 1,
                'info': 'SYN',
                'is_malicious': True
            }
        
        elif attack_type == 'BRUTE_FORCE':
            return {
                'timestamp': datetime.now().isoformat(),
                'protocol': 'SSH',
                'src_ip': attacker_ip,
                'dst_ip': target_ip,
                'src_port': random.randint(49152, 65535),
                'dst_port': 22,
                'size': random.randint(100, 300),
                'packets': 1,
                'info': 'Failed Auth Attempt',
                'is_malicious': True
            }
        
        elif attack_type == 'SYN_FLOOD':
            # Spoofed source IP for SYN flood
            spoofed_ip = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
            return {
                'timestamp': datetime.now().isoformat(),
                'protocol': 'TCP',
                'src_ip': spoofed_ip,
                'dst_ip': target_ip,
                'src_port': random.randint(1024, 65535),
                'dst_port': 80,
                'size': 44,
                'packets': 1,
                'info': 'SYN',
                'is_malicious': True
            }
        
        elif attack_type == 'DNS_TUNNELING':
            hex_data = ''.join(random.choices('0123456789abcdef', k=48))
            return {
                'timestamp': datetime.now().isoformat(),
                'protocol': 'DNS',
                'src_ip': target_ip,
                'dst_ip': attacker_ip,
                'src_port': random.randint(49152, 65535),
                'dst_port': 53,
                'size': random.randint(200, 500),
                'packets': 1,
                'info': f'TXT {hex_data[:24]}.tunnel.bad-domain.com',
                'is_malicious': True
            }
        
        # Default suspicious connection
        return {
            'timestamp': datetime.now().isoformat(),
            'protocol': 'TCP',
            'src_ip': attacker_ip,
            'dst_ip': target_ip,
            'src_port': random.randint(49152, 65535),
            'dst_port': random.choice([22, 23, 3389, 445]),
            'size': random.randint(44, 200),
            'packets': 1,
            'info': 'Suspicious Connection',
            'is_malicious': True
        }
    
    @classmethod
    def _generate_info(cls, protocol: str, session: dict, is_outbound: bool) -> str:
        """Generate realistic info string based on protocol."""
        
        packets_sent = session['packets_sent']
        
        if protocol == 'TCP':
            # Simulate TCP state machine
            if packets_sent == 1:
                return 'SYN'
            elif packets_sent == 2:
                return 'SYN ACK'
            elif packets_sent == 3:
                return 'ACK'
            elif packets_sent > 15 and random.random() < 0.2:
                return random.choice(['FIN ACK', 'RST'])
            else:
                return random.choice(['ACK', 'PSH ACK', 'ACK'])
        
        elif protocol == 'UDP':
            return f"Len={random.randint(8, 1400)}"
        
        elif protocol == 'DNS':
            domain = random.choice(cls.DNS_DOMAINS)
            if is_outbound:
                record_type = random.choice(['A', 'AAAA', 'CNAME', 'MX'])
                return f"Query: {record_type} {domain}"
            else:
                # Response with IP
                response_ip = random.choice(cls.PUBLIC_IPS)
                return f"Response: {domain} -> {response_ip}"
        
        elif protocol == 'HTTP':
            if is_outbound:
                method = random.choice(['GET', 'POST', 'GET', 'GET'])  # GET more common
                paths = ['/', '/api/v1/data', '/index.html', '/assets/main.js', 
                        '/images/logo.png', '/api/users', '/health', '/metrics']
                return f"{method} {random.choice(paths)}"
            else:
                codes = [(200, 'OK'), (200, 'OK'), (200, 'OK'), (304, 'Not Modified'),
                        (301, 'Moved'), (404, 'Not Found'), (500, 'Server Error')]
                code, text = random.choice(codes)
                return f"HTTP/1.1 {code} {text}"
        
        elif protocol == 'HTTPS':
            if packets_sent <= 3:
                return 'TLS Handshake'
            else:
                return 'Application Data'
        
        elif protocol == 'ICMP':
            if is_outbound:
                return 'Echo Request'
            else:
                return 'Echo Reply'
        
        elif protocol == 'SSH':
            if packets_sent <= 3:
                return 'Key Exchange Init'
            else:
                return 'Encrypted Data'
        
        elif protocol == 'FTP':
            commands = ['USER', 'PASS', 'LIST', 'RETR', 'STOR', 'QUIT', 'PWD', 'CWD']
            if is_outbound:
                return random.choice(commands)
            else:
                codes = ['220 Ready', '230 Login OK', '250 OK', '150 Opening', '226 Complete']
                return random.choice(codes)
        
        return protocol
    
    @classmethod
    def generate_alert(cls, attack_type=None) -> dict:
        """Generate a security alert."""
        if attack_type is None:
            attack_type = random.choice(['PORT_SCAN', 'BRUTE_FORCE', 'SYN_FLOOD', 'DNS_TUNNELING'])
        
        alerts = {
            'PORT_SCAN': {
                'type': 'PORT_SCAN',
                'severity': 'HIGH',
                'source_ip': random.choice(cls.ATTACKER_IPS),
                'message': 'Sequential port scanning detected from external host',
                'details': {
                    'ports_scanned': random.randint(15, 50),
                    'time_window': '60s',
                    'target': random.choice(cls.PRIVATE_IPS)
                }
            },
            'BRUTE_FORCE': {
                'type': 'BRUTE_FORCE',
                'severity': 'MEDIUM',
                'source_ip': random.choice(cls.ATTACKER_IPS),
                'message': 'Multiple failed authentication attempts detected on SSH',
                'details': {
                    'target_port': 22,
                    'attempts': random.randint(10, 30),
                    'time_window': '60s'
                }
            },
            'SYN_FLOOD': {
                'type': 'SYN_FLOOD',
                'severity': 'CRITICAL',
                'source_ip': 'Multiple (Spoofed)',
                'message': 'High volume of SYN packets detected - possible DDoS attack',
                'details': {
                    'syn_packets': random.randint(500, 2000),
                    'time_window': '10s',
                    'target_port': 80
                }
            },
            'DNS_TUNNELING': {
                'type': 'DNS_TUNNELING',
                'severity': 'HIGH',
                'source_ip': random.choice(cls.PRIVATE_IPS),
                'message': 'Suspicious DNS queries with encoded data detected - possible data exfiltration',
                'details': {
                    'suspicious_queries': random.randint(20, 50),
                    'avg_query_length': random.randint(100, 200),
                    'destination': 'tunnel.bad-domain.com'
                }
            }
        }
        
        alert = alerts.get(attack_type, alerts['PORT_SCAN'])
        alert['timestamp'] = datetime.now().isoformat()
        alert['id'] = f"{alert['type']}_{int(time.time() * 1000)}"
        
        return alert
    
    @classmethod
    def generate_statistics(cls) -> dict:
        """Generate realistic statistics."""
        total_packets = random.randint(5000, 50000)
        
        # Calculate protocol counts based on weights
        protocols = {}
        total_weight = sum(cls.PROTOCOL_WEIGHTS.values())
        for proto, weight in cls.PROTOCOL_WEIGHTS.items():
            count = int((weight / total_weight) * total_packets * random.uniform(0.8, 1.2))
            protocols[proto] = count
        
        return {
            'total_packets': total_packets,
            'total_bytes': random.randint(5000000, 50000000),
            'packets_per_second': round(random.uniform(20, 150), 1),
            'bytes_per_second': round(random.uniform(50000, 500000), 1),
            'duration_seconds': random.randint(60, 3600),
            'protocols': protocols,
            'top_sources': [
                {'ip': '192.168.1.100', 'count': random.randint(1000, 5000)},
                {'ip': '192.168.1.101', 'count': random.randint(500, 2000)},
                {'ip': '10.0.0.5', 'count': random.randint(300, 1000)},
            ],
            'top_ports': [
                {'port': 443, 'service': 'HTTPS', 'count': random.randint(2000, 8000)},
                {'port': 80, 'service': 'HTTP', 'count': random.randint(500, 3000)},
                {'port': 53, 'service': 'DNS', 'count': random.randint(500, 2000)},
                {'port': 22, 'service': 'SSH', 'count': random.randint(50, 500)},
            ]
        }


# =============================================================================
# Routes - Pages
# =============================================================================

@app.route('/')
def index():
    """Redirect to dashboard."""
    return redirect(url_for('dashboard'))


@app.route('/dashboard')
def dashboard():
    """Main interactive dashboard."""
    return render_template('dashboard.html', mode=get_mode())


# =============================================================================
# Routes - Mode & Status API
# =============================================================================

@app.route('/api/mode')
def api_mode():
    """Get current application mode."""
    mode = get_mode()
    manager = get_sniffer_manager()
    
    result = {
        'success': True,
        'mode': mode,
        'is_live': mode == 'live',
        'packet_count': packet_store.get_stats()['packet_count'],
        'alert_count': packet_store.get_stats()['alert_count']
    }
    
    if mode == 'live' and manager:
        status = manager.get_status()
        result['sniffer_running'] = status['is_running']
        result['sniffer_error'] = status['error']
    
    return jsonify(result)


# =============================================================================
# Routes - Sniffer Control API (Live Mode Only)
# =============================================================================

@app.route('/api/sniffer/start', methods=['POST'])
def api_sniffer_start():
    """Start the packet sniffer (live mode only)."""
    if not is_live_mode():
        return jsonify({
            'success': False,
            'error': 'Sniffer control only available in live mode'
        }), 400
    
    manager = get_sniffer_manager()
    if not manager:
        return jsonify({
            'success': False,
            'error': 'Sniffer manager not initialized'
        }), 500
    
    result = manager.start()
    return jsonify(result)


@app.route('/api/sniffer/stop', methods=['POST'])
def api_sniffer_stop():
    """Stop the packet sniffer (live mode only)."""
    if not is_live_mode():
        return jsonify({
            'success': False,
            'error': 'Sniffer control only available in live mode'
        }), 400
    
    manager = get_sniffer_manager()
    if not manager:
        return jsonify({
            'success': False,
            'error': 'Sniffer manager not initialized'
        }), 500
    
    result = manager.stop()
    return jsonify(result)


@app.route('/api/sniffer/status')
def api_sniffer_status():
    """Get sniffer status (live mode only)."""
    if not is_live_mode():
        return jsonify({
            'success': False,
            'error': 'Sniffer status only available in live mode'
        }), 400
    
    manager = get_sniffer_manager()
    if not manager:
        return jsonify({
            'success': False,
            'error': 'Sniffer manager not initialized'
        }), 500
    
    status = manager.get_status()
    return jsonify({
        'success': True,
        **status
    })


# =============================================================================
# Routes - Packet API
# =============================================================================

@app.route('/api/packets')
def api_packets():
    """Get packet stream."""
    count = request.args.get('count', default=10, type=int)
    count = min(count, 100)
    
    mode = get_mode()
    
    # In live mode, return real packets if available
    if mode == 'live':
        real_packets = packet_store.get_packets(count)
        if real_packets:
            return jsonify({
                'success': True,
                'mode': 'live',
                'count': len(real_packets),
                'packets': real_packets
            })
    
    # Demo mode or no real packets: return simulated
    packets = [DataSimulator.generate_packet() for _ in range(count)]
    
    return jsonify({
        'success': True,
        'mode': 'demo',
        'count': len(packets),
        'packets': packets
    })


@app.route('/api/ingest', methods=['POST'])
def api_ingest():
    """Receive packets from core sniffer."""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({
                'success': False,
                'error': 'No data provided'
            }), 400
        
        # Handle single packet
        if 'packet' in data:
            packet = data['packet']
            packet_store.add_packet(packet)
            return jsonify({
                'success': True,
                'message': 'Packet received'
            })
        
        # Handle batch of packets
        if 'packets' in data:
            packets = data['packets']
            for packet in packets:
                packet_store.add_packet(packet)
            return jsonify({
                'success': True,
                'message': f'{len(packets)} packets received'
            })
        
        # Handle security alert
        if 'alert' in data:
            alert = data['alert']
            packet_store.add_alert(alert)
            return jsonify({
                'success': True,
                'message': 'Alert received'
            })
        
        return jsonify({
            'success': False,
            'error': 'Invalid data format'
        }), 400
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/attack-packets')
def api_attack_packets():
    """Get simulated attack traffic (demo mode only)."""
    if is_live_mode():
        return jsonify({
            'success': False,
            'error': 'Attack simulation not available in live mode'
        }), 400
    
    attack_type = request.args.get('type', default='PORT_SCAN', type=str)
    count = request.args.get('count', default=20, type=int)
    count = min(count, 50)
    
    packets = [DataSimulator.generate_packet(is_attack=True, attack_type=attack_type) for _ in range(count)]
    alert = DataSimulator.generate_alert(attack_type)
    
    return jsonify({
        'success': True,
        'attack_type': attack_type,
        'count': len(packets),
        'packets': packets,
        'alert': alert
    })


@app.route('/api/live-alerts')
def api_live_alerts():
    """Get alerts from packet store."""
    alerts = packet_store.get_alerts(20)
    
    return jsonify({
        'success': True,
        'count': len(alerts),
        'alerts': alerts
    })


@app.route('/api/clear-alerts', methods=['POST'])
def api_clear_alerts():
    """Clear all stored data."""
    packet_store.clear()
    return jsonify({
        'success': True,
        'message': 'All data cleared'
    })


@app.route('/api/statistics')
def api_statistics():
    """Get statistics."""
    mode = get_mode()
    manager = get_sniffer_manager()
    
    if mode == 'live' and manager:
        status = manager.get_status()
        if status['is_running']:
            return jsonify({
                'success': True,
                'mode': 'live',
                'statistics': {
                    'total_packets': status.get('packets_captured', 0),
                    'duration_seconds': status.get('duration_seconds', 0),
                    'interface': status.get('interface', 'Unknown')
                }
            })
    
    # Return simulated stats
    stats = DataSimulator.generate_statistics()
    return jsonify({
        'success': True,
        'mode': 'demo',
        'statistics': stats
    })


@app.route('/api/protocol-distribution')
def api_protocol_distribution():
    """Get protocol distribution data."""
    mode = get_mode()
    
    if mode == 'live':
        # Get real protocol counts from packet store
        packets = packet_store.get_packets(1000)
        
        if packets and len(packets) > 0:
            # Count protocols from real packets
            protocol_counts = {}
            for packet in packets:
                proto = packet.get('protocol', 'UNKNOWN')
                protocol_counts[proto] = protocol_counts.get(proto, 0) + 1
            
            # Ensure all expected protocols have a value
            all_protocols = ['TCP', 'UDP', 'HTTP', 'HTTPS', 'TLS', 'DNS', 
                           'ICMP', 'ICMPv6', 'SSH', 'FTP', 'ARP', 'IPv6']
            
            for proto in all_protocols:
                if proto not in protocol_counts:
                    protocol_counts[proto] = 0
            
            return jsonify({
                'success': True,
                'mode': 'live',
                'protocols': protocol_counts
            })
    
    # Demo mode: return simulated data
    protocols = {
        'TCP': random.randint(40, 60),
        'UDP': random.randint(15, 25),
        'HTTP': random.randint(5, 15),
        'HTTPS': random.randint(10, 20),
        'TLS': random.randint(5, 10),
        'DNS': random.randint(5, 10),
        'ICMP': random.randint(1, 5),
        'ICMPv6': random.randint(1, 3),
        'SSH': random.randint(1, 3),
        'FTP': random.randint(0, 2),
        'ARP': random.randint(1, 5),
        'IPv6': random.randint(5, 15)
    }
    
    return jsonify({
        'success': True,
        'mode': 'demo',
        'protocols': protocols
    })


# =============================================================================
# Error Handlers
# =============================================================================

@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors."""
    return jsonify({
        'success': False,
        'error': 'Not found'
    }), 404


@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors."""
    return jsonify({
        'success': False,
        'error': 'Internal server error'
    }), 500


# =============================================================================
# Development Server (standalone mode)
# =============================================================================

if __name__ == '__main__':
    print("=" * 60)
    print("  PACKET SNIFFER - Web Platform")
    print("=" * 60)
    print("  Note: Run via runner.py for full functionality")
    print("  Dashboard: http://localhost:8000")
    print("=" * 60)
    
    app.run(debug=True, host='0.0.0.0', port=8000)