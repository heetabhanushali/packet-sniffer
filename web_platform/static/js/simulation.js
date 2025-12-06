/**
 * Packet Simulator / Table Manager
 * 
 * Generates realistic traffic patterns that mirror actual network behavior.
 * Features:
 * - Variable packet rates (bursts, quiet periods)
 * - Session-based connections
 * - Realistic timing patterns
 */

class PacketSimulator {
    constructor() {
        this.isRunning = false;
        this.intervalId = null;
        this.packets = [];
        this.packetCount = 0;
        this.totalBytes = 0;
        this.startTime = null;
        this.maxStoredPackets = 500;
        
        // Variable rate control
        this.baseRate = 2;           
        this.currentRate = 2;        
        this.rateChangeCounter = 0;  
        this.burstMode = false;    
        this.quietMode = false;      
        
        // Timing control
        this.fetchInterval = 1000;   
        this.currentInterval = 1000;  
        
        this.uniqueSrcIPs = new Set();
        this.uniqueDstIPs = new Set();
        
        this.portToService = {
            20: 'FTP-Data',
            21: 'FTP',
            22: 'SSH',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            443: 'HTTPS',
            3306: 'MySQL',
            5432: 'PostgreSQL',
            8080: 'HTTP-Alt',
            8443: 'HTTPS-Alt'
        };
        
        this.attackTypes = ['PORT_SCAN', 'BRUTE_FORCE', 'SYN_FLOOD', 'DNS_TUNNELING'];
    }
    
    start() {
        if (this.isRunning) return;
        
        this.isRunning = true;
        this.startTime = Date.now();
        
        const placeholder = document.getElementById('packet-placeholder');
        if (placeholder) {
            placeholder.classList.add('hidden');
        }
        
        // Reset rate controls
        this.currentRate = this.baseRate;
        this.rateChangeCounter = 0;
        this.burstMode = false;
        this.quietMode = false;
        
        // Only fetch packets automatically in demo mode
        if (typeof IS_LIVE_MODE === 'undefined' || !IS_LIVE_MODE) {
            this.scheduleNextFetch();
        }
        
        console.log('[Simulator] Started');
    }
    
    scheduleNextFetch() {
        if (!this.isRunning) return;
        
        // Update traffic pattern
        this.updateTrafficPattern();
        
        // Fetch packets based on current rate
        this.fetchPackets();
        
        // Schedule next fetch with variable timing
        this.intervalId = setTimeout(() => {
            this.scheduleNextFetch();
        }, this.currentInterval);
    }
    
    updateTrafficPattern() {
        this.rateChangeCounter++;
        
        // Change pattern every 10-20 cycles
        if (this.rateChangeCounter >= this.getRandomInt(8, 15)) {
            this.rateChangeCounter = 0;
            
            // Decide next pattern
            const rand = Math.random();
            
            if (rand < 0.15) {
                // 15% chance: Enter burst mode (high traffic)
                this.burstMode = true;
                this.quietMode = false;
                this.currentRate = this.getRandomInt(4, 7);
                this.currentInterval = this.getRandomInt(600, 900);
                console.log('[Simulator] Burst mode - Rate:', this.currentRate);
                
            } else if (rand < 0.30) {
                // 15% chance: Enter quiet mode (low traffic)
                this.burstMode = false;
                this.quietMode = true;
                this.currentRate = 1;
                this.currentInterval = this.getRandomInt(1500, 2500);
                console.log('[Simulator] Quiet mode - Rate:', this.currentRate);
                
            } else {
                // 70% chance: Normal mode with variation
                this.burstMode = false;
                this.quietMode = false;
                this.currentRate = this.getRandomInt(1, 3);
                this.currentInterval = this.getRandomInt(800, 1200);
            }
        }
        
        if (Math.random() < 0.3) {
            const variation = Math.random() < 0.5 ? -1 : 1;
            this.currentRate = Math.max(1, Math.min(7, this.currentRate + variation));
        }
    }
    
    getRandomInt(min, max) {
        return Math.floor(Math.random() * (max - min + 1)) + min;
    }
    
    stop() {
        if (!this.isRunning) return;
        
        this.isRunning = false;
        
        if (this.intervalId) {
            clearTimeout(this.intervalId);
            this.intervalId = null;
        }
        
        console.log('[Simulator] Stopped');
    }
    
    reset() {
        this.stop();
        this.packets = [];
        this.packetCount = 0;
        this.totalBytes = 0;
        this.startTime = null;
        this.uniqueSrcIPs.clear();
        this.uniqueDstIPs.clear();
        this.currentRate = this.baseRate;
        this.rateChangeCounter = 0;
        this.burstMode = false;
        this.quietMode = false;
        
        const tbody = document.getElementById('packet-tbody');
        if (tbody) {
            tbody.innerHTML = '';
        }
        
        const placeholder = document.getElementById('packet-placeholder');
        if (placeholder) {
            placeholder.classList.remove('hidden');
        }
        
        this.resetFilterDropdowns();
        
        console.log('[Simulator] Reset');
    }
    
    async fetchPackets() {
        if (!this.isRunning) return;
        
        try {
            // Fetch variable number of packets based on current rate
            const response = await fetch(`/api/packets?count=${this.currentRate}`);
            const data = await response.json();
            
            if (data.success && data.packets) {
                // Add small random delay between packets for realism
                data.packets.forEach((packet, index) => {
                    setTimeout(() => {
                        if (this.isRunning) {
                            this.addPacket(packet);
                        }
                    }, index * this.getRandomInt(20, 80));
                });
            }
        } catch (error) {
            console.error('[Simulator] Fetch error:', error);
        }
    }
    
    async triggerAttack() {
        // Only allow if simulation is running
        if (!this.isRunning) {
            console.log('[Simulator] Cannot trigger attack - simulation not running');
            return;
        }
        
        const attackType = this.attackTypes[Math.floor(Math.random() * this.attackTypes.length)];
        
        try {
            const response = await fetch(`/api/attack-packets?type=${attackType}&count=25`);
            const data = await response.json();
            
            if (data.success) {
                if (data.packets) {
                    // Stagger attack packets for realistic effect
                    data.packets.forEach((packet, index) => {
                        setTimeout(() => {
                            if (this.isRunning) {
                                this.addPacket(packet);
                            }
                        }, index * this.getRandomInt(30, 100));
                    });
                }
                
                if (data.alert) {
                    // Delay alert slightly to appear after some attack packets
                    setTimeout(() => {
                        this.displayAlert(data.alert);
                    }, 500);
                }
            }
        } catch (error) {
            console.error('[Simulator] Attack error:', error);
        }
    }
    
    addPacket(packet) {
        const service = packet.service || 
                       this.portToService[packet.dst_port] || 
                       this.portToService[packet.src_port] || 
                       '--';
        
        const enrichedPacket = {
            ...packet,
            service: service,
            id: this.packetCount,
            packets: packet.packets || 1
        };
        
        this.packets.push(enrichedPacket);
        this.packetCount++;
        this.totalBytes += packet.size || 0;
        
        // Track unique IPs for filters
        if (packet.src_ip && !this.uniqueSrcIPs.has(packet.src_ip)) {
            this.uniqueSrcIPs.add(packet.src_ip);
            this.addIPToFilter('filter-src-ip', packet.src_ip);
        }
        if (packet.dst_ip && !this.uniqueDstIPs.has(packet.dst_ip)) {
            this.uniqueDstIPs.add(packet.dst_ip);
            this.addIPToFilter('filter-dst-ip', packet.dst_ip);
        }
        
        // Limit stored packets
        if (this.packets.length > this.maxStoredPackets) {
            this.packets.shift();
            const tbody = document.getElementById('packet-tbody');
            if (tbody && tbody.firstChild) {
                tbody.removeChild(tbody.firstChild);
            }
        }
        
        this.renderPacketRow(enrichedPacket);
    }
    
    renderPacketRow(packet) {
        const tbody = document.getElementById('packet-tbody');
        if (!tbody) return;
        
        const row = document.createElement('tr');
        row.className = 'new-row';
        row.dataset.protocol = packet.protocol || '';
        row.dataset.service = this.portToService[packet.dst_port] || '';
        row.dataset.srcIp = packet.src_ip || '';
        row.dataset.dstIp = packet.dst_ip || '';
        row.dataset.dstPort = packet.dst_port || '';
        
        if (packet.is_malicious) {
            row.classList.add('malicious-row');
        }
        
        const time = new Date(packet.timestamp).toLocaleTimeString('en-US', {
            hour12: false,
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit'
        });
        
        const protocol = packet.protocol || 'UNKNOWN';
        const protocolClass = `protocol-${protocol.toLowerCase()}`;
        
        row.innerHTML = `
            <td class="col-time">${time}</td>
            <td class="col-src-addr">${packet.src_ip || '--'}</td>
            <td class="col-src-port">${packet.src_port || '--'}</td>
            <td class="col-dst-addr">${packet.dst_ip || '--'}</td>
            <td class="col-dst-port">${packet.dst_port || '--'}</td>
            <td class="col-protocol ${protocolClass}">${protocol}</td>
            <td class="col-service">${packet.service || '--'}</td>
            <td class="col-bytes">${packet.size || 0}</td>
            <td class="col-packets">${packet.packets || 1}</td>
            <td class="col-info">${packet.info || ''}</td>
        `;
        
        tbody.appendChild(row);
        
        // Auto-scroll to bottom
        const container = document.querySelector('.packet-table-container');
        if (container) {
            container.scrollTop = container.scrollHeight;
        }
        
        // Remove highlight after animation
        setTimeout(() => {
            row.classList.remove('new-row');
        }, 500);
        
        // Apply current filters
        this.applyFiltersToRow(row);
    }
    
    addIPToFilter(selectId, ip) {
        const select = document.getElementById(selectId);
        if (!select) return;
        
        // Check if option already exists
        const exists = Array.from(select.options).some(opt => opt.value === ip);
        if (exists) return;
        
        const option = document.createElement('option');
        option.value = ip;
        option.textContent = ip;
        select.appendChild(option);
    }
    
    resetFilterDropdowns() {
        const srcSelect = document.getElementById('filter-src-ip');
        const dstSelect = document.getElementById('filter-dst-ip');
        
        if (srcSelect) {
            srcSelect.innerHTML = '<option value="">All</option>';
        }
        if (dstSelect) {
            dstSelect.innerHTML = '<option value="">All</option>';
        }
    }
    
    applyFiltersToRow(row) {
        const filters = this.getCurrentFilters();
        const visible = this.rowMatchesFilters(row, filters);
        
        if (visible) {
            row.classList.remove('hidden-row');
        } else {
            row.classList.add('hidden-row');
        }
    }
    
    getCurrentFilters() {
        return {
            protocol: document.getElementById('filter-protocol')?.value || '',
            service: document.getElementById('filter-service')?.value || '',
            srcIp: document.getElementById('filter-src-ip')?.value || '',
            dstIp: document.getElementById('filter-dst-ip')?.value || ''
        };
    }
    
    rowMatchesFilters(row, filters) {
        if (filters.protocol && row.dataset.protocol !== filters.protocol) {
            return false;
        }
        if (filters.service && row.dataset.dstPort !== filters.service) {
            return false;
        }
        if (filters.srcIp && row.dataset.srcIp !== filters.srcIp) {
            return false;
        }
        if (filters.dstIp && row.dataset.dstIp !== filters.dstIp) {
            return false;
        }
        return true;
    }
    
    applyFilters() {
        const tbody = document.getElementById('packet-tbody');
        if (!tbody) return;
        
        const filters = this.getCurrentFilters();
        const rows = tbody.querySelectorAll('tr');
        
        rows.forEach(row => {
            const visible = this.rowMatchesFilters(row, filters);
            if (visible) {
                row.classList.remove('hidden-row');
            } else {
                row.classList.add('hidden-row');
            }
        });
    }
    
    getStats() {
        const duration = this.startTime ? Math.floor((Date.now() - this.startTime) / 1000) : 0;
        const rate = duration > 0 ? Math.round(this.packetCount / duration) : 0;
        
        return {
            packetCount: this.packetCount,
            totalBytes: this.totalBytes,
            duration: duration,
            rate: rate,
            currentRate: this.currentRate,
            mode: this.burstMode ? 'burst' : (this.quietMode ? 'quiet' : 'normal')
        };
    }
    
    displayAlert(alert) {
        const container = document.getElementById('alerts-container');
        if (!container) return;
        
        // Remove "no alerts" message
        const noAlerts = container.querySelector('.no-alerts');
        if (noAlerts) {
            noAlerts.remove();
        }
        
        // Update status
        const statusEl = document.getElementById('security-status');
        if (statusEl) {
            const severity = alert.severity || 'MEDIUM';
            const dotClass = severity === 'CRITICAL' || severity === 'HIGH' 
                ? 'status-critical' 
                : 'status-warning';
            statusEl.innerHTML = `
                <span class="status-dot ${dotClass}"></span>
                <span class="status-text">${severity}</span>
            `;
        }
        
        // Create alert card
        const alertEl = document.createElement('div');
        const alertType = alert.type || 'UNKNOWN';
        const severity = alert.severity || 'MEDIUM';
        
        let alertClass = 'alert-warning';
        if (severity === 'CRITICAL') alertClass = 'alert-critical';
        else if (severity === 'HIGH') alertClass = 'alert-danger';
        
        alertEl.className = `alert-card ${alertClass}`;
        
        const time = new Date(alert.timestamp).toLocaleTimeString('en-US', { hour12: false });
        
        let detailsHtml = '';
        if (alert.details) {
            detailsHtml = Object.entries(alert.details)
                .map(([key, value]) => `<span class="alert-detail">${key.replace(/_/g, ' ')}: ${value}</span>`)
                .join('');
        }
        
        alertEl.innerHTML = `
            <div class="alert-header">
                <span class="alert-title">${alertType.replace(/_/g, ' ')}</span>
                <span class="alert-severity severity-${severity.toLowerCase()}">${severity}</span>
            </div>
            <div class="alert-body">
                <p class="alert-message">${alert.message || 'Security threat detected'}</p>
                <p class="alert-source">Source: ${alert.source_ip || 'Unknown'}</p>
                ${detailsHtml ? `<div class="alert-details">${detailsHtml}</div>` : ''}
            </div>
            <div class="alert-meta">${time}</div>
        `;
        
        container.insertBefore(alertEl, container.firstChild);
        
        // Auto-restore status after 30 seconds
        setTimeout(() => {
            const currentAlerts = container.querySelectorAll('.alert-card').length;
            if (currentAlerts <= 1 && statusEl) {
                statusEl.innerHTML = `
                    <span class="status-dot status-normal"></span>
                    <span class="status-text">Normal</span>
                `;
            }
        }, 30000);
    }
}

// Global instance
const packetSimulator = new PacketSimulator();

// Global filter function (called from HTML)
function applyFilters() {
    packetSimulator.applyFilters();
}