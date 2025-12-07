/**
 * Dashboard Controller
 * 
 * Handles both LIVE and DEMO modes with appropriate behavior.
 */

let protocolChart = null;
let trafficChart = null;
let trafficData = [];
const MAX_TRAFFIC_POINTS = 30;

// =============================================================================
// Legal Notice Functions
// =============================================================================

function checkLegalConsent() {
    if(!IS_LIVE_MODE){
        showDashboard();
        return;
    }
    const consent = localStorage.getItem('legal_consent_accepted');
    const consentTime = localStorage.getItem('legal_consent_time');
    
    // Check if consent was given within last 24 hours
    if (consent === 'true' && consentTime) {
        const hoursSinceConsent = (Date.now() - parseInt(consentTime)) / (1000 * 60 * 60);
        if (hoursSinceConsent < 24) {
            // Valid consent exists, show dashboard
            showDashboard();
            return;
        }
    }
    
    // No valid consent, show popup
    showLegalPopup();
}

function showLegalPopup() {
    const overlay = document.getElementById('legal-overlay');
    const dashboard = document.getElementById('dashboard-main');
    
    if (overlay) overlay.classList.remove('hidden');
    if (dashboard) dashboard.style.display = 'none';
}

function showDashboard() {
    const overlay = document.getElementById('legal-overlay');
    const dashboard = document.getElementById('dashboard-main');
    
    if (overlay) overlay.classList.add('hidden');
    if (dashboard) dashboard.style.display = 'block';
    
    // Initialize dashboard components
    initializeDashboard();
}

function acceptLegal() {
    // Store consent
    localStorage.setItem('legal_consent_accepted', 'true');
    localStorage.setItem('legal_consent_time', Date.now().toString());
    
    console.log('[Dashboard] Legal consent accepted');
    
    // Clear any existing server-side data for fresh session
    fetch('/api/clear-alerts', { method: 'POST' })
        .then(() => console.log('[Dashboard] Server data cleared for new session'))
        .catch(err => console.log('[Dashboard] Could not clear server data:', err));
    
    // Show dashboard
    showDashboard();
}

function declineLegal() {
    console.log('[Dashboard] Legal consent declined');
    
    // Clear any existing consent
    localStorage.removeItem('legal_consent_accepted');
    localStorage.removeItem('legal_consent_time');
    
    // Show declined message and close/redirect
    const overlay = document.getElementById('legal-overlay');
    if (overlay) {
        overlay.innerHTML = `
            <div class="legal-popup">
                <div class="legal-header">
                    <h2>Access Denied</h2>
                </div>
                <div class="legal-body" style="text-align: center; padding: 40px;">
                    <p style="font-size: 1.1rem; margin-bottom: 20px;">
                        You must accept the legal terms to use this application.
                    </p>
                    <p style="color: var(--color-gray-500);">
                        This page will close automatically...
                    </p>
                </div>
            </div>
        `;
    }
    
    // Try to close the window or redirect
    setTimeout(() => {
        // Try to close (works if opened via script)
        window.close();
        
        // If still open, redirect to a blank page or show permanent message
        setTimeout(() => {
            document.body.innerHTML = `
                <div style="display: flex; justify-content: center; align-items: center; height: 100vh; background: #1f2937; color: white; font-family: sans-serif; text-align: center;">
                    <div>
                        <h1 style="margin-bottom: 20px;">Access Denied</h1>
                        <p>You must accept the legal terms to use this application.</p>
                        <p style="margin-top: 20px; color: #9ca3af;">Please close this tab.</p>
                    </div>
                </div>
            `;
        }, 1000);
    }, 2000);
}

// =============================================================================
// Initialization
// =============================================================================

document.addEventListener('DOMContentLoaded', () => {
    console.log('[Dashboard] Checking legal consent...');
    
    // Check legal consent first
    checkLegalConsent();
});

function initializeDashboard() {
    console.log('[Dashboard] Initializing in ' + APP_MODE + ' mode...');

    fetch('/api/clear-alerts', { method: 'POST' })
        .then(() => console.log('[Dashboard] Server data cleared for fresh session'))
        .catch(err => console.log('[Dashboard] Could not clear server data:', err));
    
    // Initialize client metrics
    if (typeof clientMetrics !== 'undefined') {
        clientMetrics.init();
    }
    
    // Initialize charts
    initProtocolChart();
    initTrafficChart();
    
    // Setup UI based on mode
    setupModeUI();
    
    // Initial mode check
    updateModeIndicator();
    
    // Regular updates (only mode indicator, not charts)
    setInterval(updateModeIndicator, 3000);
    setInterval(updateLiveAlerts, 2000);
    
    console.log('[Dashboard] Ready');
}

// =============================================================================
// Mode-Based UI Setup
// =============================================================================

function setupModeUI() {
    const startBtn = document.getElementById('btn-start');
    const stopBtn = document.getElementById('btn-stop');
    const attackBtn = document.getElementById('btn-trigger-alert');
    
    if (IS_LIVE_MODE) {
        // Live Mode UI
        if (startBtn) startBtn.textContent = 'Start Capture';
        if (stopBtn) stopBtn.textContent = 'Stop Capture';
        
        // Hide simulate attack button in live mode
        if (attackBtn) {
            attackBtn.style.display = 'none';
        }
        
        // Update placeholder text
        const placeholder = document.getElementById('packet-placeholder');
        if (placeholder) {
            placeholder.textContent = 'Click "Start Capture" to begin capturing real network traffic';
        }
        
        // Check if sniffer is already running
        checkSnifferStatus();
        
    } else {
        // Demo Mode UI
        if (startBtn) startBtn.textContent = 'Start';
        if (stopBtn) stopBtn.textContent = 'Stop';
        
        // Show but disable simulate attack button until simulation starts
        if (attackBtn) {
            attackBtn.style.display = 'inline-block';
            attackBtn.disabled = true;
            attackBtn.title = 'Start simulation first';
        }
        
        // Update placeholder text
        const placeholder = document.getElementById('packet-placeholder');
        if (placeholder) {
            placeholder.textContent = 'Click "Start" to begin the demonstration';
        }
    }
}

// =============================================================================
// Control Functions
// =============================================================================

function handleStart() {
    if (IS_LIVE_MODE) {
        startLiveCapture();
    } else {
        startDemo();
    }
}

function handleStop() {
    if (IS_LIVE_MODE) {
        stopLiveCapture();
    } else {
        stopDemo();
    }
}

// -----------------------------------------------------------------------------
// Live Mode Functions
// -----------------------------------------------------------------------------

async function startLiveCapture() {
    const startBtn = document.getElementById('btn-start');
    const stopBtn = document.getElementById('btn-stop');
    
    // Disable start button while starting
    if (startBtn) {
        startBtn.disabled = true;
        startBtn.textContent = 'Starting...';
    }
    
    try {
        const response = await fetch('/api/sniffer/start', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        });
        
        const data = await response.json();
        
        if (data.success) {
            console.log('[Dashboard] Sniffer started successfully');
            
            if (startBtn) {
                startBtn.disabled = true;
                startBtn.textContent = 'Start Capture';
            }
            if (stopBtn) stopBtn.disabled = false;
            
            // Hide placeholder
            const placeholder = document.getElementById('packet-placeholder');
            if (placeholder) {
                placeholder.classList.add('hidden');
            }
            
            // Reset simulator state for fresh start
            if (typeof packetSimulator !== 'undefined') {
                packetSimulator.packets = [];
                packetSimulator.packetCount = 0;
                packetSimulator.totalBytes = 0;
                packetSimulator.startTime = Date.now();
                packetSimulator.isRunning = true;
            }
            
            // Start updates
            startChartUpdates();
            startPacketPolling();
            startStatsUpdate();
            
        } else {
            console.error('[Dashboard] Failed to start sniffer:', data.error);
            alert('Failed to start capture: ' + (data.error || 'Unknown error'));
            
            if (startBtn) {
                startBtn.disabled = false;
                startBtn.textContent = 'Start Capture';
            }
        }
        
    } catch (error) {
        console.error('[Dashboard] Error starting sniffer:', error);
        alert('Error starting capture. Check console for details.');
        
        if (startBtn) {
            startBtn.disabled = false;
            startBtn.textContent = 'Start Capture';
        }
    }
}

async function stopLiveCapture() {
    const startBtn = document.getElementById('btn-start');
    const stopBtn = document.getElementById('btn-stop');
    
    // Disable stop button while stopping
    if (stopBtn) {
        stopBtn.disabled = true;
        stopBtn.textContent = 'Stopping...';
    }
    
    try {
        const response = await fetch('/api/sniffer/stop', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        });
        
        const data = await response.json();
        
        if (data.success) {
            console.log('[Dashboard] Sniffer stopped successfully');
            
            if (startBtn) startBtn.disabled = false;
            if (stopBtn) {
                stopBtn.disabled = true;
                stopBtn.textContent = 'Stop Capture';
            }
            
            // Stop all polling and updates
            stopPacketPolling();
            stopChartUpdates();
            stopStatsUpdate();
            
            // Mark simulator as stopped
            if (typeof packetSimulator !== 'undefined') {
                packetSimulator.isRunning = false;
            }
            
        } else {
            console.error('[Dashboard] Failed to stop sniffer:', data.error);
            
            if (stopBtn) {
                stopBtn.disabled = false;
                stopBtn.textContent = 'Stop Capture';
            }
        }
        
    } catch (error) {
        console.error('[Dashboard] Error stopping sniffer:', error);
        
        if (stopBtn) {
            stopBtn.disabled = false;
            stopBtn.textContent = 'Stop Capture';
        }
    }
}

async function checkSnifferStatus() {
    try {
        const response = await fetch('/api/sniffer/status');
        const data = await response.json();
        
        if (data.success && data.is_running) {
            // Sniffer is already running
            const startBtn = document.getElementById('btn-start');
            const stopBtn = document.getElementById('btn-stop');
            
            if (startBtn) startBtn.disabled = true;
            if (stopBtn) stopBtn.disabled = false;
            
            const placeholder = document.getElementById('packet-placeholder');
            if (placeholder) {
                placeholder.classList.add('hidden');
            }
            
            // Initialize simulator state
            if (typeof packetSimulator !== 'undefined') {
                packetSimulator.startTime = Date.now();
                packetSimulator.isRunning = true;
            }
            
            startChartUpdates();
            startPacketPolling();
            startStatsUpdate();
        }
        
    } catch (error) {
        console.log('[Dashboard] Could not check sniffer status');
    }
}

// Packet polling for live mode
let packetPollInterval = null;
let displayedPacketTimestamps = new Set();

function startPacketPolling() {
    if (packetPollInterval) return;
    
    // Clear previous tracking
    displayedPacketTimestamps.clear();
    
    packetPollInterval = setInterval(async () => {
        try {
            const response = await fetch('/api/packets?count=100');
            const data = await response.json();
            
            if (data.success && data.packets && data.mode === 'live') {
                data.packets.forEach(packet => {
                    // Create unique key for this packet
                    const packetKey = `${packet.timestamp}_${packet.src_ip}_${packet.dst_ip}_${packet.src_port}_${packet.dst_port}`;
                    
                    // Only add if we haven't displayed this packet yet
                    if (!displayedPacketTimestamps.has(packetKey)) {
                        displayedPacketTimestamps.add(packetKey);
                        
                        if (typeof packetSimulator !== 'undefined') {
                            packetSimulator.addPacket(packet);
                        }
                    }
                });
                
                // Limit the Set size to prevent memory issues
                if (displayedPacketTimestamps.size > 5000) {
                    const entries = Array.from(displayedPacketTimestamps);
                    displayedPacketTimestamps = new Set(entries.slice(-2500));
                }
            }
            
        } catch (error) {
            console.error('[Dashboard] Packet poll error:', error);
        }
    }, 300);
}

function stopPacketPolling() {
    if (packetPollInterval) {
        clearInterval(packetPollInterval);
        packetPollInterval = null;
    }
}

// Stats update interval
let statsInterval = null;

function startStatsUpdate() {
    if (statsInterval) return;
    
    statsInterval = setInterval(updateStats, 1000);
}

function stopStatsUpdate() {
    if (statsInterval) {
        clearInterval(statsInterval);
        statsInterval = null;
    }
}

// -----------------------------------------------------------------------------
// Demo Mode Functions
// -----------------------------------------------------------------------------

function startDemo() {
    if (typeof packetSimulator !== 'undefined') {
        packetSimulator.start();
    }
    
    document.getElementById('btn-start').disabled = true;
    document.getElementById('btn-stop').disabled = false;
    
    // Enable attack button when simulation is running
    const attackBtn = document.getElementById('btn-trigger-alert');
    if (attackBtn) {
        attackBtn.disabled = false;
        attackBtn.title = 'Simulate a security attack';
    }
    
    startChartUpdates();
    startStatsUpdate();
}

function stopDemo() {
    if (typeof packetSimulator !== 'undefined') {
        packetSimulator.stop();
    }
    
    document.getElementById('btn-start').disabled = false;
    document.getElementById('btn-stop').disabled = true;
    
    // Disable attack button when simulation stops
    const attackBtn = document.getElementById('btn-trigger-alert');
    if (attackBtn) {
        attackBtn.disabled = true;
        attackBtn.title = 'Start simulation first';
    }
    
    stopChartUpdates();
    stopStatsUpdate();
}

// -----------------------------------------------------------------------------
// Common Functions
// -----------------------------------------------------------------------------

async function clearData() {
    // Stop any running capture/simulation
    if (IS_LIVE_MODE) {
        await stopLiveCapture();
    } else {
        stopDemo();
    }
    
    // Reset simulator
    if (typeof packetSimulator !== 'undefined') {
        packetSimulator.reset();
    }
    
    // Clear tracking
    displayedPacketTimestamps = new Set();
    
    // Reset buttons
    document.getElementById('btn-start').disabled = false;
    document.getElementById('btn-stop').disabled = true;
    
    // Disable attack button
    const attackBtn = document.getElementById('btn-trigger-alert');
    if (attackBtn && !IS_LIVE_MODE) {
        attackBtn.disabled = true;
        attackBtn.title = 'Start simulation first';
    }
    
    // Reset stats display
    document.getElementById('stat-packets').textContent = '0';
    document.getElementById('stat-rate').textContent = '0';
    document.getElementById('stat-bytes').textContent = '0 KB';
    document.getElementById('stat-duration').textContent = '0s';
    
    // Reset charts
    resetCharts();
    
    // Reset security status
    const statusEl = document.getElementById('security-status');
    if (statusEl) {
        statusEl.innerHTML = `
            <span class="status-dot status-normal"></span>
            <span class="status-text">Normal</span>
        `;
    }
    
    // Clear alerts from UI
    const alertsContainer = document.getElementById('alerts-container');
    if (alertsContainer) {
        alertsContainer.innerHTML = '<div class="no-alerts">No security alerts detected</div>';
    }
    
    // Clear alerts from server
    try {
        await fetch('/api/clear-alerts', { method: 'POST' });
        console.log('[Dashboard] Data cleared');
    } catch (error) {
        console.error('[Dashboard] Failed to clear server data:', error);
    }
}

function triggerAttack() {
    // Only available in demo mode
    if (IS_LIVE_MODE) {
        console.log('[Dashboard] Attack simulation not available in live mode');
        return;
    }
    
    // Only allow if simulation is running
    if (typeof packetSimulator !== 'undefined') {
        if (!packetSimulator.isRunning) {
            alert('Start the simulation first before triggering an attack.');
            return;
        }
        packetSimulator.triggerAttack();
    }
}

// =============================================================================
// Statistics
// =============================================================================

function updateStats() {
    if (typeof packetSimulator === 'undefined') return;
    
    const stats = packetSimulator.getStats();
    
    document.getElementById('stat-packets').textContent = stats.packetCount.toLocaleString();
    document.getElementById('stat-rate').textContent = stats.rate;
    document.getElementById('stat-bytes').textContent = formatBytes(stats.totalBytes);
    document.getElementById('stat-duration').textContent = formatDuration(stats.duration);
}

// =============================================================================
// Mode Indicator
// =============================================================================

async function updateModeIndicator() {
    try {
        const response = await fetch('/api/mode');
        const data = await response.json();
        
        if (data.success) {
            const indicator = document.getElementById('mode-indicator');
            if (!indicator) return;
            
            if (data.mode === 'live') {
                let statusText = 'LIVE MODE';
                
                if (data.sniffer_running) {
                    statusText = 'LIVE - Capturing';
                } else if (data.packet_count > 0) {
                    statusText = 'LIVE - Stopped';
                }
                
                indicator.innerHTML = `
                    <span class="mode-dot mode-real"></span>
                    <span class="mode-text">${statusText}</span>
                `;
                
            } else {
                indicator.innerHTML = `
                    <span class="mode-dot mode-simulated"></span>
                    <span class="mode-text">DEMO MODE</span>
                `;
            }
        }
        
    } catch (error) {
        console.error('[Dashboard] Mode check failed:', error);
    }
}

// =============================================================================
// Live Alerts
// =============================================================================

async function updateLiveAlerts() {
    // Only fetch in live mode when running
    if (!IS_LIVE_MODE) return;
    
    try {
        const response = await fetch('/api/live-alerts');
        const data = await response.json();
        
        if (data.success && data.alerts && data.alerts.length > 0) {
            data.alerts.forEach(alert => {
                displayLiveAlert(alert);
            });
        }
        
    } catch (error) {
        console.error('[Dashboard] Live alerts fetch failed:', error);
    }
}

function displayLiveAlert(alert) {
    const container = document.getElementById('alerts-container');
    if (!container) return;
    
    // Check if alert already displayed
    const alertId = alert.id || (alert.alert_type + '_' + alert.timestamp);
    const existingAlert = container.querySelector(`[data-alert-id="${alertId}"]`);
    if (existingAlert) return;
    
    // Remove "no alerts" message
    const noAlerts = container.querySelector('.no-alerts');
    if (noAlerts) {
        noAlerts.remove();
    }
    
    // Update security status
    const statusEl = document.getElementById('security-status');
    if (statusEl) {
        const severity = alert.severity || 'MEDIUM';
        const dotClass = (severity === 'CRITICAL' || severity === 'HIGH') 
            ? 'status-critical' 
            : 'status-warning';
        statusEl.innerHTML = `
            <span class="status-dot ${dotClass}"></span>
            <span class="status-text">${severity}</span>
        `;
    }
    
    // Create alert card
    const alertEl = document.createElement('div');
    const alertType = alert.alert_type || alert.type || 'UNKNOWN';
    const severity = alert.severity || 'MEDIUM';
    const severityLower = severity.toLowerCase();
    
    let alertClass = 'alert-warning';
    if (severity === 'CRITICAL') alertClass = 'alert-critical';
    else if (severity === 'HIGH') alertClass = 'alert-danger';
    
    alertEl.className = `alert-card ${alertClass}`;
    alertEl.dataset.alertId = alertId;
    
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
            <span class="alert-severity severity-${severityLower}">${severity}</span>
        </div>
        <div class="alert-body">
            <p class="alert-message">${alert.message || 'Security threat detected'}</p>
            <p class="alert-source">Source: ${alert.source_ip || 'Unknown'}</p>
            ${detailsHtml ? `<div class="alert-details">${detailsHtml}</div>` : ''}
        </div>
        <div class="alert-meta">${time} (Live)</div>
    `;
    
    container.insertBefore(alertEl, container.firstChild);
}

// =============================================================================
// Charts
// =============================================================================

function initProtocolChart() {
    const ctx = document.getElementById('protocol-chart');
    if (!ctx) return;
    
    protocolChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['TCP', 'UDP', 'HTTP', 'HTTPS', 'TLS', 'DNS', 'ICMP', 'ICMPv6', 'SSH', 'FTP', 'ARP', 'IPv6'],
            datasets: [{
                data: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                backgroundColor: [
                    '#3b82f6',  // TCP
                    '#10b981',  // UDP
                    '#f59e0b',  // HTTP
                    '#f97316',  // HTTPS
                    '#f97316',  // TLS
                    '#a855f7',  // DNS
                    '#06b6d4',  // ICMP
                    '#0891b2',  // ICMPv6
                    '#8b5cf6',  // SSH
                    '#ec4899',  // FTP
                    '#d946ef',  // ARP
                    '#64748b'   // IPv6
                ],
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    position: 'right',
                    labels: {
                        usePointStyle: true,
                        padding: 10,
                        font: { size: 10 }
                    }
                }
            },
            cutout: '55%'
        }
    });
}

function initTrafficChart() {
    const ctx = document.getElementById('traffic-chart');
    if (!ctx) return;
    
    trafficChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'Packets/sec',
                data: [],
                borderColor: '#3b82f6',
                backgroundColor: 'rgba(59, 130, 246, 0.1)',
                fill: true,
                tension: 0.4,
                pointRadius: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            scales: {
                x: {
                    display: true,
                    grid: { display: false },
                    ticks: { maxTicksLimit: 5, font: { size: 9 } }
                },
                y: {
                    display: true,
                    beginAtZero: true,
                    grid: { color: 'rgba(0,0,0,0.05)' },
                    ticks: { font: { size: 9 } }
                }
            },
            plugins: {
                legend: { display: false }
            },
            animation: { duration: 200 }
        }
    });
}

let chartInterval = null;

function startChartUpdates() {
    if (chartInterval) return;
    
    chartInterval = setInterval(() => {
        updateProtocolChart();
        updateTrafficChart();
    }, 2000);
}

function stopChartUpdates() {
    if (chartInterval) {
        clearInterval(chartInterval);
        chartInterval = null;
    }
}

function updateProtocolChart() {
    if (!protocolChart) return;
    if (typeof packetSimulator === 'undefined') return;
    
    // Count protocols from displayed packets
    const protocolCounts = {};
    const protocols = ['TCP', 'UDP', 'HTTP', 'HTTPS', 'TLS', 'DNS', 'ICMP', 'ICMPv6', 'SSH', 'FTP', 'ARP', 'IPv6'];
    
    // Initialize all to 0
    protocols.forEach(p => protocolCounts[p] = 0);
    
    // Count from packets
    packetSimulator.packets.forEach(packet => {
        const proto = packet.protocol || 'UNKNOWN';
        if (proto in protocolCounts) {
            protocolCounts[proto]++;
        }
    });
    
    // Update chart
    protocolChart.data.datasets[0].data = protocols.map(p => protocolCounts[p]);
    protocolChart.update('none');
}

function updateTrafficChart() {
    if (!trafficChart) return;
    if (typeof packetSimulator === 'undefined') return;
    
    const stats = packetSimulator.getStats();
    const now = new Date().toLocaleTimeString('en-US', {
        hour12: false, minute: '2-digit', second: '2-digit'
    });
    
    trafficData.push({ time: now, value: stats.rate });
    
    if (trafficData.length > MAX_TRAFFIC_POINTS) {
        trafficData.shift();
    }
    
    trafficChart.data.labels = trafficData.map(d => d.time);
    trafficChart.data.datasets[0].data = trafficData.map(d => d.value);
    trafficChart.update('none');
}

function resetCharts() {
    // Stop updates first
    stopChartUpdates();
    
    // Reset protocol chart
    if (protocolChart) {
        protocolChart.data.datasets[0].data = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        protocolChart.update();
    }
    
    // Reset traffic chart
    trafficData = [];
    if (trafficChart) {
        trafficChart.data.labels = [];
        trafficChart.data.datasets[0].data = [];
        trafficChart.update();
    }
}

// =============================================================================
// Utilities
// =============================================================================

function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB'];
    const k = 1024;
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + units[i];
}

function formatDuration(seconds) {
    if (seconds < 60) return `${seconds}s`;
    if (seconds < 3600) {
        const m = Math.floor(seconds / 60);
        const s = seconds % 60;
        return `${m}m ${s}s`;
    }
    const h = Math.floor(seconds / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    return `${h}h ${m}m`;
}