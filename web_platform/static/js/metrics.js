/**
 * Client Metrics Module
 * 
 * Captures REAL performance data from the visitor's browser
 * using the Performance API and Network Information API.
 */

class ClientMetrics {
    constructor() {
        this.metrics = {};
        this.initialized = false;
    }
    
    /**
     * Initialize and collect all metrics
     */
    init() {
        if (this.initialized) return;
        
        // Wait for page to fully load
        if (document.readyState === 'complete') {
            this.collectMetrics();
        } else {
            window.addEventListener('load', () => {
                // Small delay to ensure all timing data is available
                setTimeout(() => this.collectMetrics(), 100);
            });
        }
        
        this.initialized = true;
    }
    
    /**
     * Collect all available metrics
     */
    collectMetrics() {
        this.collectNavigationTiming();
        this.collectConnectionInfo();
        this.updateDisplay();
        
        console.log('[ClientMetrics] Collected:', this.metrics);
    }
    
    /**
     * Collect Navigation Timing metrics
     */
    collectNavigationTiming() {
        // Use Navigation Timing API Level 2 if available
        const entries = performance.getEntriesByType('navigation');
        
        if (entries.length > 0) {
            const nav = entries[0];
            
            this.metrics.dnsLookup = Math.round(nav.domainLookupEnd - nav.domainLookupStart);
            this.metrics.tcpConnect = Math.round(nav.connectEnd - nav.connectStart);
            this.metrics.tlsHandshake = Math.round(nav.secureConnectionStart > 0 
                ? nav.connectEnd - nav.secureConnectionStart 
                : 0);
            this.metrics.ttfb = Math.round(nav.responseStart - nav.requestStart);
            this.metrics.contentDownload = Math.round(nav.responseEnd - nav.responseStart);
            this.metrics.domParsing = Math.round(nav.domContentLoadedEventEnd - nav.responseEnd);
            this.metrics.pageLoad = Math.round(nav.loadEventEnd - nav.startTime);
            
        } else if (performance.timing) {
            // Fallback to Navigation Timing API Level 1
            const timing = performance.timing;
            
            this.metrics.dnsLookup = timing.domainLookupEnd - timing.domainLookupStart;
            this.metrics.tcpConnect = timing.connectEnd - timing.connectStart;
            this.metrics.ttfb = timing.responseStart - timing.requestStart;
            this.metrics.pageLoad = timing.loadEventEnd - timing.navigationStart;
        }
        
        // Ensure non-negative values
        Object.keys(this.metrics).forEach(key => {
            if (this.metrics[key] < 0) this.metrics[key] = 0;
        });
    }
    
    /**
     * Collect Connection/Network information
     */
    collectConnectionInfo() {
        // Network Information API (not available in all browsers)
        if (navigator.connection) {
            const conn = navigator.connection;
            
            this.metrics.connectionType = conn.effectiveType || 'unknown';
            this.metrics.downlink = conn.downlink || null; // Mbps
            this.metrics.rtt = conn.rtt || null; // ms
            this.metrics.saveData = conn.saveData || false;
            
        } else {
            this.metrics.connectionType = 'N/A';
            this.metrics.downlink = null;
            this.metrics.rtt = null;
        }
        
        // Additional browser info
        this.metrics.online = navigator.onLine;
        this.metrics.userAgent = navigator.userAgent;
        this.metrics.platform = navigator.platform || 'Unknown';
        this.metrics.language = navigator.language || 'Unknown';
        this.metrics.screenWidth = window.screen.width;
        this.metrics.screenHeight = window.screen.height;
    }
    
    /**
     * Update the dashboard display with collected metrics
     */
    updateDisplay() {
        // Latency (TTFB)
        const latencyEl = document.getElementById('client-latency');
        if (latencyEl) {
            latencyEl.textContent = this.metrics.ttfb !== undefined 
                ? `${this.metrics.ttfb} ms` 
                : '--';
        }
        
        // DNS Lookup
        const dnsEl = document.getElementById('client-dns');
        if (dnsEl) {
            dnsEl.textContent = this.metrics.dnsLookup !== undefined 
                ? `${this.metrics.dnsLookup} ms` 
                : '--';
        }
        
        // Connection Type
        const connEl = document.getElementById('client-connection');
        if (connEl) {
            let connText = this.metrics.connectionType;
            if (connText && connText !== 'N/A') {
                connText = connText.toUpperCase();
            }
            connEl.textContent = connText || '--';
        }
        
        // Page Load
        const loadEl = document.getElementById('client-load');
        if (loadEl) {
            if (this.metrics.pageLoad !== undefined && this.metrics.pageLoad > 0) {
                const seconds = (this.metrics.pageLoad / 1000).toFixed(2);
                loadEl.textContent = `${seconds} s`;
            } else {
                loadEl.textContent = '--';
            }
        }
    }
    
    /**
     * Get all collected metrics
     */
    getMetrics() {
        return { ...this.metrics };
    }
    
    /**
     * Get a formatted summary for display
     */
    getSummary() {
        return {
            latency: this.metrics.ttfb ? `${this.metrics.ttfb} ms` : 'N/A',
            dnsLookup: this.metrics.dnsLookup ? `${this.metrics.dnsLookup} ms` : 'N/A',
            connectionType: this.metrics.connectionType || 'N/A',
            pageLoad: this.metrics.pageLoad ? `${(this.metrics.pageLoad / 1000).toFixed(2)} s` : 'N/A',
            platform: this.metrics.platform,
            online: this.metrics.online ? 'Yes' : 'No'
        };
    }
}

// Create global instance
const clientMetrics = new ClientMetrics();