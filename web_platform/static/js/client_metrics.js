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
    
    init() {
        if (this.initialized) return;
        
        if (document.readyState === 'complete') {
            this.collectMetrics();
        } else {
            window.addEventListener('load', () => {
                setTimeout(() => this.collectMetrics(), 100);
            });
        }
        
        this.initialized = true;
    }
    
    collectMetrics() {
        this.collectNavigationTiming();
        this.collectConnectionInfo();
        this.updateDisplay();
        
        console.log('[ClientMetrics] Collected:', this.metrics);
    }
    
    collectNavigationTiming() {
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
            const timing = performance.timing;
            
            this.metrics.dnsLookup = timing.domainLookupEnd - timing.domainLookupStart;
            this.metrics.tcpConnect = timing.connectEnd - timing.connectStart;
            this.metrics.ttfb = timing.responseStart - timing.requestStart;
            this.metrics.pageLoad = timing.loadEventEnd - timing.navigationStart;
        }
        
        Object.keys(this.metrics).forEach(key => {
            if (this.metrics[key] < 0) this.metrics[key] = 0;
        });
    }
    
    collectConnectionInfo() {
        if (navigator.connection) {
            const conn = navigator.connection;
            
            this.metrics.connectionType = conn.effectiveType || 'unknown';
            this.metrics.downlink = conn.downlink || null;
            this.metrics.rtt = conn.rtt || null;
            this.metrics.saveData = conn.saveData || false;
            
        } else {
            this.metrics.connectionType = 'N/A';
            this.metrics.downlink = null;
            this.metrics.rtt = null;
        }
        
        this.metrics.online = navigator.onLine;
        this.metrics.platform = navigator.platform || 'Unknown';
    }
    
    updateDisplay() {
        const latencyEl = document.getElementById('client-latency');
        if (latencyEl) {
            latencyEl.textContent = this.metrics.ttfb !== undefined 
                ? `${this.metrics.ttfb} ms` 
                : '--';
        }
        
        const dnsEl = document.getElementById('client-dns');
        if (dnsEl) {
            dnsEl.textContent = this.metrics.dnsLookup !== undefined 
                ? `${this.metrics.dnsLookup} ms` 
                : '--';
        }
        
        const connEl = document.getElementById('client-connection');
        if (connEl) {
            let connText = this.metrics.connectionType;
            if (connText && connText !== 'N/A') {
                connText = connText.toUpperCase();
            }
            connEl.textContent = connText || '--';
        }
        
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
    
    getMetrics() {
        return { ...this.metrics };
    }
}

// Global instance
const clientMetrics = new ClientMetrics();