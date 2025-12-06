
"""
Packet Sniffer - Single Entry Point

Usage:
    sudo python3 runner.py      # Live mode (real traffic)
    python3 runner.py           # Demo mode (simulated traffic)
"""

import os
import sys
import threading
import signal
import webbrowser
import time
from datetime import datetime

# Add web_platform to path FIRST
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'web_platform'))


# =============================================================================
# Mode Detection
# =============================================================================

class AppMode:
    LIVE = "live"
    DEMO = "demo"


def detect_mode():
    """Auto-detect which mode to run in."""
    
    # Check 1: Running on Heroku?
    if os.environ.get('DYNO'):
        return AppMode.DEMO
    
    # Check 2: Running with sudo/root? (Linux/Mac)
    if hasattr(os, 'geteuid'):
        if os.geteuid() == 0:
            return AppMode.LIVE
    
    # Check 3: Windows admin check
    if sys.platform == 'win32':
        try:
            import ctypes
            if ctypes.windll.shell32.IsUserAnAdmin():
                return AppMode.LIVE
        except:
            pass
    
    return AppMode.DEMO


# =============================================================================
# Sniffer Manager (For Live Mode)
# =============================================================================

class SnifferManager:
    """Manages the packet sniffer in a background thread."""
    
    def __init__(self):
        self.engine = None
        self.thread = None
        self.is_running = False
        self.error = None
        self.start_time = None
        
    def start(self, web_url="http://127.0.0.1:8000"):
        """Start the packet sniffer."""
        if self.is_running:
            return {"success": False, "error": "Already running"}
        
        try:
            from core_sniffer.capture_engine import CaptureEngine, CaptureConfig
            
            config = CaptureConfig(
                enable_security=True,
                store_packets=False,
                enable_web=True,
                web_url=web_url
            )
            
            self.engine = CaptureEngine(config)
            self.error = None
            self.start_time = datetime.now()
            
            # Start in background thread
            self.thread = threading.Thread(target=self._run_capture, daemon=True)
            self.thread.start()
            
            # Wait briefly to check if it started
            time.sleep(0.5)
            
            if self.error:
                return {"success": False, "error": self.error}
            
            self.is_running = True
            return {"success": True, "message": "Sniffer started"}
            
        except ImportError as e:
            self.error = f"Import error: {e}"
            return {"success": False, "error": self.error}
        except Exception as e:
            self.error = str(e)
            return {"success": False, "error": self.error}
    
    def _run_capture(self):
        """Internal capture loop."""
        try:
            self.engine.start(blocking=True)
        except PermissionError:
            self.error = "Permission denied. Run with sudo."
            self.is_running = False
        except Exception as e:
            self.error = str(e)
            self.is_running = False
        finally:
            self.is_running = False
    
    def stop(self):
        """Stop the packet sniffer."""
        if not self.is_running and not self.engine:
            return {"success": False, "error": "Not running"}
        
        try:
            if self.engine:
                self.engine.stop()
            self.is_running = False
            return {"success": True, "message": "Sniffer stopped"}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def get_status(self):
        """Get current sniffer status."""
        status = {
            "is_running": self.is_running,
            "error": self.error,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "duration_seconds": 0,
            "packets_captured": 0,
            "interface": None
        }
        
        if self.start_time:
            duration = (datetime.now() - self.start_time).total_seconds()
            status["duration_seconds"] = int(duration)
        
        if self.engine:
            try:
                engine_status = self.engine.get_status()
                status["packets_captured"] = engine_status.get("packets_captured", 0)
                status["interface"] = engine_status.get("interface", None)
            except:
                pass
        
        return status


# Global sniffer manager
sniffer_manager = SnifferManager()


# =============================================================================
# Flask App Setup
# =============================================================================

def create_app(mode):
    """Create and configure Flask application."""
    
    from app import app
    
    # Store mode and manager in config
    app.config['SNIFFER_MODE'] = mode
    app.config['SNIFFER_MANAGER'] = sniffer_manager
    
    # Disable Flask logging
    import logging
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)
    
    return app


# =============================================================================
# Browser Auto-Open
# =============================================================================

def open_browser(url, delay=1.5):
    """Open browser after a short delay."""
    def _open():
        time.sleep(delay)
        webbrowser.open(url)
    
    thread = threading.Thread(target=_open, daemon=True)
    thread.start()


# =============================================================================
# Main Entry Point
# =============================================================================

def main():
    """Main entry point."""
    
    # Detect mode
    mode = detect_mode()
    
    # Create Flask app
    app = create_app(mode)
    
    # Handle shutdown
    def signal_handler(signum, frame):
        if mode == AppMode.LIVE and sniffer_manager.is_running:
            sniffer_manager.stop()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Auto-open browser
    url = "http://127.0.0.1:8000"
    open_browser(url)
    
    # Run Flask (silent)
    port = int(os.environ.get('PORT', 8000))
    app.run(
        host='0.0.0.0',
        port=port,
        debug=False,
        threaded=True,
        use_reloader=False
    )


if __name__ == '__main__':
    main()

