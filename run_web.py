
"""
FullMute Web Server Entry Point
Run this file to start the web interface
"""
import sys
import os


sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

import uvicorn
from fullmute.web.config import config
from fullmute.web.database import init_web_db
from fullmute.web.scheduler import init_scheduler


def main():
    """Initialize and run the web server"""
    print("""
    ╔═══════════════════════════════════════════════════════╗
    ║                                                       ║
    ║   FullMute Web Interface                              ║
    ║   Advanced Web Security Scanner                       ║
    ║                                                       ║
    ╚═══════════════════════════════════════════════════════╝
    """)
    
    
    print("[*] Initializing database...")
    init_web_db()
    print("[+] Database ready")
    
    
    print("[*] Starting scan scheduler...")
    init_scheduler()
    print("[+] Scheduler ready")
    
    
    print(f"\n[*] Starting web server on http://{config.host}:{config.port}")
    print("[*] Press Ctrl+C to stop\n")
    
    uvicorn.run(
        "fullmute.web.app:app",
        host=config.host,
        port=config.port,
        reload=config.debug,
        log_level="info"
    )


if __name__ == "__main__":
    main()
