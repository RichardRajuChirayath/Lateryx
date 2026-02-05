
import http.server
import socketserver
import json
import os
import time
from threading import Thread
from pathlib import Path
from .cli import scan_directory_internal  # We'll need to refactor cli.py slightly or reproduce logic

# Configuration
PORT = 9991
WATCH_DIR = "."

class SecurityHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/status':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')  # Allow browser extension
            self.end_headers()
            
            # Run a quick scan (cached ideally, but live for now)
            # For speed, we might want to cache this and update via a file watcher
            result = self.perform_scan()
            self.wfile.write(json.dumps(result).encode())
        else:
            self.send_response(404)
            self.end_headers()

    def perform_scan(self):
        """Runs the scan logic and returns a simplified JSON result"""
        # Note: In a real implementation, we would import the scanner properly.
        # This is a lightweight wrapper around the existing logic.
        try:
            from .main import InfrastructureGraph
            from .scanners.terraform_scanner import TerraformScanner
            from .intelligence import get_intelligence
            
            scanner = TerraformScanner()
            graph = scanner.scan_directory(os.getcwd())
            attack_paths = graph.find_all_attack_paths()
            intel = get_intelligence()
            
            findings = []
            for path in attack_paths:
                 sensitive_node = path.path[-1] # Simplification
                 res_type = graph.graph.nodes[sensitive_node].get('type', 'unknown')
                 impact = intel.translate_breach("ATTACK_PATH", res_type, sensitive_node)
                 findings.append({
                     "severity": "CRITICAL" if path.risk_score > 0.7 else "HIGH",
                     "description": impact.impact_summary
                 })
            
            return {
                "active": True,
                "is_safe": len(attack_paths) == 0,
                "findings": findings,
                "stats": {
                    "resources": graph.graph.number_of_nodes()
                }
            }
        except Exception as e:
            # Fallback if scan fails (e.g., syntax error in TF)
            return {
                "active": True,
                "error": str(e),
                "is_safe": False
            }

def start_server():
    """Starts the local security server"""
    print(f"🛡️ Lateryx Local Sentinel running on http://localhost:{PORT}")
    print(f"   Watching: {os.path.abspath(WATCH_DIR)}")
    print("   Extension will now sync with this process.")
    
    with socketserver.TCPServer(("", PORT), SecurityHandler) as httpd:
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n🛑 Stopping Sentinel...")

if __name__ == "__main__":
    start_server()
