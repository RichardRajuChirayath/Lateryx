
import http.server
import socketserver
import json
import os
import time
from threading import Thread
from pathlib import Path
from .scanner import TerraformScanner
from .main import InfrastructureGraph
from .intelligence import get_intelligence

# Configuration
PORT = 9991
WATCH_DIR = "."

class SecurityHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/status':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            
            result = self.perform_scan()
            self.wfile.write(json.dumps(result).encode())
        else:
            self.send_response(404)
            self.end_headers()

    def perform_scan(self):
        """Runs the scan logic and returns a simplified JSON result"""
        try:
            scanner = TerraformScanner()
            scan_result = scanner.scan_directory(os.getcwd())
            
            if not scan_result.success or not scan_result.graph:
                return {
                    "active": True,
                    "is_safe": True,
                    "findings": [],
                    "stats": {"resources": 0}
                }

            graph = scan_result.graph
            attack_paths = graph.find_all_attack_paths()
            intel = get_intelligence()
            
            findings = []
            for path in attack_paths:
                 sensitive_node = path.path[-1]
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
                    "resources": graph.graph.number_of_nodes() - 2
                }
            }
        except Exception as e:
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
    
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("", PORT), SecurityHandler) as httpd:
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n🛑 Stopping Sentinel...")

if __name__ == "__main__":
    start_server()
