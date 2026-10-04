#!/usr/bin/env python3
"""
authentik-pangolin-sync.py
Listens for Authentik authentication webhooks, extracts true client WAN IPs,
and dynamically registers temporary firewall/proxy allowances in Pangolin.
"""

import os
import sys
import json
import logging
from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.request
import urllib.error

# --- Environment Configurations ---
LISTEN_HOST = os.getenv("LISTEN_HOST", "0.0.0.0")
LISTEN_PORT = int(os.getenv("LISTEN_PORT", "9190"))
WEBHOOK_SECRET = os.getenv("AUTHENTIK_WEBHOOK_SECRET")

PANGOLIN_API_URL = os.getenv("PANGOLIN_API_URL", "http://10.30.30.30:8080/api/v1")
PANGOLIN_API_KEY = os.getenv("PANGOLIN_API_KEY")
TARGET_SERVICE_ID = os.getenv("PANGOLIN_SERVICE_ID", "jellyfin-core")
RULE_TTL_SECONDS = int(os.getenv("RULE_TTL_SECONDS", "86400"))  # Default 24 hours

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)

def update_pangolin_whitelist(client_ip: str, user_email: str) -> bool:
    """Sends an authenticated request to Pangolin's API to whitelist the remote IP."""
    endpoint = f"{PANGOLIN_API_URL}/services/{TARGET_SERVICE_ID}/whitelist"
    headers = {
        "Authorization": f"Bearer {PANGOLIN_API_KEY}",
        "Content-Type": "application/json",
    }
    payload = {
        "ip": client_ip,
        "comment": f"Auto-synced via Authentik login: {user_email}",
        "ttl": RULE_TTL_SECONDS,
    }
    
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(endpoint, data=data, headers=headers, method="POST")
    
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            if response.status in (200, 201):
                logging.info(f"Successfully whitelisted {client_ip} for {user_email} on Pangolin.")
                return True
            logging.warning(f"Pangolin API returned unexpected status {response.status}")
            return False
    except urllib.error.HTTPError as e:
        logging.error(f"Pangolin API Error {e.code}: {e.read().decode('utf-8')}")
        return False
    except Exception as e:
        logging.error(f"Failed to communicate with Pangolin: {e}")
        return False

class AuthentikWebhookHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        # 1. Validate Secret Authorization Header
        auth_header = self.headers.get("X-Authentik-Secret")
        if not WEBHOOK_SECRET or auth_header != WEBHOOK_SECRET:
            logging.warning("Unauthorized webhook invocation attempt rejected.")
            self.send_response(401)
            self.end_headers()
            self.wfile.write(b'{"error": "Unauthorized"}')
            return

        # 2. Ingest Payload
        content_length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_length)
        
        try:
            event = json.loads(post_data.decode("utf-8"))
        except json.JSONDecodeError:
            self.send_response(400)
            self.end_headers()
            return

        # 3. Extract True Client IP (resolves Cloudflare & upstream proxy headers)
        user_email = event.get("context", {}).get("authorized_user", {}).get("email", "unknown")
        headers_map = event.get("context", {}).get("http_headers", {})
        
        # Priority order: CF-Connecting-IP -> X-Forwarded-For -> remote IP
        client_ip = (
            headers_map.get("cf-connecting-ip")
            or headers_map.get("x-real-ip")
            or headers_map.get("x-forwarded-for", "").split(",")[0].strip()
            or event.get("context", {}).get("client_ip")
        )

        if not client_ip:
            logging.error(f"No valid client IP could be parsed for user {user_email}.")
            self.send_response(422)
            self.end_headers()
            return

        logging.info(f"Received valid login event for '{user_email}' originating from {client_ip}")

        # 4. Trigger Pangolin Rule Update
        success = update_pangolin_whitelist(client_ip, user_email)
        
        if success:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status": "whitelisted"}')
        else:
            self.send_response(502)
            self.end_headers()

    def do_GET(self):
        """Health check endpoint for Uptime Kuma."""
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"status": "healthy"}')

    def log_message(self, format, *args):
        # Suppress default noisy stdlib HTTP access logs
        return

def main():
    if not PANGOLIN_API_KEY:
        logging.error("PANGOLIN_API_KEY environment variable is missing. Halting.")
        sys.exit(1)
        
    server_address = (LISTEN_HOST, LISTEN_PORT)
    httpd = HTTPServer(server_address, AuthentikWebhookHandler)
    logging.info(f"Authentik-to-Pangolin sync daemon listening on {LISTEN_HOST}:{LISTEN_PORT}")
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        logging.info("Shutting down daemon...")
        httpd.server_close()

if __name__ == "__main__":
    main()