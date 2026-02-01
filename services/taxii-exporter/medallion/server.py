import os
from http.server import SimpleHTTPRequestHandler, HTTPServer

HOST = os.getenv("TAXII_HOST", "0.0.0.0")
PORT = int(os.getenv("TAXII_PORT", "9000"))

# Minimal demo: serve exported STIX bundle as a file over HTTP.
# In your presentation: explain TAXII is normally structured endpoints; for demo, keep it simple & reliable.

class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory="/data", **kwargs)

if __name__ == "__main__":
    httpd = HTTPServer((HOST, PORT), Handler)
    print(f"[taxii-demo-server] serving /data on http://{HOST}:{PORT}")
    httpd.serve_forever()
