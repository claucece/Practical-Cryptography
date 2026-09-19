#!/usr/bin/env python3
import json, re
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        email = parse_qs(urlparse(self.path).query).get("email", [""])[0]
        if re.fullmatch(r"[^@\s\"']+@[^@\s\"']+", email):
            code, body = 200, json.dumps({"email": email, "age": 7, "role": "user"})
        else:
            code, body = 400, f'Bad Request. The Email "{email}" is invalid.'
        self.send_response(code)
        self.send_header("Content-Type", "application/json" if code == 200 else "text/plain")
        self.send_header("Content-Length", str(len(body.encode())))
        self.end_headers()
        self.wfile.write(body.encode())

HTTPServer(("127.0.0.1", 8080), Handler).serve_forever()
