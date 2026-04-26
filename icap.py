#!/usr/bin/env python3
import socketserver
import gzip
from pyicap import ICAPServer, BaseICAPRequestHandler
import os

PHRASELIST_DIR = "./phraselist"



KEYWORDS = [
    "gambling", "casino", "drugs", "malware",
    "phishing", "keyword1", "keyword2"
]







BLOCK_PAGE = b"<html><body style='background-color: red;color:white;font-family:sans-serif;'><h1>Access Blocked</h1><p>This page was blocked by your network policy.</p></body></html>"


class KeywordFilter(BaseICAPRequestHandler):

    def handle(self):
        try:
            super().handle()
        except ConnectionResetError:
            pass

    def keyword_filter_OPTIONS(self):
        self.set_icap_response(200)
        self.set_icap_header(b'Methods', b'REQMOD, RESPMOD')
        self.set_icap_header(b'Service', b'Keyword Filter 1.0')
        self.set_icap_header(b'Preview', b'0')
        self.set_icap_header(b'Transfer-Complete', b'*')
        self.set_icap_header(b'Max-Connections', b'100')
        self.send_headers(False)

    def keyword_filter_REQMOD(self):
        body = b""
        if self.has_body:
            while True:
                chunk = self.read_chunk()
                if chunk == b"":
                    break
                body += chunk

        url = self.enc_req_headers.get(b'host', [b''])[0].decode('utf-8', errors='ignore')
        print(f"[DEBUG] REQMOD URL: {url}")

        BLOCKED_URLS = ["gambling.com", "malware.com", "baddomain.com"]

        for blocked in BLOCKED_URLS:
            if blocked.lower() in url.lower():
                print(f"[BLOCKED REQUEST] URL matched: {blocked}")
                self.set_icap_response(200)
                self.set_enc_status(b'HTTP/1.1 403 Forbidden')
                self.set_enc_header(b'Content-Type', b'text/html')
                self.set_enc_header(b'Content-Length', str(len(BLOCK_PAGE)).encode())
                self.send_headers(True)
                self.write_chunk(BLOCK_PAGE)
                self.write_chunk(b"")
                return

        print(f"[DEBUG] Passing through: {url}")
        self.set_icap_response(200)
        self.set_enc_request(b" ".join(self.enc_req))
        for header, values in self.enc_req_headers.items():
            for val in values:
                self.set_enc_header(header, val)
        self.send_headers(body != b"")
        if body:
            self.write_chunk(body)
            self.write_chunk(b"")

    def keyword_filter_RESPMOD(self):
        print(f"[DEBUG] has_body: {self.has_body}")
        print(f"[DEBUG] enc_res_status: {self.enc_res_status}")

        body = b""
        if self.has_body:
            while True:
                chunk = self.read_chunk()
                if chunk == b"":
                    break
                body += chunk

        # No body - pass through as-is (304 Not Modified, etc.)
        if not body and not self.has_body:
            self.set_icap_response(204)
            self.send_headers(False)
            return

        content_type = self.enc_res_headers.get(
            b'content-type', [b''])[0].decode('utf-8', errors='ignore')
        content_encoding = self.enc_res_headers.get(
            b'content-encoding', [b''])[0].decode('utf-8', errors='ignore')

        if 'gzip' in content_encoding:
            try:
                body = gzip.decompress(body)
                print(f"[DEBUG] Decompressed body length: {len(body)}")
            except Exception as e:
                print(f"[DEBUG] Gzip decompress failed: {e}")

        if 'text/html' in content_type:
            text = body.decode('utf-8', errors='ignore').lower()
            for keyword in KEYWORDS:
                if keyword.lower() in text:
                    print(f"[BLOCKED] Keyword matched: {keyword}")
                    self.set_icap_response(200)
                    self.set_enc_status(b'HTTP/1.1 403 Forbidden')
                    self.set_enc_header(b'Content-Type', b'text/html')
                    self.set_enc_header(b'Content-Length', str(len(BLOCK_PAGE)).encode())
                    self.send_headers(True)
                    self.write_chunk(BLOCK_PAGE)
                    self.write_chunk(b"")
                    return

        # Pass through
        self.set_icap_response(200)
        self.set_enc_status(b" ".join(self.enc_res_status))
        for header, values in self.enc_res_headers.items():
            if header == b'content-encoding':
                continue
            if header == b'content-length':
                continue
            for val in values:
                self.set_enc_header(header, val)
        self.set_enc_header(b'content-length', str(len(body)).encode())
        self.send_headers(True)
        self.write_chunk(body)
        self.write_chunk(b"")


class ThreadedICAPServer(socketserver.ThreadingMixIn, ICAPServer):
    pass


if __name__ == '__main__':
    server = ThreadedICAPServer(('0.0.0.0', 1344), KeywordFilter)
    print("ICAP Keyword Filter running on port 1344...")
    server.serve_forever()