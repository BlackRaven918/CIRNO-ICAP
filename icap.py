#!/usr/bin/env python3
import socketserver
import gzip
import json
import os
import signal

# --- Config ---
CONFIG_DIR = "/home/jasper/pycap"
PHRASELIST_DIR = f"{CONFIG_DIR}/phraselist"
DOMAINLIST_DIR = f"{CONFIG_DIR}/domainlist"

KEYWORD_CATEGORIES = {}
BLOCKED_URL_CATEGORIES = {}

BLOCK_PAGE_TEMPLATE = """<html>
<head><title>Access Blocked By JCAP</title>
<style>body{{background-color: red;color:white;font-family:sans-serif;}}</style>
</head>
<body>
<h1>Access Blocked</h1>
<p>You visited <b>{url}</b>.</p>
<p>This page was blocked because it contains content in the <b>{category}</b> category.</p>
<p>Matched keyword: <b>{keyword}</b></p>
</body>
</html>"""

URL_BLOCK_PAGE_TEMPLATE = """<html>
<head><title>Access Blocked By JCAP</title>
<style>body{{background-color: red;color:white;font-family:sans-serif;}}</style>
</head>
<body>
<h1>Access Blocked</h1>
<p>You visited <b>{url}</b>.</p>
<p>This site is blocked under the <b>{category}</b> category.</p>
</body>
</html>"""


def load_e2guardian_list(filepath):
    phrases = []
    try:
        with open(filepath, encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                if line.startswith('#'):
                    continue
                if line.startswith('<include>'):
                    continue
                if line.startswith('<'):
                    line = line.split('>')[0].lstrip('<').strip()
                phrases.append(line.lower())
    except Exception as e:
        print(f"[WARN] Could not read {filepath}: {e}")
    return phrases


def load_config():
    global KEYWORD_CATEGORIES, BLOCKED_URL_CATEGORIES
    KEYWORD_CATEGORIES = {}
    BLOCKED_URL_CATEGORIES = {}

    # Load phraselists
    if os.path.exists(PHRASELIST_DIR):
        for category in os.listdir(PHRASELIST_DIR):
            category_path = os.path.join(PHRASELIST_DIR, category)
            if not os.path.isdir(category_path):
                continue
            phrases = []
            for filename in os.listdir(category_path):
                filepath = os.path.join(category_path, filename)
                if os.path.isfile(filepath):
                    phrases.extend(load_e2guardian_list(filepath))
            if phrases:
                KEYWORD_CATEGORIES[category] = list(set(phrases))
                print(f"[INFO] Loaded {len(KEYWORD_CATEGORIES[category])} phrases for category: {category}")

    # Load domain lists
    if os.path.exists(DOMAINLIST_DIR):
        for filename in os.listdir(DOMAINLIST_DIR):
            filepath = os.path.join(DOMAINLIST_DIR, filename)
            if not os.path.isfile(filepath):
                continue
            category = filename.replace('banned', '').replace('domains', '').replace('list', '').strip('_').title()
            domains = load_e2guardian_list(filepath)
            if domains:
                BLOCKED_URL_CATEGORIES[category] = domains
                print(f"[INFO] Loaded {len(domains)} domains for category: {category}")

    print(f"[INFO] Config reloaded - {len(KEYWORD_CATEGORIES)} keyword categories, {len(BLOCKED_URL_CATEGORIES)} URL categories")


# Load on startup
load_config()

# Reload config on SIGUSR1 without restarting
signal.signal(signal.SIGUSR1, lambda sig, frame: load_config())


from pyicap import ICAPServer, BaseICAPRequestHandler


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
        self.set_icap_header(b'Preview', b'1024')
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

        for category, urls in BLOCKED_URL_CATEGORIES.items():
            for blocked in urls:
                if blocked.lower() in url.lower():
                    print(f"[BLOCKED REQUEST] Category: {category} | URL: {blocked}")
                    block_page = URL_BLOCK_PAGE_TEMPLATE.format(category=category).encode()
                    self.set_icap_response(200)
                    self.set_enc_status(b'HTTP/1.1 403 Forbidden')
                    self.set_enc_header(b'Content-Type', b'text/html')
                    self.set_enc_header(b'Content-Length', str(len(block_page)).encode())
                    self.send_headers(True)
                    self.write_chunk(block_page)
                    self.write_chunk(b"")
                    return

        # Pass through
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

        url = self.enc_req_headers.get(b'host', [b''])[0].decode('utf-8', errors='ignore')

        body = b""
        if self.has_body:
            while True:
                chunk = self.read_chunk()
                if chunk == b"":
                    break
                body += chunk

        # No body - pass through as-is (304 Not Modified etc.)
        if not self.has_body:
            self.set_icap_response(204)
            self.send_headers(False)
            return

        content_type = self.enc_res_headers.get(
            b'content-type', [b''])[0].decode('utf-8', errors='ignore')
        content_encoding = self.enc_res_headers.get(
            b'content-encoding', [b''])[0].decode('utf-8', errors='ignore')

        # Decompress if gzip
        if 'gzip' in content_encoding:
            try:
                body = gzip.decompress(body)
                print(f"[DEBUG] Decompressed body length: {len(body)}")
            except Exception as e:
                print(f"[DEBUG] Gzip decompress failed: {e}")

        # Only scan HTML
        if 'text/html' in content_type:
            text = body.decode('utf-8', errors='ignore').lower()
            for category, keywords in KEYWORD_CATEGORIES.items():
                for keyword in keywords:
                    if keyword.lower() in text:
                        print(f"[BLOCKED] Category: {category} | Keyword: {keyword}")
                        block_page = BLOCK_PAGE_TEMPLATE.format(
                            category=category,
                            keyword=keyword,
                            url=url
                        ).encode()
                        self.set_icap_response(200)
                        self.set_enc_status(b'HTTP/1.1 403 Forbidden')
                        self.set_enc_header(b'Content-Type', b'text/html')
                        self.set_enc_header(b'Content-Length', str(len(block_page)).encode())
                        self.send_headers(True)
                        self.write_chunk(block_page)
                        self.write_chunk(b"")
                        return

        # Pass through - update content-length since we decompressed
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