#!/usr/bin/env python3
import socketserver
import gzip
import json
import os
import signal
import ahocorasick
import re
from pyicap import ICAPServer, BaseICAPRequestHandler

# --- Config ---
CONFIG_DIR = "/home/jasper/pycap"
PHRASELIST_DIR = f"{CONFIG_DIR}/phraselist"
DOMAINLIST_DIR = f"{CONFIG_DIR}/domainlist"
CONFIG_FILE = f"{CONFIG_DIR}/config.json"

KEYWORD_CATEGORIES = {}
BLOCKED_URL_CATEGORIES = {}
KEYWORD_SCORES = {} 
GOOD_SCORES = {}
AUTOMATONS = {}
GOOD_AUTOMATONS = {}


BLOCK_PAGE_TEMPLATE = """<html>
<head><title>Access Blocked By J-ICAP</title>
<style>body{{background-color: lightred;color:white;font-family:sans-serif;}}</style>
</head>
<body>
<img src="./static/stop_visiting.png" alt="stop">
<h1>Access Blocked By J-ICAP</h1>
<p>You visited <b>{url}</b>.</p>
<p>This page was blocked because it contains content in the <b>{category}</b> category.</p>
<p>Matched keyword: <b>{keyword}</b></p>
</body>
</html>"""

URL_BLOCK_PAGE_TEMPLATE = """<html>
<head><title>Access Blocked By J-ICAP</title>
<style>body{{background-color: lightred;color:white;font-family:sans-serif;}}</style>
</head>
<body>
<img src="./static/stop_visiting.png" alt="stop">
<h1>Access Blocked</h1>
<p>You visited <b>{url}</b>.</p>
<p>This site is blocked under the <b>{category}</b> category.</p>
</body>
</html>"""


def load_e2guardian_list(filepath):
    phrases = {}  # {phrase: score}
    try:
        with open(filepath, encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()

                # Skip empty lines and comments
                if not line or line.startswith('#'):
                    continue

                # Skip include directives
                if line.startswith('<include>'):
                    continue

                # Handle weighted phrase lines like:
                # < adult >,< sex >,< escorts ><80>
                # < gambling ><50>
                # < bollocks ><25>
                if line.startswith('<'):
                    try:
                        # Extract the score — it's always the last <number>
                        last_open = line.rfind('<')
                        last_close = line.rfind('>')
                        score_str = line[last_open+1:last_close].strip()

                        if score_str.lstrip('-').isdigit():
                            score = int(score_str)
                            # Everything before the last <score> is the phrase(s)
                            phrase_part = line[:last_open]
                        else:
                            # No score found, default
                            score = 10
                            phrase_part = line

                        # Split by comma to handle multiple phrases per line
                        parts = phrase_part.split(',')
                        for part in parts:
                            # Strip < > and whitespace
                            phrase = part.strip().strip('<>').strip()
                            if phrase:
                                phrases[phrase.lower()] = score

                    except Exception as e:
                        print(f"[WARN] Could not parse line '{line}': {e}")
                        continue
                else:
                    # Plain phrase with no weight
                    phrases[line.lower()] = 10

    except Exception as e:
        print(f"[WARN] Could not read {filepath}: {e}")
    return phrases


def build_automatons():
    global AUTOMATONS, GOOD_AUTOMATONS
    AUTOMATONS = {}
    GOOD_AUTOMATONS = {}

    for category, keywords in KEYWORD_SCORES.items():
        A = ahocorasick.Automaton()
        for keyword, score in keywords.items():
            print(f"[DEBUG] Adding keyword: '{keyword}' score: {score}")  # add this
            A.add_word(keyword, (keyword, score))
        A.make_automaton()
        AUTOMATONS[category] = A


CONFIG_FILE = f"{CONFIG_DIR}/config.json"

def load_config():
    global KEYWORD_CATEGORIES, BLOCKED_URL_CATEGORIES, KEYWORD_SCORES, GOOD_SCORES, BLOCK_THRESHOLD, ENABLED_CATEGORIES


    # Load main config
    try:
        with open(CONFIG_FILE) as f:
            config = json.load(f)
            BLOCK_THRESHOLD = config.get("block_threshold", 100)
            ENABLED_CATEGORIES = [c.lower() for c in config.get("enabled_categories", [])]
            print(f"[INFO] Block threshold: {BLOCK_THRESHOLD}")
            print(f"[INFO] Enabled categories: {ENABLED_CATEGORIES}")
    except Exception as e:
        print(f"[WARN] Could not read config.json, using defaults: {e}")
        BLOCK_THRESHOLD = 100
        ENABLED_CATEGORIES = []  # empty = all categories enabled

    KEYWORD_CATEGORIES = {}
    BLOCKED_URL_CATEGORIES = {}
    KEYWORD_SCORES = {}
    GOOD_SCORES = {}

    if os.path.exists(PHRASELIST_DIR):
        for category in os.listdir(PHRASELIST_DIR):
            # Skip disabled categories
            if ENABLED_CATEGORIES and category.lower() not in ENABLED_CATEGORIES:
                print(f"[INFO] Skipping disabled category: {category}")
                continue

            category_path = os.path.join(PHRASELIST_DIR, category)
            if not os.path.isdir(category_path):
                continue

            all_phrases = {}
            good_phrases = {}

            for filename in os.listdir(category_path):
                filepath = os.path.join(category_path, filename)
                if not os.path.isfile(filepath):
                    continue
                if 'good' in filename.lower():
                    good_phrases.update(load_e2guardian_list(filepath))
                else:
                    all_phrases.update(load_e2guardian_list(filepath))

            if all_phrases:
                KEYWORD_CATEGORIES[category] = list(all_phrases.keys())
                KEYWORD_SCORES[category] = all_phrases
                GOOD_SCORES[category] = good_phrases
                print(f"[INFO] Loaded {len(all_phrases)} phrases and {len(good_phrases)} good phrases for category: {category}")
                print(f"[DEBUG] Sample keywords for {category}: {list(KEYWORD_SCORES[category].keys())[:10]}")


    if os.path.exists(DOMAINLIST_DIR):
        for filename in os.listdir(DOMAINLIST_DIR):
            filepath = os.path.join(DOMAINLIST_DIR, filename)
            if not os.path.isfile(filepath):
                continue
            category = filename.replace('banned', '').replace('domains', '').replace('list', '').strip('_').title()
            if ENABLED_CATEGORIES and category.lower() not in ENABLED_CATEGORIES:
                continue
            domains = list(load_e2guardian_list(filepath).keys())
            if domains:
                BLOCKED_URL_CATEGORIES[category] = domains
                print(f"[INFO] Loaded {len(domains)} domains for category: {category}")

    print(f"[INFO] Config reloaded - {len(KEYWORD_CATEGORIES)} keyword categories, {len(BLOCKED_URL_CATEGORIES)} URL categories")
    build_automatons()


def is_whole_word_match(text, keyword, end_index):
    start_index = end_index - len(keyword) + 1
    
    # Check character before the match
    if start_index > 0 and text[start_index - 1].isalnum():
        return False
    
    # Check character after the match
    if end_index + 1 < len(text) and text[end_index + 1].isalnum():
        return False
    
    return True

# Load on startup
load_config()

# Reload config on SIGUSR1 without restarting
signal.signal(signal.SIGUSR1, lambda sig, frame: load_config())

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

        # Only scan HTML - this must be at the same level as the gzip block, not inside it
        if 'text/html' in content_type:
            text = body.decode('utf-8', errors='ignore').lower()

            print(f"[DEBUG] Automatons available: {list(AUTOMATONS.keys())}")

            for category, automaton in AUTOMATONS.items():
                total_score = 0
                matched_keywords = []
                matched_good = []

                for end_index, (keyword, score) in automaton.iter(text):
                    if not is_whole_word_match(text, keyword, end_index):
                        continue
                    total_score += score
                    matched_keywords.append(f"{keyword} (+{score})")

                if category in GOOD_AUTOMATONS:
                    for end_index, (keyword, score) in GOOD_AUTOMATONS[category].iter(text):
                        if not is_whole_word_match(text, keyword, end_index):
                            continue
                        total_score -= score
                        matched_good.append(f"{keyword} (-{score})")

                print(f"[DEBUG] Category: {category} | Score: {total_score} | Bad: {matched_keywords[:5]} | Good: {matched_good[:5]}")

                if total_score >= BLOCK_THRESHOLD:
                    print(f"[BLOCKED] Category: {category} | Score: {total_score}")
                    block_page = BLOCK_PAGE_TEMPLATE.format(
                        category=category,
                        keyword=", ".join(matched_keywords[:10]),
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