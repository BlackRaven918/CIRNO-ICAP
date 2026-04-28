#!/usr/bin/env python3
import socketserver
import gzip
import json
import os
import signal
import ahocorasick
import re
import clamd
import io
import base64
import email as email_lib


from pyicap import ICAPServer, BaseICAPRequestHandler
import base64
# --- Config ---
CONFIG_DIR = "/opt/CIRNO-ICAP"
PHRASELIST_DIR = f"{CONFIG_DIR}/phraselist"
DOMAINLIST_DIR = f"{CONFIG_DIR}/domainlist"
CONFIG_FILE = f"{CONFIG_DIR}/config.json"
MAX_SCAN_SIZE = 25 * 1024 * 1024

KEYWORD_CATEGORIES = {}
BLOCKED_URL_CATEGORIES = {}
KEYWORD_SCORES = {} 
GOOD_SCORES = {}
AUTOMATONS = {}
GOOD_AUTOMATONS = {}
DLP_CONFIG = {}
DLP_PATTERNS = {}


def load_block_pages():
    global URL_BLOCK_PAGE_TEMPLATE, BLOCK_PAGE_TEMPLATE, VIRUS_BLOCK_PAGE_TEMPLATE, DLP_BLOCK_PAGE_TEMPLATE
    
    try:
        with open(f"{CONFIG_DIR}/stop_visiting.png", "rb") as f:
            img_b64 = base64.b64encode(f.read()).decode()
        img_tag = f'<img src="data:image/png;base64,{img_b64}" alt="stop" style="height:50%;">'
    except Exception as e:
        print(f"[WARN] Could not load block page image: {e}")
        img_tag = ""

    URL_BLOCK_PAGE_TEMPLATE = f"""<html>
        <head>
            <title>Access Blocked By CIRNO-ICAP</title>
            <style>body{{{{background-color: #ff4444;color:white;font-family:sans-serif;text-align:center;}}}}</style>
        </head>
        <body>
            {img_tag}
            <h1>Access Blocked</h1>
            <p>You visited <b>{{url}}</b>.</p>
            <p>This site is blocked under the <b>{{category}}</b> category.</p>
        </body>
        </html>
    """

    BLOCK_PAGE_TEMPLATE = f"""<html>
        <head>
            <title>Access Blocked By CIRNO-ICAP</title>
            <style>body{{{{background-color: #ff4444;color:white;font-family:sans-serif;text-align:center;}}}}
        </style>
        </head>
        <body>
            {img_tag}
            <h1>Access Blocked</h1>
            <p>You visited <b>{{url}}</b>.</p>
            <p>This page was blocked because it contains content in the <b>{{category}}</b> category.</p>
            <p>Matched keywords: <b>{{keyword}}</b></p>
        </body>
        </html>
    """
    
    VIRUS_BLOCK_PAGE_TEMPLATE = f"""<html>
        <head>
            <title>Virus Blocked By CIRNO-ICAP</title>
            <style>body{{{{background-color: #ff4444;color:white;font-family:sans-serif;text-align:center;}}}}</style>
        </head>
        <body>
            {img_tag}
            <h1>Virus Blocked</h1>
            <p>A virus was detected in a file downloaded from <b>{{url}}</b>.</p>
            <p>Threat: <b>{{virus}}</b></p>
        </body>
        </html>
    """

    DLP_BLOCK_PAGE_TEMPLATE = f"""<html>
        <head><title>Upload Blocked By J-ICAP</title>
            <style>body{{{{background-color: #ff8800;color:white;font-family:sans-serif;text-align:center;}}}}</style>
        </head>
        <body>
            {img_tag}
            <h1>Upload Blocked</h1>
            <p>An attempt to upload sensitive data to <b>{{url}}</b> was blocked.</p>
            <p>Detected: <b>{{findings}}</b></p>
        </body>
        </html>
    """


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

def get_client_ip(self):
    # Try X-Client-IP header first (set by Squid when icap_send_client_ip is on)
    #print(f"[DEBUG] ICAP headers: {self.headers}")
    x_client_ip = self.headers.get(b'x-client-ip', [b''])[0].decode('utf-8', errors='ignore')
    if x_client_ip:
        return x_client_ip
    # Fall back to connection IP
    return self.client_address[0]

def build_automatons():
    global AUTOMATONS, GOOD_AUTOMATONS
    AUTOMATONS = {}
    GOOD_AUTOMATONS = {}

    for category, keywords in KEYWORD_SCORES.items():
        A = ahocorasick.Automaton()
        for keyword, score in keywords.items():
            #print(f"[DEBUG] Adding keyword: '{keyword}' score: {score}")  # add this
            A.add_word(keyword, (keyword, score))
        A.make_automaton()
        AUTOMATONS[category] = A


CONFIG_FILE = f"{CONFIG_DIR}/config.json"

GROUPS = {}
DEFAULT_CONFIG = {}

def load_config():
    global KEYWORD_CATEGORIES, BLOCKED_URL_CATEGORIES, KEYWORD_SCORES, GOOD_SCORES
    global BLOCK_THRESHOLD, ENABLED_CATEGORIES, GROUPS, DEFAULT_CONFIG, DLP_CONFIG, DLP_PATTERNS

    try:
        with open(CONFIG_FILE) as f:
            config = json.load(f)
            DEFAULT_CONFIG = {
                "block_threshold": config.get("default", {}).get("block_threshold", 100),
                "enabled_categories": [c.lower() for c in config.get("default", {}).get("enabled_categories", [])]
            }
            GROUPS = {}
            for group_name, group_cfg in config.get("groups", {}).items():
                GROUPS[group_name] = {
                    "ips": group_cfg.get("ips", []),
                    "block_threshold": group_cfg.get("block_threshold", DEFAULT_CONFIG["block_threshold"]),
                    "enabled_categories": [c.lower() for c in group_cfg.get("enabled_categories", [])]
                }
            #print(f"[INFO] Loaded {len(GROUPS)} groups")
    except Exception as e:
        print(f"[WARN] Could not read config.json: {e}")
        DEFAULT_CONFIG = {"block_threshold": 100, "enabled_categories": []}
        GROUPS = {}

    KEYWORD_CATEGORIES = {}
    BLOCKED_URL_CATEGORIES = {}
    KEYWORD_SCORES = {}
    GOOD_SCORES = {}

    if os.path.exists(PHRASELIST_DIR):
        for category in os.listdir(PHRASELIST_DIR):
            
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
                #print(f"[INFO] Loaded {len(all_phrases)} phrases and {len(good_phrases)} good phrases for category: {category}")
                # print(f"[DEBUG] Sample keywords for {category}: {list(KEYWORD_SCORES[category].keys())[:10]}")


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
                #print(f"[INFO] Loaded {len(domains)} domains for category: {category}")

    dlp = config.get("dlp", {})
    DLP_CONFIG = {
        "enabled": dlp.get("enabled", False),
        "blocked_upload_domains": [d.lower() for d in dlp.get("blocked_upload_domains", [])],
        "custom_keywords": [k.lower() for k in dlp.get("custom_keywords", [])]
    }
    DLP_PATTERNS = {}
    for category, patterns in dlp.get("patterns", {}).items():
        DLP_PATTERNS[category] = [re.compile(p) for p in patterns]
    print(f"[INFO] DLP loaded - {len(DLP_PATTERNS)} pattern categories, {len(DLP_CONFIG['blocked_upload_domains'])} upload domains")

    #print(f"[INFO] Config reloaded - {len(KEYWORD_CATEGORIES)} keyword categories, {len(BLOCKED_URL_CATEGORIES)} URL categories")
    build_automatons()

def scan_for_dlp(body, content_type):
    findings = []
    texts_to_scan = []

    try:
        if 'application/x-www-form-urlencoded' in content_type:
            from urllib.parse import unquote_plus
            texts_to_scan.append(unquote_plus(body.decode('utf-8', errors='ignore')))
        
        

        elif 'multipart/form-data' in content_type:
            parts = parse_multipart(body, content_type)
            for part_type, content, headers in parts:
                if part_type == 'file':
                    # Scan file contents
                    filename = ''
                    for h in headers.split(';'):
                        h = h.strip()
                        if h.startswith('filename='):
                            filename = h[9:].strip('"')

                    print(f"[DLP] Scanning file upload: {filename} | {len(content)} bytes")

                    # Scan with ClamAV if available
                    if cd is not None:
                        status, reason = scan_with_clamav(content)
                        if status == 'FOUND':
                            # print(f"[DLP] Virus in upload: {reason} | file: {filename}")
                            findings.append(f"Virus: {reason} in {filename}")

                    # Try to read as text for keyword/pattern scanning
                    # Works for .txt, .csv, .html, .xml, .json, .py etc
                    try:
                        file_text = content.decode('utf-8', errors='ignore')
                        if file_text.isprintable() or sum(c.isprintable() for c in file_text) / max(len(file_text), 1) > 0.8:
                            texts_to_scan.append(file_text)
                            print(f"[DLP] Added text file to scan: {filename}")
                    except:
                        pass

                else:
                    # Form field
                    texts_to_scan.append(content.decode('utf-8', errors='ignore'))
        elif 'multipart/related' in content_type or 'multipart/form-data' in content_type:
                    parts = parse_multipart(body, content_type)
        elif 'application/json' in content_type or 'protobuf' in content_type:
            try:
                import json
                data = json.loads(body.decode('utf-8', errors='ignore'))
                texts_to_scan.append(decode_body_recursive(data))
            except:
                # protobuf fallback - just scan raw bytes as text
                texts_to_scan.append(body.decode('utf-8', errors='ignore'))

    except Exception as e:
        print(f"[DLP] Parse error: {e}")
        return []

    # Scan all collected text
    for text in texts_to_scan:
        text_lower = text.lower()

        # Regex patterns
        for category, patterns in DLP_PATTERNS.items():
            if category in [f[0] for f in findings]:
                continue  # already found this category
            for pattern in patterns:
                if pattern.search(text):
                    print(f"[DLP] Pattern matched: {category}")
                    findings.append(category)
                    break

        # Custom keywords
        for keyword in DLP_CONFIG.get("custom_keywords", []):
            if keyword in text_lower:
                if f"keyword: {keyword}" not in findings:
                    print(f"[DLP] Keyword matched: {keyword}")
                    findings.append(f"keyword: {keyword}")

    return findings

def decode_body_recursive(obj):
    """Recursively extract all string values from nested JSON"""
    text = ""
    if isinstance(obj, str):
        # Try base64 decode
        try:
            decoded = base64.b64decode(obj + "==").decode('utf-8', errors='ignore')
            if decoded.isprintable():
                text += decoded + " "
        except:
            pass
        text += obj + " "
    elif isinstance(obj, dict):
        for val in obj.values():
            text += decode_body_recursive(val)
    elif isinstance(obj, list):
        for item in obj:
            text += decode_body_recursive(item)
    return text

def get_group_config(client_ip):
    for group_name, group_cfg in GROUPS.items():
        if client_ip in group_cfg["ips"]:
            #print(f"[DEBUG] Client {client_ip} matched group: {group_name}")
            return group_cfg
    #print(f"[DEBUG] Client {client_ip} using default config")
    return DEFAULT_CONFIG

def is_whole_word_match(text, keyword, end_index):
    start_index = end_index - len(keyword) + 1
    
    # Check character before the match
    if start_index > 0 and text[start_index - 1].isalnum():
        return False
    
    # Check character after the match
    if end_index + 1 < len(text) and text[end_index + 1].isalnum():
        return False
    
    return True


def load_clamav():
    global cd
    cd = None
    try:
        cd = clamd.ClamdUnixSocket()
        cd.ping()
        #print("[INFO] ClamAV daemon connected")
    except Exception as e:
        cd = None
        print(f"[WARN] ClamAV not available: {e}")

SKIP_SCAN_TYPES = [
    'text/html', 'text/css', 'text/javascript',
    'application/javascript', 'application/json',
    'image/', 'font/', 'audio/', 'video/'
]

def scan_with_clamav(data):
    if cd is None:
        #print("[DEBUG] ClamAV not available, skipping scan")
        return None, None
    try:
        result = cd.instream(io.BytesIO(data))
        status, reason = result['stream']
        #print(f"[DEBUG] ClamAV result: {status} {reason}")
        return status, reason
    except Exception as e:
        #print(f"[WARN] ClamAV scan error: {e}")
        return None, None

def parse_multipart(body, content_type):
    """Extract all parts from a multipart/form-data body"""
    parts = []
    try:
        # Extract boundary from content-type header
        boundary = None
        for part in content_type.split(';'):
            part = part.strip()
            if part.startswith('boundary='):
                boundary = part[9:].strip('"')
                break
        
        if not boundary:
            return [body.decode('utf-8', errors='ignore')]

        # Split body by boundary
        boundary_bytes = f'--{boundary}'.encode()
        sections = body.split(boundary_bytes)
        
        for section in sections:
            if not section or section == b'--\r\n':
                continue
            # Split headers from body
            if b'\r\n\r\n' in section:
                headers, content = section.split(b'\r\n\r\n', 1)
                headers_str = headers.decode('utf-8', errors='ignore').lower()
                content = content.rstrip(b'\r\n')
                
                # Check if this part is a file
                if 'filename=' in headers_str:
                    # It's a file - scan contents
                    parts.append(('file', content, headers_str))
                else:
                    # It's a form field
                    parts.append(('field', content, headers_str))
    except Exception as e:
        print(f"[DLP] Multipart parse error: {e}")
        parts.append(('raw', body, ''))
    
    return parts


# Load on startup
load_config()
load_block_pages()
load_clamav()
# Reload config on SIGUSR1 without restarting
signal.signal(signal.SIGUSR1, lambda sig, frame: load_config())

class KeywordFilter(BaseICAPRequestHandler):

    def log_message(self, format, *args):
        """Override to prevent printing access logs to the console/systemd."""
        pass

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
        client_ip = get_client_ip(self)
        group_cfg = get_group_config(client_ip)
        block_threshold = group_cfg["block_threshold"]
        enabled_categories = group_cfg["enabled_categories"]

        body = b""
        if self.has_body:
            while True:
                chunk = self.read_chunk()
                if chunk == b"":
                    break
                body += chunk

        url = self.enc_req_headers.get(b'host', [b''])[0].decode('utf-8', errors='ignore')
        method = self.enc_req[0].decode('utf-8', errors='ignore') if self.enc_req else ''
        content_type = self.enc_req_headers.get(
            b'content-type', [b''])[0].decode('utf-8', errors='ignore')

        # No group match - pass through without filtering
        if enabled_categories is None:
            self.set_icap_response(200)
            self.set_enc_request(b" ".join(self.enc_req))
            for header, values in self.enc_req_headers.items():
                if header in (b'if-modified-since', b'if-none-match', b'if-range'):
                    continue
                for val in values:
                    self.set_enc_header(header, val)
            self.set_enc_header(b'cache-control', b'no-cache')
            self.set_enc_header(b'pragma', b'no-cache')
            self.send_headers(body != b"")
            if body:
                self.write_chunk(body)
                self.write_chunk(b"")
            return

        # URL category blocking
        for category, urls in BLOCKED_URL_CATEGORIES.items():
            if category.lower() not in enabled_categories:
                continue
            for blocked in urls:
                if blocked.lower() in url.lower():
                    print(f"[BLOCKED REQUEST] Client: {client_ip} | Category: {category} | URL: {blocked}")
                    block_page = URL_BLOCK_PAGE_TEMPLATE.format(
                        category=category, url=url).encode()
                    self.set_icap_response(200)
                    self.set_enc_status(b'HTTP/1.1 403 Forbidden')
                    self.set_enc_header(b'Content-Type', b'text/html')
                    self.set_enc_header(b'Content-Length', str(len(block_page)).encode())
                    self.send_headers(True)
                    self.write_chunk(block_page)
                    self.write_chunk(b"")
                    return

        # DLP scanning on POST requests to upload domains
        if DLP_CONFIG.get("enabled") and method in ('POST', 'PUT', 'PATCH') and body:
            print(f"[DLP DEBUG] {method} to {url} | content-type: {content_type} | size: {len(body)}")
            is_upload_domain = any(
                d in url.lower() for d in DLP_CONFIG["blocked_upload_domains"]
            )
            if is_upload_domain:
                print(f"[DLP] Scanning POST to {url} | {len(body)} bytes")
                findings = scan_for_dlp(body, content_type)
                if findings:
                    print(f"[DLP BLOCKED] Client: {client_ip} | URL: {url} | Findings: {findings}")
                    block_page = DLP_BLOCK_PAGE_TEMPLATE.format(
                        url=url,
                        findings=", ".join(findings)
                    ).encode()
                    self.set_icap_response(200)
                    self.set_enc_status(b'HTTP/1.1 403 Forbidden')
                    self.set_enc_header(b'Content-Type', b'text/html')
                    self.set_enc_header(b'Content-Length', str(len(block_page)).encode())
                    self.send_headers(True)
                    self.write_chunk(block_page)
                    self.write_chunk(b"")
                    return

        # Pass through with cache-busting
        self.set_icap_response(200)
        self.set_enc_request(b" ".join(self.enc_req))
        for header, values in self.enc_req_headers.items():
            if header in (b'if-modified-since', b'if-none-match', b'if-range'):
                continue
            for val in values:
                self.set_enc_header(header, val)
        self.set_enc_header(b'cache-control', b'no-cache')
        self.set_enc_header(b'pragma', b'no-cache')
        self.send_headers(body != b"")
        if body:
            self.write_chunk(body)
            self.write_chunk(b"")

    def keyword_filter_RESPMOD(self):
        client_ip = get_client_ip(self)
        group_cfg = get_group_config(client_ip)
        block_threshold = group_cfg["block_threshold"]
        enabled_categories = group_cfg["enabled_categories"]

        #print(f"[DEBUG] has_body: {self.has_body}")
        #print(f"[DEBUG] enc_res_status: {self.enc_res_status}")

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

        # No group match - pass through without filtering
        if enabled_categories is None:
            #print(f"[DEBUG] Client {client_ip} not in any group - passing through")
            self.set_icap_response(204)
            self.send_headers(False)
            return

        content_type = self.enc_res_headers.get(
            b'content-type', [b''])[0].decode('utf-8', errors='ignore')
        content_encoding = self.enc_res_headers.get(
            b'content-encoding', [b''])[0].decode('utf-8', errors='ignore')

        # Decompress if gzip
        decompressed = False
        if 'gzip' in content_encoding:
            try:
                body = gzip.decompress(body)
                decompressed = True
                #print(f"[DEBUG] Decompressed body length: {len(body)}")
            except Exception as e:
                print(f"[DEBUG] Gzip decompress failed: {e}")

        #print(f"[DEBUG] content-type: {content_type} | body size: {len(body)}")


        # print(f"[DEBUG] content-type for ClamAV check: {content_type}")

        should_scan = body and cd is not None and not any(ct in content_type for ct in SKIP_SCAN_TYPES)

        if should_scan:
            print(f"[DEBUG] Sending to ClamAV: {content_type} | {len(body)} bytes")
            if len(body) <= MAX_SCAN_SIZE:
                status, reason = scan_with_clamav(body)
                if status == 'FOUND':
                    print(f"[BLOCKED] Virus found: {reason} | URL: {url}")
                    block_page = VIRUS_BLOCK_PAGE_TEMPLATE.format(
                        url=url,
                        virus=reason
                    ).encode()
                    self.set_icap_response(200)
                    self.set_enc_status(b'HTTP/1.1 403 Forbidden')
                    self.set_enc_header(b'Content-Type', b'text/html')
                    self.set_enc_header(b'Content-Length', str(len(block_page)).encode())
                    self.send_headers(True)
                    self.write_chunk(block_page)
                    self.write_chunk(b"")
                    return
                elif status == 'ERROR':
                    print(f"[WARN] ClamAV scan error for {url}: {reason}")

        # Only scan HTML
        if 'text/html' in content_type:
            text = body.decode('utf-8', errors='ignore').lower()

            for category, automaton in AUTOMATONS.items():
                if category.lower() not in enabled_categories:
                    continue

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

                #print(f"[DEBUG] Client: {client_ip} | Category: {category} | Score: {total_score} | Threshold: {block_threshold} | Bad: {matched_keywords[:5]} | Good: {matched_good[:5]}")

                if total_score >= block_threshold:
                    print(f"[BLOCKED] Client: {client_ip} | Category: {category} | Score: {total_score}")
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
            if decompressed and header == b'content-encoding':
                continue
            if decompressed and header == b'content-length':
                continue
            for val in values:
                self.set_enc_header(header, val)
        if decompressed:
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