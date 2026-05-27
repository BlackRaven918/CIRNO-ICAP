import json
import os
import subprocess
import requests
from flask import Flask, render_template, request, jsonify

app = Flask(__name__)
CONFIG_DIR = "/opt/CIRNO-ICAP"
CONFIG_FILE = f"{CONFIG_DIR}/config.json"
PHRASELIST_DIR = f"{CONFIG_DIR}/phraselist"

NETBIRD_BASE_URL = os.environ.get("NETBIRD_BASE_URL", "https://netbird.newwave.local/api")
NETBIRD_TOKEN = os.environ.get("NETBIRD_TOKEN", "")

# Updated default skeleton for a newly created group using nested user arrays
DEFAULT_GROUP = {
    "block_threshold": 400,
    "enabled_categories": [],
    "google_safe_search": False,
    "users": [],
    "dlp": {
        "enabled": False,
        "blocked_upload_domains": [],
        "patterns": {},
        "custom_keywords": []
    }
}


def read_config():
    with open(CONFIG_FILE) as f:
        return json.load(f)


def write_config(config):
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=4)


def reload_icap():
    subprocess.run(["sudo", "/usr/bin/systemctl", "kill", "-s", "USR1", "CIRNO-ICAP"])


def get_netbird_settings():
    """Return (base_url, token) from config, falling back to env vars."""
    try:
        config = read_config()
        nb = config.get("netbird", {})
        url = nb.get("base_url") or NETBIRD_BASE_URL
        token = nb.get("token") or NETBIRD_TOKEN
    except Exception:
        url, token = NETBIRD_BASE_URL, NETBIRD_TOKEN
    return url.rstrip("/"), token


def netbird_get(path):
    """GET from the NetBird API, returns parsed JSON or raises."""
    base_url, token = get_netbird_settings()
    resp = requests.get(
        f"{base_url}/{path}",
        headers={"Authorization": f"Bearer {token}"},
        verify=False,
        timeout=10
    )
    resp.raise_for_status()
    return resp.json()


# --- Config ---
@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/config', methods=['GET'])
def get_config():
    return jsonify(read_config())


@app.route('/api/config', methods=['POST'])
def save_config():
    existing = read_config()
    incoming = request.json
    existing['web_filter'] = existing.get('web_filter', {})
    existing['web_filter']['groups'] = incoming.get('web_filter', {}).get('groups', existing['web_filter'].get('groups', {}))
    # DLP is now stored per-group inside web_filter.groups; remove legacy top-level dlp key if present
    existing.pop('dlp', None)
    write_config(existing)
    reload_icap()
    return jsonify({"status": "ok"})


# --- Groups ---
@app.route('/api/groups', methods=['GET'])
def get_groups():
    config = read_config()
    return jsonify(config.get('web_filter', {}).get('groups', {}))


@app.route('/api/groups/<name>', methods=['POST'])
def save_group(name):
    config = read_config()
    config["web_filter"]["groups"][name] = request.json
    write_config(config)
    reload_icap()
    return jsonify({"status": "ok"})


@app.route('/api/groups/<name>', methods=['DELETE'])
def delete_group(name):
    config = read_config()
    config["web_filter"]["groups"].pop(name, None)
    write_config(config)
    reload_icap()
    return jsonify({"status": "ok"})


# --- Categories ---
@app.route('/api/categories', methods=['GET'])
def get_categories():
    categories = []
    if os.path.exists(PHRASELIST_DIR):
        for cat in os.listdir(PHRASELIST_DIR):
            if os.path.isdir(os.path.join(PHRASELIST_DIR, cat)):
                categories.append(cat)
    return jsonify(categories)


@app.route('/api/categories/<category>/keywords', methods=['GET'])
def get_keywords(category):
    keywords = []
    cat_path = os.path.join(PHRASELIST_DIR, category)
    if os.path.exists(cat_path):
        for filename in os.listdir(cat_path):
            filepath = os.path.join(cat_path, filename)
            if os.path.isfile(filepath):
                with open(filepath) as f:
                    keywords.extend([l.strip() for l in f if l.strip() and not l.startswith('#')])
    return jsonify(keywords)


@app.route('/api/categories/<category>/keywords', methods=['POST'])
def save_keywords(category):
    keywords = request.json.get("keywords", [])
    cat_path = os.path.join(PHRASELIST_DIR, category)
    os.makedirs(cat_path, exist_ok=True)
    with open(os.path.join(cat_path, "phrases"), 'w') as f:
        f.write('\n'.join(keywords))
    reload_icap()
    return jsonify({"status": "ok"})


# Updated to aggregate IPs from the nested users schema
@app.route('/api/groups/ips', methods=['GET'])
def get_groups_ips_response():
    config = read_config()
    groups = config.get("web_filter", {}).get("groups", {})
    response_data = {}
    for name, data in groups.items():
        all_ips = []
        for user_obj in data.get("users", []):
            all_ips.extend(user_obj.get("ips", []))
        response_data[name] = all_ips
    return jsonify(response_data)


# --- NetBird Settings ---
@app.route('/api/netbird-settings', methods=['GET'])
def get_netbird_settings_route():
    config = read_config()
    nb = config.get("netbird", {})
    return jsonify({
        "base_url": nb.get("base_url", NETBIRD_BASE_URL)
    })


@app.route('/api/netbird-settings', methods=['POST'])
def save_netbird_settings_route():
    data = request.json or {}
    config = read_config()
    if "netbird" not in config:
        config["netbird"] = {}
    if "base_url" in data and data["base_url"].strip():
        config["netbird"]["base_url"] = data["base_url"].strip()
    write_config(config)
    return jsonify({"status": "ok"})


# --- NetBird Sync ---
@app.route('/api/sync-netbird', methods=['POST'])
def sync_netbird():
    _, token = get_netbird_settings()
    if not token:
        return jsonify({"status": "error", "message": "NetBird token is not configured. Set it in the Settings tab."}), 500

    try:
        peers = netbird_get("peers")
        users = netbird_get("users")
    except requests.RequestException as e:
        return jsonify({"status": "error", "message": f"NetBird API error: {e}"}), 502

    # Map user IDs to usernames for a clean display name
    user_id_to_name = {
        u["id"]: u.get("name") or u.get("id")
        for u in users
    }

    # Structure: { group_name: { username: set(ips) } }
    group_user_ips = {}
    
    for peer in peers:
        netbird_ip = peer.get("ip", "").strip()
        connection_ip = peer.get("connection_ip", "").strip()
        
        # Collect valid IPs for this peer, ignoring localhost and zero routes
        peer_ips = []
        for ip in [netbird_ip, connection_ip]:
            if ip and ip not in ["127.0.0.1", "0.0.0.0"]:
                peer_ips.append(ip)
                
        # If no valid IPs remain after filtering, skip this peer
        if not peer_ips:
            continue

        # Resolve username via user_id, fall back to hostname if unassigned
        user_id = peer.get("user_id")
        username = user_id_to_name.get(user_id) if user_id else peer.get("hostname") or peer.get("name") or "unknown"

        # Iterate directly through the peer's assigned groups from the payload
        peer_groups = peer.get("groups", [])
        for group_obj in peer_groups:
            group_name = group_obj.get("name", "").strip()
            
            # Skip the catch-all group
            if not group_name or group_name.lower() == "all":
                continue
                
            # Initialize set if group/user combo doesn't exist, then update with collected IPs
            user_set = group_user_ips.setdefault(group_name, {}).setdefault(username, set())
            user_set.update(peer_ips)

    config = read_config()
    groups = config.setdefault("web_filter", {}).setdefault("groups", {})
    changes = {"created": [], "updated": [], "unchanged": []}

    for group_name, users_dict in group_user_ips.items():
        # Converts the internal set into a cleanly sorted array of strings for the JSON payload
        sorted_users_list = [
            {"username": uname, "ips": sorted(list(ips_set))}
            for uname, ips_set in users_dict.items()
        ]
        
        # Sort user lists by username stably to minimize cosmetic file differences
        sorted_users_list = sorted(sorted_users_list, key=lambda x: x["username"])

        if group_name not in groups:
            groups[group_name] = {**DEFAULT_GROUP, "users": sorted_users_list}
            changes["created"].append(group_name)
        else:
            old_users = groups[group_name].get("users", [])
            if json.dumps(old_users, sort_keys=True) != json.dumps(sorted_users_list, sort_keys=True):
                groups[group_name]["users"] = sorted_users_list
                changes["updated"].append(group_name)
            else:
                changes["unchanged"].append(group_name)

    write_config(config)
    reload_icap()

    return jsonify({
        "status": "ok",
        "peers_processed": len(peers),
        "changes": changes
    })


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)