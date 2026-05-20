import json
import os
import subprocess
import requests
from flask import Flask, render_template, request, jsonify

app = Flask(__name__)
CONFIG_DIR = "/opt/CIRNO-ICAP"
CONFIG_FILE = f"{CONFIG_DIR}/config.json"
PHRASELIST_DIR = f"{CONFIG_DIR}/phraselist"

NETBIRD_BASE_URL = "https://netbird.newwave.local/api"
NETBIRD_TOKEN = os.environ.get("NETBIRD_TOKEN", "")

# Default skeleton for a newly created group
DEFAULT_GROUP = {
    "block_threshold": 400,
    "enabled_categories": [],
    "google_safe_search": False,
    "ips": []
}


def read_config():
    with open(CONFIG_FILE) as f:
        return json.load(f)


def write_config(config):
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=4)


def reload_icap():
    subprocess.run(["sudo", "/usr/bin/systemctl", "kill", "-s", "USR1", "CIRNO-ICAP"])


def netbird_get(path):
    """GET from the NetBird API, returns parsed JSON or raises."""
    resp = requests.get(
        f"{NETBIRD_BASE_URL}/{path}",
        headers={"Authorization": f"Bearer {NETBIRD_TOKEN}"},
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
    write_config(existing)
    reload_icap()
    return jsonify({"status": "ok"})


@app.route('/api/config/dlp', methods=['POST'])
def save_dlp():
    existing = read_config()
    existing['dlp'] = request.json
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
    for cat in os.listdir(PHRASELIST_DIR):
        if os.path.isdir(os.path.join(PHRASELIST_DIR, cat)):
            categories.append(cat)
    return jsonify(categories)


@app.route('/api/categories/<category>/keywords', methods=['GET'])
def get_keywords(category):
    keywords = []
    cat_path = os.path.join(PHRASELIST_DIR, category)
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

@app.route('/api/groups', methods=['GET'])
def get_groups_response():
    config = read_config()
    groups = config.get("web_filter", {}).get("groups", {})
    # Return just name -> ips mapping
    return jsonify({
        name: data.get("ips", [])
        for name, data in groups.items()
    })
# --- NetBird Sync ---
@app.route('/api/sync-netbird', methods=['POST'])
def sync_netbird():
    """
    Sync NetBird peers into CIRNO web_filter groups using Entra ID group
    membership.

    Flow:
      1. Fetch /api/peers, /api/users, /api/groups from NetBird.
      2. Build a map of group_id -> group_name (skip "All").
      3. For each peer, find the matching user via peer.user_id == user.id,
         then resolve the user's auto_groups IDs to names.
      4. Map each peer's connection_ip into those group names.
      5. Create any missing groups in CIRNO config with DEFAULT_GROUP settings,
         update IPs for existing ones, and reload ICAP.
    """
    if not NETBIRD_TOKEN:
        return jsonify({"status": "error", "message": "NETBIRD_TOKEN environment variable is not set"}), 500

    try:
        peers     = netbird_get("peers")
        users     = netbird_get("users")
        nb_groups = netbird_get("groups")
    except requests.RequestException as e:
        return jsonify({"status": "error", "message": f"NetBird API error: {e}"}), 502

    # group_id -> group_name, excluding "All"
    group_id_to_name = {
        g["id"]: g["name"]
        for g in nb_groups
        if g.get("name", "").lower() != "all"
    }

    # user_id -> list of resolved group names (via auto_groups)
    user_id_to_groups = {
        u["id"]: [
            group_id_to_name[gid]
            for gid in u.get("auto_groups", [])
            if gid in group_id_to_name
        ]
        for u in users
    }

    # Build group_name -> set of connection_ips
    group_ips: dict[str, set] = {}
    for peer in peers:
        connection_ip = peer.get("ip", "").strip()
        if not connection_ip:
            continue
        user_id = peer.get("user_id", "")
        group_names = user_id_to_groups.get(user_id, [])
        for name in group_names:
            group_ips.setdefault(name, set()).add(connection_ip)

    config = read_config()
    groups = config.setdefault("web_filter", {}).setdefault("groups", {})
    changes = {"created": [], "updated": [], "unchanged": []}

    for group_name, ips in group_ips.items():
        sorted_ips = sorted(ips)
        if group_name not in groups:
            groups[group_name] = {**DEFAULT_GROUP, "ips": sorted_ips}
            changes["created"].append(group_name)
        else:
            old_ips = sorted(groups[group_name].get("ips", []))
            if old_ips != sorted_ips:
                groups[group_name]["ips"] = sorted_ips
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
