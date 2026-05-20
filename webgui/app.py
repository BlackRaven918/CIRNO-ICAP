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

# Updated default skeleton for a newly created group using nested user arrays
DEFAULT_GROUP = {
    "block_threshold": 400,
    "enabled_categories": [],
    "google_safe_search": False,
    "users": []
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


# --- NetBird Sync ---
@app.route('/api/sync-netbird', methods=['POST'])
def sync_netbird():
    if not NETBIRD_TOKEN:
        return jsonify({"status": "error", "message": "NETBIRD_TOKEN environment variable is not set"}), 500

    try:
        peers     = netbird_get("peers")
        users     = netbird_get("users")
        nb_groups = netbird_get("groups")
    except requests.RequestException as e:
        return jsonify({"status": "error", "message": f"NetBird API error: {e}"}), 502

    group_id_to_name = {
        g["id"]: g["name"]
        for g in nb_groups
        if g.get("name", "").lower() != "all"
    }

    user_id_to_info = {
        u["id"]: {
            "username": u.get("name") or u.get("id"),
            "groups": [group_id_to_name[gid] for gid in u.get("auto_groups", []) if gid in group_id_to_name]
        }
        for u in users
    }

    # Structure: { group_name: { username: set(ips) } }
    group_user_ips = {}
    for peer in peers:
        connection_ip = peer.get("ip", "").strip()
        if not connection_ip:
            continue
        user_id = peer.get("user_id", "")
        if user_id in user_id_to_info:
            u_info = user_id_to_info[user_id]
            username = u_info["username"]
            for g_name in u_info["groups"]:
                group_user_ips.setdefault(g_name, {}).setdefault(username, set()).add(connection_ip)

    config = read_config()
    groups = config.setdefault("web_filter", {}).setdefault("groups", {})
    changes = {"created": [], "updated": [], "unchanged": []}

    for group_name, users_dict in group_user_ips.items():
        sorted_users_list = [
            {"username": uname, "ips": sorted(list(ips_set))}
            for uname, ips_set in sorted_users_list.items()
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