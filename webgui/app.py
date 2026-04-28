import json
import os
import signal
import subprocess
from flask import Flask, render_template, request, jsonify


app = Flask(__name__)

CONFIG_DIR = "/opt/CIRNO-ICAP"
CONFIG_FILE = f"{CONFIG_DIR}/config.json"
PHRASELIST_DIR = f"{CONFIG_DIR}/phraselist"

def read_config():
    try:
        with open(CONFIG_FILE) as f:
            return json.load(f)
    except FileNotFoundError:
        return {"groups": {}}

def write_config(config):
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=4)

def reload_icap():
    subprocess.run(["sudo", "/usr/bin/systemctl", "kill", "-s", "USR1", "CIRNO-ICAP"])

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
    
    # Only update the keys the GUI manages, preserve everything else
    existing['default'] = incoming.get('default', existing.get('default', {}))
    existing['groups'] = incoming.get('groups', existing.get('groups', {}))
    
    write_config(existing)
    reload_icap()
    return jsonify({"status": "ok"})

# --- Groups ---
@app.route('/api/groups', methods=['GET'])
def get_groups():
    return jsonify(read_config().get("groups", {}))

@app.route('/api/groups/<name>', methods=['POST'])
def save_group(name):
    config = read_config()
    config["groups"][name] = request.json
    write_config(config)
    reload_icap()
    return jsonify({"status": "ok"})

@app.route('/api/groups/<name>', methods=['DELETE'])
def delete_group(name):
    config = read_config()
    config["groups"].pop(name, None)
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

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)