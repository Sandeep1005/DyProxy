import subprocess
import re
import time

from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import yaml
import os
import bcrypt
import secrets
from datetime import timedelta
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address


# Load configuration from YAML file
CONFIG_FILE = "./config.yaml"
with open(CONFIG_FILE, 'r') as file:
    config = yaml.safe_load(file)


NGINX_TEMPLATE_FILE = "./default_nginx_template.txt"
def load_nginx_template():
    if os.path.exists(NGINX_TEMPLATE_FILE):
        with open(NGINX_TEMPLATE_FILE, "r") as file:
            return file.read()
    return ""


NGINS_CONFIG_TEMPLATE = load_nginx_template()


app = Flask(__name__)


def get_domain_config(domain):
    for entry in config.get("ddns_entries"):
        if domain == entry['domain_name']:
            return entry
    return None


def update_last_updated_list():
    for entry in config["ddns_entries"]:
        if not entry["domain_name"] in config["last_updated"]:
            config["last_updated"][entry["domain_name"]] = None
    
    existing_domains = [entry["domain_name"] for entry in config["ddns_entries"]]
    for domain_name in config["last_updated"].keys():
        if domain_name not in existing_domains:
            del config["last_updated"][entry["domain_name"]]


update_last_updated_list()


@app.route("/update_ipv6", methods=["POST"])
def update_ipv6():
    domain = request.json.get("domain_name")
    access_code = request.json.get("access_code")
    new_ipv6 = request.json.get("ipv6")

    domain_config = get_domain_config(domain)

    if domain_config is None:
        return jsonify({"error": "Domain is not registered for ddns"}), 403

    if domain_config['access_code'] != access_code:
        return jsonify({"error": "Unauthorized (incorrect access code)"}), 403

    if domain_config['ipv6_address'] == new_ipv6:
        # Updating last updated value
        config["last_updated"][domain] = time.time()

        # Dumping the updated configuration
        with open(CONFIG_FILE, "w") as file:
            yaml.safe_dump(config, file, default_flow_style=False, sort_keys=False)

        return jsonify({"message": "Already set to the same IPv6"})

    if not re.match(r'^[a-fA-F0-9:]+$', new_ipv6):
        return jsonify({"error": "Invalid IPv6 address format"}), 400
    else:
        domain_config['ipv6_address'] = new_ipv6

    try:
        nginx_config = get_domain_nginx_config(domain_name=domain,
                                                protocol=domain_config['protocol'],
                                                ipv6_address=new_ipv6)

        echo_process = subprocess.Popen(["echo", nginx_config], stdout=subprocess.PIPE)
        subprocess.run(["sudo", "tee", domain_config['config_file_path']], stdin=echo_process.stdout, check=True)
        print(f"Created {domain_config['config_file_path']} with IPv6: {new_ipv6}")

        # Reload Nginx with sudo
        subprocess.run(["sudo", "systemctl", "reload", "nginx"], check=True)
        print("Nginx reloaded successfully")

        # Updating last updated value
        config["last_updated"][domain] = time.time()

        # Dumping the updated configuration
        with open(CONFIG_FILE, "w") as file:
            yaml.safe_dump(config, file, default_flow_style=False, sort_keys=False)

        return jsonify({"message": "IPv6 address updated successfully"})

    except Exception as e:
        return jsonify({"error": str(e)}), 500


def get_domain_nginx_config(domain_name, protocol, ipv6_address):
    return NGINS_CONFIG_TEMPLATE.replace("$#@domain_name", domain_name).replace("$#@protocol", protocol).replace("$#@ipv6_address", ipv6_address)


def create_reverse_proxies():
    for entry in config.get("ddns_entries"):
        domain_name = entry['domain_name']
        protocol = entry['protocol']
        ipv6 = entry['ipv6_address']
        config_file_path = entry['config_file_path']

        if ipv6 is None:
            ipv6 = "2001:db8::1"

        nginx_config = get_domain_nginx_config(domain_name=domain_name,
                                               protocol=protocol,
                                               ipv6_address=ipv6)

        echo_process = subprocess.Popen(["echo", nginx_config], stdout=subprocess.PIPE)
        subprocess.run(["sudo", "tee", config_file_path], stdin=echo_process.stdout, check=True)
        print(f"Created {config_file_path} with IPv6: {ipv6}")

    # Reload Nginx with sudo
    subprocess.run(["sudo", "systemctl", "reload", "nginx"], check=True)
    print("Nginx reloaded successfully")


def create_single_reverse_proxy(domain_name, config_file_path, protocol, ipv6_address):
    try:
        nginx_config = get_domain_nginx_config(domain_name=domain_name,
                                                protocol=protocol,
                                                ipv6_address=ipv6_address)
        
        echo_process = subprocess.Popen(["echo", nginx_config], stdout=subprocess.PIPE)
        subprocess.run(["sudo", "tee", config_file_path], stdin=echo_process.stdout, check=True)
        print(f"Created {config_file_path} with IPv6: {ipv6_address}")

        # Reload Nginx with sudo
        subprocess.run(["sudo", "systemctl", "reload", "nginx"], check=True)
        print("Nginx reloaded successfully")

        return True
    except:
        return False


def delete_single_reverse_proxy(config_file_path):
    try:
        subprocess.run(["sudo", "rm", config_file_path], check=True)

        # Reload Nginx with sudo
        subprocess.run(["sudo", "systemctl", "reload", "nginx"], check=True)
        print("Nginx reloaded successfully")

        return True
    except:
        return False


app.secret_key = os.getenv("SECRET_KEY", secrets.token_hex(32))  # Secure secret key
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=15)  # Auto logout after 15 min

# Rate limiter to prevent brute-force attacks
limiter = Limiter(get_remote_address, app=app, default_limits=["5 per minute"])

CONFIG_FILE = "config.yaml"
AUTH_FILE = "auth.yaml"


def load_config():
    if not os.path.exists(CONFIG_FILE):
        return {"ddns_entries": []}
    with open(CONFIG_FILE, "r") as file:
        return yaml.safe_load(file) or {"ddns_entries": []}


def save_config(data):
    with open(CONFIG_FILE, "w") as file:
        yaml.safe_dump(data, file)


def load_auth():
    if not os.path.exists(AUTH_FILE):
        return {"users": {}}
    with open(AUTH_FILE, "r") as file:
        return yaml.safe_load(file)


def check_password(stored_password, provided_password):
    return bcrypt.checkpw(provided_password.encode("utf-8"), stored_password.encode("utf-8"))


@app.route("/", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        auth_data = load_auth()
        
        if username in auth_data["users"] and check_password(auth_data["users"][username], password):
            session["username"] = username
            session["session_id"] = secrets.token_hex(16)
            return redirect(url_for("dashboard"))
        
        return render_template("login.html", error="Invalid username or password")
    
    return render_template("login.html")


@app.route("/dashboard")
def dashboard():
    if "username" not in session:
        return redirect(url_for("login"))
    config = load_config()

    last_updated_times = config["last_updated"].copy()
    for domain, prev_time in last_updated_times.items():
        last_updated_times[domain] = round((time.time() - float(prev_time)) / 60) if prev_time else "NA"
    
    return render_template("index.html", 
                           entries=config["ddns_entries"], 
                           username=session["username"], 
                           nginx_template=NGINS_CONFIG_TEMPLATE,
                           entry_keys=config["required_keys"],
                           last_updated=last_updated_times)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.post("/update_entity")
def update_entity():
    if "username" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    index = int(request.form["index"])
    domain_name = request.form["domain_name"]
    config_file_path = request.form["config_file_path"]
    protocol = request.form["protocol"]
    ipv6_address = request.form.get("ipv6_address", None)
    access_code = request.form["access_code"]
    
    # config = load_config()
    if index >= len(config["ddns_entries"]):
        return jsonify({"error": "Entity not found"}), 404
    
    config["ddns_entries"][index] = {
        "domain_name": domain_name,
        "config_file_path": config_file_path,
        "protocol": protocol,
        "ipv6_address": ipv6_address,
        "access_code": access_code
    }

    # Updating the nginx config for the site
    is_success = create_single_reverse_proxy(domain_name, config_file_path, protocol, ipv6_address)
    if not is_success:
        return jsonify({"message": "Entity updation failed"})
    else:
        config["last_updated"][domain_name] = time.time()
        save_config(config)    
        return jsonify({"message": "Entity updated successfully"})


@app.post("/add_entity")
def add_entity():
    if "username" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    domain_name = request.form["domain_name"]
    config_file_path = request.form["config_file_path"]
    protocol = request.form["protocol"]
    ipv6_address = request.form.get("ipv6_address", None)
    access_code = request.form["access_code"]
    
    # config = load_config()
    config["ddns_entries"].append({
        "domain_name": domain_name,
        "config_file_path": config_file_path,
        "protocol": protocol,
        "ipv6_address": ipv6_address,
        "access_code": access_code
    })

    # Updating the nginx config for the site
    is_success = create_single_reverse_proxy(domain_name, config_file_path, protocol, ipv6_address)
    if not is_success:
        return jsonify({"message": "Entity addition failed"})
    else:
        update_last_updated_list()
        save_config(config)    
        return jsonify({"message": "Entity added successfully"})


@app.post("/delete_entity")
def delete_entity():
    if "username" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    index = int(request.form["index"])
    # config = load_config()
    
    if index >= len(config["ddns_entries"]):
        return jsonify({"error": "Entity not found"}), 404
    
    is_success = delete_single_reverse_proxy(config["ddns_entries"][index]["config_file_path"])
    if not is_success:
        return jsonify({"message": "Entity deletion failed"})
    else:
        del config["ddns_entries"][index]
        update_last_updated_list()
        save_config(config)
        return jsonify({"message": "Entity deleted successfully"})


@app.post("/update_nginx_template")
def update_nginx_template():
    global NGINS_CONFIG_TEMPLATE
    if "username" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    NGINS_CONFIG_TEMPLATE = request.form["template"]
    return jsonify({"message": "Nginx template updated successfully"})


@app.post("/reset_nginx_template")
def reset_nginx_template():
    global NGINS_CONFIG_TEMPLATE
    if "username" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    NGINS_CONFIG_TEMPLATE = load_nginx_template()
    return jsonify({"message": "Nginx template reset to default", "template": NGINS_CONFIG_TEMPLATE})


@app.route('/get_nginx_template', methods=['GET'])
def get_nginx_template():
    if "username" not in session:
        return jsonify({"error": "Unauthorized"}), 401  # Return 401 if not logged in

    return jsonify({"template": NGINS_CONFIG_TEMPLATE})
