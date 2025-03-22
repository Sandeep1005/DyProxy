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


NGINX_TEMPLATE_FILE_HTTP = "./default_nginx_template_http.txt"
NGINX_TEMPLATE_FILE_HTTPS = "./default_nginx_template_https.txt"
def load_nginx_template(protocol='http'):
    if protocol == 'http':
        if os.path.exists(NGINX_TEMPLATE_FILE_HTTP):
            with open(NGINX_TEMPLATE_FILE_HTTP, "r") as file:
                return file.read()
        return ""
    
    if protocol == 'https':
        if os.path.exists(NGINX_TEMPLATE_FILE_HTTPS):
            with open(NGINX_TEMPLATE_FILE_HTTPS, "r") as file:
                return file.read()
        return ""
    

NGINX_CONFIG_TEMPLATE = load_nginx_template()


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


def is_authentic_request(domain_config, access_code):
    if domain_config is None:
        return False
    elif domain_config['access_code'] == access_code:
        return True
    else:
        return False
    

def is_ipv6_updated(domain_config, new_ipv6):
    if domain_config['ipv6_address'] == new_ipv6:
        return False
    else: return True


def is_ssl_certs_updated(domain_config, ssl_private_key, ssl_certificate_crt):
    if os.path.exists(domain_config['ssl_private_key_path']) and os.path.exists(domain_config['ssl_certificate_crt_path']):
        with open(domain_config['ssl_private_key_path'], 'r') as file:
            prev_ssl_private_key = file.read()
        with open(domain_config['ssl_certificate_crt_path'], 'r') as file:
            prev_ssl_certificate_crt = file.read()
        
        if ssl_private_key is None or ssl_certificate_crt is None:
            return True
        elif prev_ssl_certificate_crt == ssl_certificate_crt and prev_ssl_private_key == ssl_private_key:
            return False
        else:
            return True
    else:
        if ssl_private_key is None or ssl_certificate_crt is None:
            return False
        else:
            return True
        

def update_ssl_keys(domain_config, ssl_private_key, ssl_certificate_crt):
    if ssl_private_key is None or ssl_certificate_crt is None:
        domain_config['protocol'] = 'http'
    else:
        # Update the SSL key and certificate files
        dir_name = os.path.dirname(domain_config['ssl_private_key_path'])
        if not os.path.exists(dir_name):
            os.makedirs(dir_name)
        
        command = f"echo '{ssl_private_key}' | sudo tee {domain_config['ssl_private_key_path']} > /dev/null"
        subprocess.run(command, shell=True, check=True)

        command = f"echo '{ssl_certificate_crt}' | sudo tee {domain_config['ssl_certificate_crt_path']} > /dev/null"
        subprocess.run(command, shell=True, check=True)

        domain_config['protocol'] = 'https'

    
def get_current_date_time():
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())


@app.route("/update_ipv6", methods=['POST'])
def update_ipv6():
    domain_name = request.json.get("domain_name")
    access_code = request.json.get("access_code")
    new_ipv6 = request.json.get("ipv6")

    ssl_private_key = None
    ssl_certificate_crt = None
    if "ssl_private_key" in request.json and "ssl_certificate_crt" in request.json:
        ssl_private_key = request.json.get("ssl_private_key")
        ssl_certificate_crt = request.json.get("ssl_certificate_crt")

    # 1) Check if domain name exists in current sites
    domain_config = get_domain_config(domain_name)
    if domain_config is None:
        return jsonify({"error": "Domain is not registered for DDNS"}), 403
    
    # 2) Authentication with domain name and access code
    if not is_authentic_request(domain_config=domain_config, access_code=access_code):
        return jsonify({"error": "Unauthorized (incorrect access code)"}), 403
    
    # 3) Check if IPv6 address is valid
    if not re.match(r'^[a-fA-F0-9:]+$', new_ipv6):
        return jsonify({"error": "Invalid IPv6 address format"}), 400
    
    # Last ping time update
    config["last_updated"][domain_name] = time.time()

    # Check which parts are updated
    ipv6_updated = is_ipv6_updated(domain_config=domain_config, new_ipv6=new_ipv6)
    ssl_updated = is_ssl_certs_updated(domain_config=domain_config, ssl_private_key=ssl_private_key, ssl_certificate_crt=ssl_certificate_crt)

    # If neither got updated
    if (ipv6_updated is False) and (ssl_updated is False):
        return jsonify({"message": "IPv6 and SSL are both same as requested values"})

    # If IPv6 is updated
    if ipv6_updated:
        domain_config['previous_ipv6'] = domain_config['ipv6_address']
        domain_config['ipv6_address'] = new_ipv6
        domain_config['ipv6_updated_on'] = get_current_date_time()

    # If SSL is updated
    if ssl_updated:
        # Updating the files of SSL keys
        update_ssl_keys(domain_config, ssl_private_key, ssl_certificate_crt)
        domain_config['ssl_updated_on'] = get_current_date_time()

    # Generate final NGINX config
    nginx_config = get_domain_nginx_config(domain_name=domain_config['domain_name'],
                                            protocol=domain_config['protocol'],
                                            ipv6_address=domain_config['ipv6_address'],
                                            ssl_private_key_path=domain_config['ssl_private_key_path'],
                                            ssl_certificate_crt_path=domain_config['ssl_certificate_crt_path'])
    
    # Change the nginx config file
    echo_process = subprocess.Popen(["echo", nginx_config], stdout=subprocess.PIPE)
    subprocess.run(["sudo", "tee", domain_config['config_file_path']], stdin=echo_process.stdout, check=True)
    print(f"Created {domain_config['config_file_path']} with IPv6: {new_ipv6}")

    # Reload Nginx with sudo
    subprocess.run(["sudo", "systemctl", "reload", "nginx"], check=True)
    print("Nginx reloaded successfully")

    # Dumping the updated configuration
    with open(CONFIG_FILE, "w") as file:
        yaml.safe_dump(config, file, default_flow_style=False, sort_keys=False)

    if ipv6_updated and ssl_updated:
        return jsonify({"message": "Both IPv6 and SSL are updated"})
    elif ipv6_updated:
        return jsonify({"message": "Only IPv6 is updated"})
    else:
        return jsonify({"message": "Only SSL is updated"})


@app.route("/update_ipv6_old", methods=["POST"])
def update_ipv6_old():
    domain = request.json.get("domain_name")
    access_code = request.json.get("access_code")
    new_ipv6 = request.json.get("ipv6")

    ssl_private_key = None
    ssl_certificate_crt = None
    if "ssl_private_key" in request.json and "ssl_certificate_crt" in request.json:
        ssl_private_key = request.json.get("ssl_private_key")
        ssl_certificate_crt = request.json.get("ssl_certificate_crt")

    domain_config = get_domain_config(domain)

    if domain_config is None:
        return jsonify({"error": "Domain is not registered for ddns"}), 403

    if domain_config['access_code'] != access_code:
        return jsonify({"error": "Unauthorized (incorrect access code)"}), 403

    if domain_config['ipv6_address'] == new_ipv6:
        # Updating last updated value
        config["last_updated"][domain] = time.time()

        # Handle SSL changes
        if ssl_private_key is not None and ssl_certificate_crt is not None:
            folder_path = os.path.join('etc', 'nginx', 'ssl', domain_config['domain_name'])
            domain_config['ssl_private_key_path'] = os.path.join(folder_path, 'private.key')
            domain_config['ssl_certificate_crt_path'] = os.path.join(folder_path, 'certificate.crt')
            domain_config['protocol'] = 'https'
            
            # Writing the SSL certs to the paths
            if not os.path.exists(folder_path):
                os.makedirs(folder_path)
            with open(domain_config['ssl_private_key_path'], 'w') as file:
                file.write(ssl_private_key)
            with open(domain_config['ssl_certificate_crt_path'], 'w') as file:
                file.write(ssl_certificate_crt)

            create_single_reverse_proxy(domain_config['domain_name'], 
                                        domain_config['config_file_path'], 
                                        domain_config['protocol'], 
                                        domain_config['ipv6_address'], 
                                        domain_config['ssl_private_key_path'], 
                                        domain_config['ssl_certificate_crt_path'])

        # Dumping the updated configuration
        with open(CONFIG_FILE, "w") as file:
            yaml.safe_dump(config, file, default_flow_style=False, sort_keys=False)

        return jsonify({"message": "Already set to the same IPv6"})

    if not re.match(r'^[a-fA-F0-9:]+$', new_ipv6):
        return jsonify({"error": "Invalid IPv6 address format"}), 400
    else:
        old_ipv6 = domain_config['ipv6_address']
        domain_config['ipv6_address'] = new_ipv6
        
        # Handle SSL changes
        if ssl_private_key is not None and ssl_certificate_crt is not None:
            folder_path = os.path.join('etc', 'nginx', 'ssl', domain_config['domain_name'])
            domain_config['ssl_private_key_path'] = os.path.join(folder_path, 'private.key')
            domain_config['ssl_certificate_crt_path'] = os.path.join(folder_path, 'certificate.crt')
            domain_config['protocol'] = 'https'
            
            # Writing the SSL certs to the paths
            if not os.path.exists(folder_path):
                os.makedirs(folder_path)
            with open(domain_config['ssl_private_key_path'], 'w') as file:
                file.write(ssl_private_key)
            with open(domain_config['ssl_certificate_crt_path'], 'w') as file:
                file.write(ssl_certificate_crt)

        try:
            nginx_config = get_domain_nginx_config(domain_name=domain,
                                                    protocol=domain_config['protocol'],
                                                    ipv6_address=new_ipv6,
                                                    ssl_private_key_path=domain_config['ssl_private_key_path'],
                                                    ssl_certificate_crt_path=domain_config['ssl_certificate_crt_path'])

            echo_process = subprocess.Popen(["echo", nginx_config], stdout=subprocess.PIPE)
            subprocess.run(["sudo", "tee", domain_config['config_file_path']], stdin=echo_process.stdout, check=True)
            print(f"Created {domain_config['config_file_path']} with IPv6: {new_ipv6}")

            # Reload Nginx with sudo
            subprocess.run(["sudo", "systemctl", "reload", "nginx"], check=True)
            print("Nginx reloaded successfully")

            # Updating last updated value
            config["last_updated"][domain] = time.time()

            # Updating the date at which IPv6 is changed
            domain_config['ipv6_updated_on'] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

            # Updating the previous IPv6
            domain_config['previous_ipv6'] = old_ipv6

            # Dumping the updated configuration
            with open(CONFIG_FILE, "w") as file:
                yaml.safe_dump(config, file, default_flow_style=False, sort_keys=False)

            return jsonify({"message": "IPv6 address updated successfully"})

        except Exception as e:
            return jsonify({"error": str(e)}), 500


def get_domain_nginx_config(domain_name, protocol, ipv6_address, ssl_private_key_path=None, ssl_certificate_crt_path=None):
    if ssl_private_key_path is None or ssl_certificate_crt_path is None:
        if os.path.exists(ssl_private_key_path) is False or os.path.exists(ssl_certificate_crt_path) is False:
            config = load_nginx_template()
            config = config.replace("$#@domain_name", domain_name)
            config = config.replace("$#@protocol", protocol)
            config = config.replace("$#@ipv6_address", ipv6_address)
            return config
    else:
        config = load_nginx_template(protocol='https')
        config = config.replace("$#@domain_name", domain_name)
        config = config.replace("$#@protocol", protocol)
        config = config.replace("$#@ipv6_address", ipv6_address)
        config = config.replace("$#@ssl_private_key_path", ssl_private_key_path)
        config = config.replace("$#@ssl_certificate_crt_path", ssl_certificate_crt_path)
        return config


def create_reverse_proxies():
    for entry in config.get("ddns_entries"):
        domain_name = entry['domain_name']
        protocol = entry['protocol']
        ipv6 = entry['ipv6_address']
        config_file_path = entry['config_file_path']
        ssl_private_key_path = entry['ssl_private_key_path']
        ssl_certificate_crt_path = entry['ssl_certificate_crt_path']

        if ipv6 is None:
            ipv6 = "2001:db8::1"

        nginx_config = get_domain_nginx_config(domain_name=domain_name,
                                               protocol=protocol,
                                               ipv6_address=ipv6,
                                               ssl_private_key_path=ssl_private_key_path,
                                               ssl_certificate_crt_path=ssl_certificate_crt_path)

        echo_process = subprocess.Popen(["echo", nginx_config], stdout=subprocess.PIPE)
        subprocess.run(["sudo", "tee", config_file_path], stdin=echo_process.stdout, check=True)
        print(f"Created {config_file_path} with IPv6: {ipv6}")

    # Reload Nginx with sudo
    subprocess.run(["sudo", "systemctl", "reload", "nginx"], check=True)
    print("Nginx reloaded successfully")


def create_single_reverse_proxy(domain_name, 
                                config_file_path, 
                                protocol, 
                                ipv6_address, 
                                ssl_private_key_path, 
                                ssl_certificate_crt_path):
    try:
        nginx_config = get_domain_nginx_config(domain_name=domain_name,
                                                protocol=protocol,
                                                ipv6_address=ipv6_address,
                                                ssl_private_key_path=ssl_private_key_path,
                                                ssl_certificate_crt_path=ssl_certificate_crt_path)
        
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
                           nginx_template=NGINX_CONFIG_TEMPLATE,
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
    nginx_config = request.form["nginx_config"]
    
    # config = load_config()
    if index >= len(config["ddns_entries"]):
        return jsonify({"error": "Entity not found"}), 404
    
    config["ddns_entries"][index] = {
        "domain_name": domain_name,
        "config_file_path": config_file_path,
        "protocol": protocol,
        "ipv6_address": ipv6_address,
        "access_code": access_code,
        "nginx_config": nginx_config,
    }

    # Updating the nginx config for the site
    is_success = create_single_reverse_proxy(domain_name, 
                                             config_file_path, 
                                             protocol, 
                                             ipv6_address, 
                                             config["ddns_entries"][index]['ssl_private_key_path'],
                                             config["ddns_entries"][index]['ssl_certificate_crt_path'])
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
    nginx_config = request.form["nginx_config"]
    
    # config = load_config()
    config["ddns_entries"].append({
        "domain_name": domain_name,
        "config_file_path": config_file_path,
        "protocol": protocol,
        "ipv6_address": ipv6_address,
        "access_code": access_code,
        "previous_ipv6": "0000:0000:0000:0000:0000:0000:0000:0000",
        "ipv6_updated_on": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
        "nginx_config": nginx_config,
        "ssl_private_key_path": f"/etc/nginx/ssl/{domain_name}/private.key",
        "ssl_certificate_crt_path": f"/etc/nginx/ssl/{domain_name}/certificate.crt"
    })

    # Updating the nginx config for the site
    is_success = create_single_reverse_proxy(domain_name, 
                                            config_file_path, 
                                            protocol, 
                                            ipv6_address)
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
    global NGINX_CONFIG_TEMPLATE
    if "username" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    NGINX_CONFIG_TEMPLATE = request.form["template"]
    return jsonify({"message": "Nginx template updated successfully"})


@app.post("/reset_nginx_template")
def reset_nginx_template():
    global NGINX_CONFIG_TEMPLATE
    if "username" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    NGINX_CONFIG_TEMPLATE = load_nginx_template()
    return jsonify({"message": "Nginx template reset to default", "template": NGINX_CONFIG_TEMPLATE})


@app.route('/get_nginx_template', methods=['GET'])
def get_nginx_template():
    if "username" not in session:
        return jsonify({"error": "Unauthorized"}), 401  # Return 401 if not logged in

    return jsonify({"template": NGINX_CONFIG_TEMPLATE})
