import subprocess
import re
import time

import io
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, send_file
import yaml
import os
import bcrypt
import secrets
from datetime import timedelta, datetime
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address


CONFIG_FILE = "./config.yaml"

NGINX_TEMPLATE_FILE_HTTP = "./default_nginx_template_http.txt"
NGINX_TEMPLATE_FILE_HTTPS = "./default_nginx_template_https.txt"

AUTH_FILE = "auth.yaml"

CLIENT_TOOL_CODE_PATH="client_bash_code.txt"
CHECK_IP_SERVICE="http://ipv6check.bysandeep.site/"
DDNS_UPDATE_URL="http://ddnsdiy.bysandeep.site/update_ipv6"
GET_CLIENT_TOOL_URL = "http://ddnsdiy.bysandeep.site/get_client_tool_code"


def load_config():
    with open(CONFIG_FILE, 'r') as file:
        config = yaml.safe_load(file)
    return config


def save_config(updated_config):
    with open(CONFIG_FILE, "w") as file:
        yaml.safe_dump(updated_config, file, default_flow_style=False, sort_keys=False)


def load_global_variables():
    config = load_config()
    global_vars = config["global_variables"]
    
    global NGINX_TEMPLATE_FILE_HTTP
    NGINX_TEMPLATE_FILE_HTTP = global_vars["NGINX_TEMPLATE_FILE_HTTP"]
    global NGINX_TEMPLATE_FILE_HTTPS
    NGINX_TEMPLATE_FILE_HTTPS = global_vars["NGINX_TEMPLATE_FILE_HTTPS"]
    global AUTH_FILE
    AUTH_FILE = global_vars["AUTH_FILE"]
    global CLIENT_TOOL_CODE_PATH
    CLIENT_TOOL_CODE_PATH = global_vars["CLIENT_TOOL_CODE_PATH"]
    global CHECK_IP_SERVICE
    CHECK_IP_SERVICE = f"{config['required_sites']['ipv6_checker']['protocol']}://{config['required_sites']['ipv6_checker']['domain_name']}/"
    global DDNS_UPDATE_URL
    DDNS_UPDATE_URL = f"{config["required_sites"]["app"]["protocol"]}://{config["required_sites"]["app"]["domain_name"]}/{global_vars["DDNS_UPDATE_ENDPOINT"]}"
    global GET_CLIENT_TOOL_URL
    GET_CLIENT_TOOL_URL = f"{config["required_sites"]["app"]["protocol"]}://{config["required_sites"]["app"]["domain_name"]}/{global_vars["GET_CLIENT_TOOL_ENDPOINT"]}"


def get_domain_config(domain):
    config = load_config()
    if domain in config.get("ddns_entries"):
        return config["ddns_entries"][domain]
    else:
        return None
    

def load_default_nginx_template(protocol='http'):
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
    

def get_custom_nginx_config(domain_name):
    config = load_config()
    if domain_name not in config["ddns_entries"]:
        raise Exception(f"Domain with the name {domain_name} not present")
    
    domain_config = config["ddns_entries"][domain_name]
    custom_nginx_config_path = domain_config["custom_nginx_config_path"]
    if os.path.exists(custom_nginx_config_path):
        with open(custom_nginx_config_path, 'r') as file:
            custom_nginx_config = file.read()
        return custom_nginx_config
    else:
        # Returning default config 
        return load_default_nginx_template(protocol=domain_config["protocol"])
    

def save_custom_nginx_config(domain_name, nginx_config):
    try:
        config = load_config()
        if domain_name not in config["ddns_entries"]:
            raise Exception(f"Domain with the name {domain_name} not present")
        
        domain_config = config["ddns_entries"][domain_name]
        custom_nginx_config_path = domain_config["custom_nginx_config_path"]
        if not os.path.exists(custom_nginx_config_path):
            # Create the necessary directory
            dirname = os.path.dirname(custom_nginx_config_path)
            os.makedirs(dirname, exist_ok=True)

        # Write the file
        subprocess.run(["bash", "-c", f"sudo echo '{nginx_config}' > {custom_nginx_config_path}"], check=True)

        return True
    except Exception as e:
        subprocess.run(["echo", str(e)], check=True)
        print(f"Exception in saving custom config: {e}")
        return False


def load_auth():
    if not os.path.exists(AUTH_FILE):
        return {"users": {}}
    with open(AUTH_FILE, "r") as file:
        return yaml.safe_load(file)
    

def check_password(stored_password, provided_password):
    return bcrypt.checkpw(provided_password.encode("utf-8"), stored_password.encode("utf-8"))


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
        elif prev_ssl_certificate_crt.strip() == ssl_certificate_crt.strip() and prev_ssl_private_key.strip() == ssl_private_key.strip():
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
            subprocess.run(["sudo", "mkdir", "-p", dir_name], check=True)
        
        command = f"echo '{ssl_private_key}' | sudo tee {domain_config['ssl_private_key_path']} > /dev/null"
        subprocess.run(command, shell=True, check=True)

        command = f"echo '{ssl_certificate_crt}' | sudo tee {domain_config['ssl_certificate_crt_path']} > /dev/null"
        subprocess.run(command, shell=True, check=True)

        domain_config['protocol'] = 'https'


def is_protocol_updated(domain_config, ssl_private_key, ssl_certificate_crt):
    if ssl_private_key is None or ssl_certificate_crt is None:
        target_protocol = 'http'
    else:
        target_protocol = 'https'
    
    if domain_config['protocol'] == target_protocol:
        return False
    else:
        return True
    

def get_protocol(ssl_private_key, ssl_certificate_crt):
    if ssl_private_key is None or ssl_certificate_crt is None:
        target_protocol = 'http'
    else:
        target_protocol = 'https'
    return target_protocol

    
def get_current_date_time():
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())


def get_domain_nginx_config(domain_name, 
                            protocol, 
                            ipv6_address, 
                            ssl_private_key_path=None, 
                            ssl_certificate_crt_path=None, 
                            nginx_config='default'):
    if ssl_private_key_path is None or ssl_certificate_crt_path is None:
        if nginx_config == 'default':
            config = load_default_nginx_template()
        else:
            config = get_custom_nginx_config(domain_name=domain_name)
        config = config.replace("$#@domain_name", domain_name)
        config = config.replace("$#@protocol", protocol)
        config = config.replace("$#@ipv6_address", ipv6_address)
        return config
    elif os.path.exists(ssl_private_key_path) is False or os.path.exists(ssl_certificate_crt_path) is False:
        if nginx_config == 'default':
            config = load_default_nginx_template()
        else:
            config = get_custom_nginx_config(domain_name=domain_name)
        config = config.replace("$#@domain_name", domain_name)
        config = config.replace("$#@protocol", protocol)
        config = config.replace("$#@ipv6_address", ipv6_address)
        return config
    else:
        if nginx_config == 'default':
            config = load_default_nginx_template(protocol='https')
        else:
            config = get_custom_nginx_config(domain_name=domain_name)
        config = config.replace("$#@domain_name", domain_name)
        config = config.replace("$#@protocol", protocol)
        config = config.replace("$#@ipv6_address", ipv6_address)
        config = config.replace("$#@ssl_private_key_path", ssl_private_key_path)
        config = config.replace("$#@ssl_certificate_crt_path", ssl_certificate_crt_path)
        return config
    

### Creation and deletion of reverse proxies
def create_reverse_proxies():
    config = load_config()

    for domain, domain_config in config.get("ddns_entries").items():
        domain_name = domain_config['domain_name']
        protocol = domain_config['protocol']
        ipv6 = domain_config['ipv6_address']
        config_file_path = domain_config['config_file_path']
        ssl_private_key_path = domain_config['ssl_private_key_path']
        ssl_certificate_crt_path = domain_config['ssl_certificate_crt_path']

        if ipv6 is None:
            ipv6 = "2001:db8::1"

        nginx_config = get_domain_nginx_config(domain_name=domain_name,
                                               protocol=protocol,
                                               ipv6_address=ipv6,
                                               ssl_private_key_path=ssl_private_key_path,
                                               ssl_certificate_crt_path=ssl_certificate_crt_path,
                                               nginx_config=domain_config["nginx_config"])

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
                                ssl_certificate_crt_path,
                                nginx_config="default"):
    try:
        nginx_config = get_domain_nginx_config(domain_name=domain_name,
                                                protocol=protocol,
                                                ipv6_address=ipv6_address,
                                                ssl_private_key_path=ssl_private_key_path,
                                                ssl_certificate_crt_path=ssl_certificate_crt_path,
                                                nginx_config=nginx_config)
        
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
    

def load_client_tool_template():
    with open(CLIENT_TOOL_CODE_PATH, 'r') as file:
        client_tool_template = file.read()
    return client_tool_template


def get_client_tool_bash_script(domain_name):
    config = load_config()
    if domain_name not in config["ddns_entries"]:
        return "Requested domain does not exist"
    
    tool_code = load_client_tool_template()
    tool_code = tool_code.replace("$#@check_ip_service", CHECK_IP_SERVICE)
    tool_code = tool_code.replace("$#@ddns_update_url", DDNS_UPDATE_URL)
    tool_code = tool_code.replace("$#@access_code", config["ddns_entries"][domain_name]["access_code"])
    tool_code = tool_code.replace("$#@domain_name", domain_name)

    return tool_code


### SSL certificate management for default sites
def obtain_certificate(domain, email):
    try:
        result = subprocess.run([
            "certbot", "certonly", "--standalone",
            "--non-interactive", "--agree-tos",
            "--email", email, "-d", domain
        ], capture_output=True, text=True, check=True)

        # Extract the certificate path from the output
        match = re.search(r'Saving debug log to (.*)', result.stdout)
        if match:
            cert_path = f"/etc/letsencrypt/live/{domain}/fullchain.pem"
            key_path = f"/etc/letsencrypt/live/{domain}/privkey.pem"
            if os.path.exists(cert_path) and os.path.exists(key_path):
                return cert_path, key_path

        raise FileNotFoundError("Certificate files were not found after Certbot execution.")
    
    except subprocess.CalledProcessError as e:
        print(f"Error obtaining certificate: {e}")
    except FileNotFoundError as e:
        print(e)
    
    return None, None  # Return None if something goes wrong


def is_certificate_expired(domain):
    cert_path = f"/etc/letsencrypt/live/{domain}/cert.pem"
    try:
        result = subprocess.run(
            ["openssl", "x509", "-enddate", "-noout", "-in", cert_path],
            capture_output=True, text=True, check=True
        )
        expiry_str = result.stdout.strip().split("=")[1]
        expiry_date = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")

        days_left = (expiry_date - datetime.utcnow()).days
        print(f"Certificate for {domain} expires in {days_left} days.")

        return days_left <= 30  # Renew if 30 days or less
    except Exception as e:
        print(f"Error checking certificate expiry: {e}")
        return True  # Assume expired if check fails
    

def renew_certificate_for_domain(domain):
    try:
        subprocess.run(["certbot", "renew", "--cert-name", domain, "--quiet"], check=True)
        print(f"Certificate for {domain} renewed successfully!")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error renewing certificate for {domain}: {e}")
        return False
    

def are_ssl_certs_present(ssl_certificate_crt_path, ssl_private_key_path):
    if ssl_certificate_crt_path is None or ssl_private_key_path is None:
        return False
    if os.path.exists(ssl_certificate_crt_path) and os.path.exists(ssl_private_key_path):
        return True
    else:
        return False


def create_ipv6_checker_site():
    config = load_config()
    site_config = config["required_sites"]["ipv6_checker"]

    ssl_present = are_ssl_certs_present(site_config["ssl_certificate_crt_path"], site_config["ssl_private_key_path"])
    if ssl_present:
        config_template_path = 'nginx_for_ipv6check_https.txt'
    else:
        config_template_path = 'nginx_for_ipv6check_http.txt'
    with open(config_template_path, 'r') as file:
        config_template = config_template_path.read()
    config_template = config_template.replace("$#@domain_name", site_config["domain_name"])
    if ssl_present:
        config_template = config_template.replace("$#@ssl_certificate_crt_path", site_config["ssl_certificate_crt_path"])
        config_template = config_template.replace("$#@ssl_private_key_path", site_config["ssl_private_key_path"])

    echo_process = subprocess.Popen(["echo", config_template], stdout=subprocess.PIPE)
    subprocess.run(["sudo", "tee", site_config["config_file_path"]], stdin=echo_process.stdout, check=True)
    print(f"Created {site_config["config_file_path"]} for ipv6 check")

    # Reload Nginx with sudo
    subprocess.run(["sudo", "systemctl", "reload", "nginx"], check=True)
    print("Nginx reloaded successfully")

    if not ssl_present:
        cert_path, key_path = obtain_certificate(domain=site_config["domain_name"], email="sandeepzphs98@gmail.com")
        if are_ssl_certs_present(cert_path, key_path):
            config["required_sites"]["ipv6_checker"]["ssl_certificate_crt_path"] = cert_path
            config["required_sites"]["ipv6_checker"]["ssl_private_key_path"] = key_path
        site_config["protocol"] = 'https'
        save_config(config)
        create_ipv6_checker_site()


def create_app_site():
    config = load_config()
    site_config = config["required_sites"]["app"]

    ssl_present = are_ssl_certs_present(site_config["ssl_certificate_crt_path"], site_config["ssl_private_key_path"])
    if ssl_present:
        config_template_path = 'nginx_for_app_https.txt'
    else:
        config_template_path = 'nginx_for_app_http.txt'
    with open(config_template_path, 'r') as file:
        config_template = config_template_path.read()
    config_template = config_template.replace("$#@domain_name", site_config["domain_name"])
    config_template = config_template.replace("$#@app_port", site_config["app_port"])
    if ssl_present:
        config_template = config_template.replace("$#@ssl_certificate_crt_path", site_config["ssl_certificate_crt_path"])
        config_template = config_template.replace("$#@ssl_private_key_path", site_config["ssl_private_key_path"])

    echo_process = subprocess.Popen(["echo", config_template], stdout=subprocess.PIPE)
    subprocess.run(["sudo", "tee", site_config["config_file_path"]], stdin=echo_process.stdout, check=True)
    print(f"Created {site_config["config_file_path"]} for ipv6 check")

    # Reload Nginx with sudo
    subprocess.run(["sudo", "systemctl", "reload", "nginx"], check=True)
    print("Nginx reloaded successfully")

    if not ssl_present:
        cert_path, key_path = obtain_certificate(domain=site_config["domain_name"], email="sandeepzphs98@gmail.com")
        if are_ssl_certs_present(cert_path, key_path):
            config["required_sites"]["ipv6_checker"]["ssl_certificate_crt_path"] = cert_path
            config["required_sites"]["ipv6_checker"]["ssl_private_key_path"] = key_path
        site_config["protocol"] = 'https'
        save_config(config)
        create_ipv6_checker_site()



# Function that will adjust things before server starts
def initial_setup():
    # Loading updated global variables
    load_global_variables()

    # Create reverse proxies for existing sites
    create_reverse_proxies()

    # Create Sites for required services (ipv6check and app)
    create_ipv6_checker_site()
    create_app_site()


# Calling the initial setup function
initial_setup()


### Flask app and end points
app = Flask(__name__)


app.secret_key = os.getenv("SECRET_KEY", secrets.token_hex(32))  # Secure secret key
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=15)  # Auto logout after 15 min

# Rate limiter to prevent brute-force attacks
limiter = Limiter(get_remote_address, app=app, default_limits=["5 per minute"])


# End point for clients to update proxy config
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

    # Load config into variable
    current_config = load_config()

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
    domain_config["last_pinged_at"] = time.time()

    # Check which parts are updated
    ipv6_updated = is_ipv6_updated(domain_config=domain_config, new_ipv6=new_ipv6)
    ssl_updated = is_ssl_certs_updated(domain_config=domain_config, ssl_private_key=ssl_private_key, ssl_certificate_crt=ssl_certificate_crt)
    protocol_updated = is_protocol_updated(domain_config=domain_config, ssl_private_key=ssl_private_key, ssl_certificate_crt=ssl_certificate_crt)

    # If neither got updated
    if (ipv6_updated is False) and (ssl_updated is False) and (protocol_updated is False):
        # Dumping the updated configuration
        current_config["ddns_entries"][domain_name] = domain_config
        save_config(current_config)
        return jsonify({"message": "IPv6 SSL and protocol are all same as requested values"})

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
    
    # If protocol is updated
    if protocol_updated:
        domain_config['protocol'] = get_protocol(ssl_certificate_crt=ssl_certificate_crt, ssl_private_key=ssl_private_key)

    # Generate final NGINX config
    nginx_config = get_domain_nginx_config(domain_name=domain_config['domain_name'],
                                            protocol=domain_config['protocol'],
                                            ipv6_address=domain_config['ipv6_address'],
                                            ssl_private_key_path=domain_config['ssl_private_key_path'],
                                            ssl_certificate_crt_path=domain_config['ssl_certificate_crt_path'],
                                            nginx_config=domain_config["nginx_config"])
    
    # Change the nginx config file
    echo_process = subprocess.Popen(["echo", nginx_config], stdout=subprocess.PIPE)
    subprocess.run(["sudo", "tee", domain_config['config_file_path']], stdin=echo_process.stdout, check=True)
    print(f"Created {domain_config['config_file_path']} with IPv6: {new_ipv6}")

    # Reload Nginx with sudo
    subprocess.run(["sudo", "systemctl", "reload", "nginx"], check=True)
    print("Nginx reloaded successfully")

    # Dumping the updated configuration
    current_config["ddns_entries"][domain_name] = domain_config
    save_config(current_config)

    return_message = ""
    if ipv6_updated:
        return_message += " IPv6 "
    if ssl_updated:
        return_message += " SSL "
    if protocol_updated:
        return_message += " protocol "

    if len(return_message) == 0:
        return_message = "All values are same as requested"
    else:
        return_message += "updated"
    return jsonify({"message": return_message})


@app.post("/get_client_tool_code")
def get_client_tool_code():
    domain_name = request.json.get("domain_name")
    access_code = request.json.get("access_code")

    # 1) Check if domain name exists in current sites
    domain_config = get_domain_config(domain_name)
    if domain_config is None:
        return jsonify({"error": "Domain is not registered for DDNS"}), 403
    
    # 2) Authentication with domain name and access code
    if not is_authentic_request(domain_config=domain_config, access_code=access_code):
        return jsonify({"error": "Unauthorized (incorrect access code)"}), 403
    
    # Create a file-like object from the client_tool_code string
    client_tool_code = get_client_tool_bash_script(domain_name=domain_name)
    file_like_object = io.BytesIO(client_tool_code.encode("utf-8"))

    # Send the content as a file download
    return send_file(
        file_like_object,
        as_attachment=True,
        download_name=f"{domain_name}.sh",
        mimetype="application/x-sh"
    )


### End points for User Interface
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

    last_updated_times = {}
    for domain, domain_config in config["ddns_entries"].items():
        last_updated_times[domain] = round((time.time() - float(domain_config["last_pinged_at"])) / 60)

    return render_template("index.html", 
                           entries=list(config["ddns_entries"].values()), 
                           username=session["username"], 
                           nginx_template=load_default_nginx_template(),
                           entry_keys=config["required_keys"],
                           last_updated=last_updated_times,
                           client_tool_url=GET_CLIENT_TOOL_URL)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))
    

### End points for creation, deletion and updation of Reverse proxies from UI
@app.post("/update_entity")
def update_entity():
    if "username" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    domain_name = request.form["domain_name"]
    protocol = request.form["protocol"]
    ipv6_address = request.form.get("ipv6_address", None)
    access_code = request.form["access_code"]
    nginx_config = request.form["nginx_config"]
    
    config = load_config()
    if domain_name not in config["ddns_entries"]:
        return jsonify({"error": "Entity not found"}), 404
    
    new_domain_config = {
        "domain_name": domain_name,
        "protocol": protocol,
        "ipv6_address": ipv6_address,
        "access_code": access_code,
        "nginx_config": nginx_config,
    }

    # Updating the nginx config for the site
    is_success = create_single_reverse_proxy(domain_name, 
                                             config["ddns_entries"][domain_name]["config_file_path"], 
                                             protocol, 
                                             ipv6_address, 
                                             config["ddns_entries"][domain_name]['ssl_private_key_path'],
                                             config["ddns_entries"][domain_name]['ssl_certificate_crt_path'],
                                             nginx_config=nginx_config)
    if not is_success:
        return jsonify({"message": "Entity updation failed"})
    else:
        config["ddns_entries"][domain_name].update(new_domain_config)
        config["ddns_entries"][domain_name]["last_pinged_at"] = time.time()
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
    
    config = load_config()
    new_domain_config = {
        "domain_name": domain_name,
        "config_file_path": config_file_path,
        "protocol": protocol,
        "ipv6_address": ipv6_address,
        "access_code": access_code,
        "previous_ipv6": "0000:0000:0000:0000:0000:0000:0000:0000",
        "ipv6_updated_on": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
        "ssl_updated_on": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
        "last_pinged_at": 10000,
        "nginx_config": nginx_config,
        "ssl_private_key_path": f"/etc/nginx/ssl/{domain_name}/private.key",
        "ssl_certificate_crt_path": f"/etc/nginx/ssl/{domain_name}/certificate.crt"
    }

    # Updating the nginx config for the site
    is_success = create_single_reverse_proxy(domain_name, 
                                            config_file_path, 
                                            protocol, 
                                            ipv6_address,
                                            ssl_private_key_path=new_domain_config["ssl_private_key_path"], 
                                            ssl_certificate_crt_path=new_domain_config["ssl_certificate_crt_path"],
                                            nginx_config=new_domain_config["nginx_config"])
    if not is_success:
        return jsonify({"message": "Entity addition failed"})
    else:
        config["ddns_entries"][domain_name] = new_domain_config
        save_config(config)    
        return jsonify({"message": "Entity added successfully"})


@app.post("/delete_entity")
def delete_entity():
    if "username" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    domain_name = request.form["domain_name"]
    
    config = load_config()
    if domain_name not in config["ddns_entries"]:
        return jsonify({"error": "Entity not found"}), 404
    
    is_success = delete_single_reverse_proxy(config["ddns_entries"][domain_name]["config_file_path"])
    if not is_success:
        return jsonify({"message": "Entity deletion failed"})
    else:
        del config["ddns_entries"][domain_name]
        save_config(config)
        return jsonify({"message": "Entity deleted successfully"})


### End points for NGINX default template modifications
@app.post("/update_custom_nginx_template")
def update_nginx_template():
    global NGINX_CONFIG_TEMPLATE
    if "username" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    nginx_template = request.form["nginx_template"]
    domain_name = request.form["domain_name"]
    is_updated = save_custom_nginx_config(domain_name=domain_name, nginx_config=nginx_template)
    if is_updated:
        return jsonify({"message": "Nginx template updated successfully"})
    else:
        return jsonify({"message": "Error occurred in template updation"})


@app.post("/get_default_nginx_template")
def reset_nginx_template():
    if "username" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    domain_name = request.form["domain_name"]
    domain_config = get_domain_config(domain=domain_name)

    nginx_template = load_default_nginx_template(domain_config["protocol"])
    return jsonify({"nginx_template": nginx_template})


@app.post('/get_custom_nginx_template')
def get_nginx_template():
    if "username" not in session:
        return jsonify({"error": "Unauthorized"}), 401  # Return 401 if not logged in

    domain_name = request.form["domain_name"]
    domain_config = get_domain_config(domain=domain_name)
    if domain_config["nginx_config"] == 'default':
        nginx_template = load_default_nginx_template(domain_config["protocol"])
    else:
        nginx_template = get_custom_nginx_config(domain_name=domain_name)

    return jsonify({"nginx_template": nginx_template})
