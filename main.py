from flask import Flask, request, jsonify
import subprocess
import re
import os
import yaml


# Load configuration from YAML file
CONFIG_FILE = "./config.yaml"
with open(CONFIG_FILE, 'r') as file:
    config = yaml.safe_load(file)


NGINS_CONFIG_TEMPLATE = """
server {
    listen 80;
    listen [::]:80;

    server_name $#@domain_name;

    location / {
        proxy_pass $#@protocol://[$#@ipv6_address];  # Replace with actual IPv6 address
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
"""


app = Flask(__name__)


def get_domain_config(domain):
    for entry in config.get("ddns_entries"):
        if domain == entry['domain_name']:
            return entry
    return None


@app.route("/update_ipv6", methods=["POST"])
def update_ipv6():
    domain = request.form.get("domain_name")
    access_code = request.form.get("access_code")
    new_ipv6 = request.form.get("ipv6")

    domain_config = get_domain_config(domain)

    if domain_config is None:
        return jsonify({"error": "Domain is not registered for ddns"}), 403

    if domain_config['access_code'] != access_code:
        return jsonify({"error": "Unauthorized (incorrect access code)"}), 403

    if not re.match(r'^[a-fA-F0-9:]+$', new_ipv6):
        return jsonify({"error": "Invalid IPv6 address format"}), 400
    
    try:
        nginx_config = get_domain_nginx_config(domain_name=domain,
                                                protocol=domain_config['protocol'],
                                                ipv6_address=new_ipv6)
        
        echo_process = subprocess.Popen(["echo", nginx_config], stdout=subprocess.PIPE)
        subprocess.run(["sudo", "tee", domain_config['config_file_path']], stdin=echo_process.stdout, check=True)
        print(f"Created {domain_config['config_file_path']} with IPv6: {new_ipv6}")

        # Restart Nginx with sudo
        subprocess.run(["sudo", "systemctl", "restart", "nginx"], check=True)
        print("Nginx restarted successfully")

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

        nginx_config = get_domain_nginx_config(domain_name=domain_name,
                                               protocol=protocol,
                                               ipv6_address=ipv6)
        
        echo_process = subprocess.Popen(["echo", nginx_config], stdout=subprocess.PIPE)
        subprocess.run(["sudo", "tee", config_file_path], stdin=echo_process.stdout, check=True)
        print(f"Created {config_file_path} with IPv6: {ipv6}")

    # Restart Nginx with sudo
    subprocess.run(["sudo", "systemctl", "restart", "nginx"], check=True)
    print("Nginx restarted successfully")


if __name__ == "__main__":
    # Start the necessary nginx services first
    create_reverse_proxies()

    # Start the IPv6 updation service 
    app.run()