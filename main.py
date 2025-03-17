from flask import Flask, request, jsonify
import subprocess
import re
import os
import yaml

# Load configuration from YAML file
CONFIG_FILE = "config.yaml"
with open(CONFIG_FILE, 'r') as file:
    config = yaml.safe_load(file)

ACCESS_CODE = config.get("access_code", "your_secret_code")
NGINX_CONFIG_FILES = config.get("nginx_config_files", ["/etc/nginx/conf.d/test.nginx.site.conf"])
PREVIOUS_IPV6_FILE = "/tmp/previous_ipv6.txt"

app = Flask(__name__)

def get_previous_ipv6():
    if os.path.exists(PREVIOUS_IPV6_FILE):
        with open(PREVIOUS_IPV6_FILE, 'r') as file:
            return file.read().strip()
    return None

def set_previous_ipv6(ipv6):
    with open(PREVIOUS_IPV6_FILE, 'w') as file:
        file.write(ipv6)

def update_nginx_config(new_ipv6):
    previous_ipv6 = get_previous_ipv6()
    if previous_ipv6 == new_ipv6:
        print("IPv6 address is unchanged. Skipping update.")
        return

    for config_file in NGINX_CONFIG_FILES:
        if not os.path.exists(config_file):
            continue

        with open(config_file, 'r') as file:
            content = file.read()

        # Replace IPv6 only inside proxy_pass directive
        new_content = re.sub(r'(proxy_pass\s+https?://)\[([a-fA-F0-9:]+)\]',
                             lambda m: f"{m.group(1)}[{new_ipv6}]", content)

        # Write to file with sudo
        echo_process = subprocess.Popen(["echo", new_content], stdout=subprocess.PIPE)
        subprocess.run(["sudo", "tee", config_file], stdin=echo_process.stdout, check=True)
        print(f"Updated {config_file} with new IPv6: {new_ipv6}")

    # Restart Nginx with sudo
    subprocess.run(["sudo", "systemctl", "restart", "nginx"], check=True)
    print("Nginx restarted successfully")

    # Save the new IPv6 address
    set_previous_ipv6(new_ipv6)

@app.route("/update_ipv6", methods=["POST"])
def update_ipv6():
    access_code = request.form.get("access_code")
    new_ipv6 = request.form.get("ipv6")

    if access_code != ACCESS_CODE:
        return jsonify({"error": "Unauthorized"}), 403

    if not re.match(r'^[a-fA-F0-9:]+$', new_ipv6):
        return jsonify({"error": "Invalid IPv6 address format"}), 400

    try:
        update_nginx_config(new_ipv6)
        return jsonify({"message": "IPv6 address updated successfully"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run()