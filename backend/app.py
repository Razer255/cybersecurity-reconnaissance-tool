from flask import Flask, request, jsonify
from flask_cors import CORS
import socket
import requests
from urllib.parse import urlparse

# Safe WHOIS import
try:
    import whois
except ImportError:
    whois = None

app = Flask(__name__)
CORS(app)  # Enable CORS for frontend

COMMON_PORTS = [21, 22, 80, 443, 3306]


def normalize_domain(user_input: str):
    """
    Accepts:
      - example.com
      - http://example.com
      - https://example.com/path
    Returns:
      - example.com
    """
    user_input = user_input.strip()
    if not user_input:
        return None

    if not user_input.startswith(("http://", "https://")):
        user_input = "http://" + user_input

    parsed = urlparse(user_input)
    return parsed.hostname


@app.route("/recon", methods=["POST"])
def recon():
    raw_input = request.json.get("domain", "")
    domain = normalize_domain(raw_input)

    if not domain:
        return jsonify({"error": "Invalid domain or URL"}), 400

    try:
        # DNS Resolution
        ip = socket.gethostbyname(domain)

        # HTTP Headers
        headers = {}
        try:
            r = requests.get(f"http://{domain}", timeout=5)
            headers = dict(r.headers)
        except Exception:
            headers = {"info": "HTTP headers not accessible"}

        # Port Scan
        open_ports = []
        for port in COMMON_PORTS:
            s = socket.socket()
            s.settimeout(1)
            if s.connect_ex((ip, port)) == 0:
                open_ports.append(port)
            s.close()

        # Geo-IP OSINT
        geo = {}
        try:
            geo = requests.get(
                f"https://ipinfo.io/{ip}/json", timeout=5
            ).json()
        except Exception:
            geo = {"info": "Geo lookup failed"}

        # WHOIS
        whois_data = "WHOIS not available"
        if whois:
            try:
                whois_data = str(whois.whois(domain))
            except Exception:
                pass

        return jsonify({
            "target": domain,
            "ip": ip,
            "open_ports": open_ports,
            "headers": headers,
            "geo": geo,
            "whois": whois_data
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    print(">>> Cyber Recon Backend Started <<<")
    app.run(debug=True)
