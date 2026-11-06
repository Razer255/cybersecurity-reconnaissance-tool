
from flask import Flask, request, jsonify
from flask_cors import CORS
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse
import socket
import requests
import ipaddress
import re
import os

# Optional WHOIS support
try:
    import whois
except ImportError:
    whois = None


app = Flask(__name__)

# Configuration
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024

# For local development. Restrict origins when deploying.
CORS(app, resources={r"/recon": {"origins": ["http://127.0.0.1:5500",
                                             "http://localhost:5500"]}})

COMMON_PORTS = [21, 22, 25, 53, 80, 110, 143, 443, 3306, 8080, 8443]

REQUEST_TIMEOUT = 5
PORT_TIMEOUT = 1
MAX_WORKERS = 10


# ----------------------------------
# DOMAIN NORMALIZATION
# ----------------------------------

def normalize_domain(user_input):
    if not isinstance(user_input, str):
        return None

    user_input = user_input.strip()

    if not user_input or len(user_input) > 253:
        return None

    if not user_input.startswith(("http://", "https://")):
        user_input = "https://" + user_input

    try:
        parsed = urlparse(user_input)

        if parsed.scheme not in ("http", "https"):
            return None

        if parsed.username or parsed.password:
            return None

        domain = parsed.hostname

        if not domain:
            return None

        domain = domain.rstrip(".").lower()

        # Validate IP addresses or domain names
        try:
            ipaddress.ip_address(domain)
            return domain
        except ValueError:
            pass

        # Basic hostname validation
        if len(domain) > 253:
            return None

        labels = domain.split(".")

        for label in labels:
            if (
                not label
                or len(label) > 63
                or not re.fullmatch(
                    r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?",
                    label
                )
            ):
                return None

        return domain

    except Exception:
        return None


# ----------------------------------
# DNS RECONNAISSANCE
# ----------------------------------

def get_dns_info(domain):
    try:
        results = socket.getaddrinfo(
            domain,
            None,
            socket.AF_UNSPEC,
            socket.SOCK_STREAM
        )

        ipv4 = set()
        ipv6 = set()

        for result in results:
            address = result[4][0]

            if ":" in address:
                ipv6.add(address)
            else:
                ipv4.add(address)

        return {
            "ipv4": sorted(ipv4),
            "ipv6": sorted(ipv6)
        }

    except socket.gaierror:
        return {
            "ipv4": [],
            "ipv6": [],
            "error": "DNS resolution failed"
        }


# ----------------------------------
# TARGET SAFETY CHECK
# ----------------------------------

def validate_public_target(domain, dns_info):
    addresses = dns_info.get("ipv4", []) + dns_info.get("ipv6", [])

    if not addresses:
        return False

    try:
        for address in addresses:
            ip = ipaddress.ip_address(address)

            # Reject localhost, private, reserved,
            # link-local and other non-global addresses.
            if not ip.is_global:
                return False

        return True

    except ValueError:
        return False


# ----------------------------------
# PORT SCANNING
# ----------------------------------

def check_port(ip, port):
    try:
        with socket.create_connection(
            (ip, port),
            timeout=PORT_TIMEOUT
        ):
            return port

    except (socket.timeout, ConnectionRefusedError, OSError):
        return None


def scan_ports(ip):
    open_ports = []

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        results = executor.map(
            lambda port: check_port(ip, port),
            COMMON_PORTS
        )

    open_ports = [
        port for port in results if port is not None
    ]

    return open_ports


# ----------------------------------
# HTTP RECONNAISSANCE
# ----------------------------------

def get_http_info(domain):
    security_headers = [
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Content-Type-Options",
        "X-Frame-Options",
        "Referrer-Policy",
        "Permissions-Policy"
    ]

    try:
        response = requests.get(
            f"https://{domain}",
            timeout=REQUEST_TIMEOUT,
            allow_redirects=False,
            headers={"User-Agent": "CyberRecon/1.0"}
        )

    except requests.RequestException:
        try:
            response = requests.get(
                f"http://{domain}",
                timeout=REQUEST_TIMEOUT,
                allow_redirects=False,
                headers={"User-Agent": "CyberRecon/1.0"}
            )

        except requests.RequestException:
            return {
                "status_code": None,
                "server": "Unavailable",
                "headers": {},
                "security_headers": {},
                "missing_security_headers": security_headers,
                "info": "HTTP connection failed"
            }

    headers = dict(response.headers)

    security_status = {
        header: headers.get(header, "Missing")
        for header in security_headers
    }

    missing_headers = [
        header for header, value in security_status.items()
        if value == "Missing"
    ]

    return {
        "status_code": response.status_code,
        "server": headers.get("Server", "Not disclosed"),
        "headers": headers,
        "security_headers": security_status,
        "missing_security_headers": missing_headers
    }


# ----------------------------------
# GEOLOCATION
# ----------------------------------

def get_geo_info(ip):
    try:
        response = requests.get(
            f"https://ipinfo.io/{ip}/json",
            timeout=REQUEST_TIMEOUT
        )

        response.raise_for_status()
        data = response.json()

        return {
            "ip": data.get("ip"),
            "city": data.get("city"),
            "region": data.get("region"),
            "country": data.get("country"),
            "org": data.get("org"),
            "timezone": data.get("timezone"),
            "loc": data.get("loc")
        }

    except requests.RequestException:
        return {"info": "Geolocation lookup failed"}


# ----------------------------------
# WHOIS LOOKUP
# ----------------------------------

def get_whois_info(domain):
    if not whois:
        return "WHOIS library not installed"

    try:
        result = whois.whois(domain)

        if not result:
            return "WHOIS information unavailable"

        return {
            "domain_name": str(result.domain_name or ""),
            "registrar": str(result.registrar or ""),
            "creation_date": str(result.creation_date or ""),
            "expiration_date": str(result.expiration_date or ""),
            "name_servers": result.name_servers or []
        }

    except Exception:
        return "WHOIS lookup failed"


# ----------------------------------
# MAIN RECON ENDPOINT
# ----------------------------------

@app.route("/recon", methods=["POST"])
def recon():

    data = request.get_json(silent=True) or {}
    raw_input = data.get("domain", "")

    domain = normalize_domain(raw_input)

    if not domain:
        return jsonify({
            "error": "Invalid domain or URL"
        }), 400

    try:
        # DNS lookup
        dns_info = get_dns_info(domain)

        # Public target validation
        if not validate_public_target(domain, dns_info):
            return jsonify({
                "error": "Target must resolve exclusively to public IP addresses."
            }), 400

        # Primary IPv4 address for legacy frontend compatibility
        ip = (
            dns_info["ipv4"][0]
            if dns_info["ipv4"]
            else dns_info["ipv6"][0]
        )

        # Reconnaissance modules
        open_ports = scan_ports(ip)
        http_info = get_http_info(domain)
        geo_info = get_geo_info(ip)
        whois_info = get_whois_info(domain)

        return jsonify({

            # Original response fields
            "target": domain,
            "ip": ip,
            "open_ports": open_ports,
            "headers": http_info["headers"],
            "geo": geo_info,
            "whois": whois_info,

            # Additional reconnaissance fields
            "dns": dns_info,
            "http": http_info,
            "scan_info": {
                "ports_tested": COMMON_PORTS,
                "open_ports_count": len(open_ports),
                "status": "Completed"
            }

        }), 200

    except Exception as e:
        app.logger.exception("Reconnaissance failed")

        return jsonify({
            "error": "An internal reconnaissance error occurred."
        }), 500


# ----------------------------------
# HEALTH CHECK
# ----------------------------------

@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "online",
        "service": "Cyber Recon Backend",
        "version": "2.0"
    })


# ----------------------------------
# APPLICATION ENTRY POINT
# ----------------------------------

if __name__ == "__main__":
    print("=" * 45)
    print("     CYBER RECON BACKEND v2.0")
    print("     Server: http://127.0.0.1:5000")
    print("=" * 45)

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )
