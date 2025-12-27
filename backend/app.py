import os
import socket
from datetime import datetime
import tempfile
import subprocess


from flask import Flask, request, jsonify
import dns.resolver
import phonenumbers
import requests
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS
from twilio.rest import Client  # Twilio SDK [web:621][web:633]
from sip_core import analyze_sip_log


app = Flask(__name__)

# Enable CORS so React (Vite) at localhost:5173 can call the API. [web:610]
CORS(app, origins=["http://localhost:5173"])

# Rate limiter: per-client IP limits, in-memory. [web:607]
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["60 per minute"],
    storage_uri="memory://",
)

# ================== CONFIG / KEYS ==================

TWILIO_ACCOUNT_SID = os.environ.get("TWILIO_ACCOUNT_SID", "")
TWILIO_AUTH_TOKEN = os.environ.get("TWILIO_AUTH_TOKEN", "")
IPQS_PHONE_KEY = os.environ.get("IPQS_PHONE_KEY", "")     # IPQS phone reputation [web:624][web:636]

IPINFO_TOKEN = os.environ.get("IPINFO_TOKEN", "YOUR_IPINFO_TOKEN")  # optional
WHOISXML_API_KEY = os.environ.get("WHOISXML_API_KEY", "YOUR_WHOISXML_KEY")

_twilio_client = None
def get_twilio_client():
    global _twilio_client
    if _twilio_client is None:
        if not TWILIO_ACCOUNT_SID or not TWILIO_AUTH_TOKEN:
            raise RuntimeError("TWILIO_ACCOUNT_SID / TWILIO_AUTH_TOKEN not configured")
        _twilio_client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
    return _twilio_client

# ================== COMMON HELPERS ==================

def parse_creation_date(raw_date):
    if isinstance(raw_date, list):
        raw_date = raw_date[0]
    if isinstance(raw_date, datetime):
        return raw_date
    try:
        return datetime.strptime(str(raw_date)[:10], "%Y-%m-%d")
    except Exception:
        return None

import os
import subprocess
import tempfile

# Adjust this if your Wireshark is in Program Files (x86)
TSHARK_PATH = r"C:\Program Files\Wireshark\tshark.exe"

def sip_text_from_pcap_bytes(pcap_bytes: bytes) -> str:
    """
    Use tshark to extract only SIP packets from a pcap and return as text.
    Requires Wireshark/tshark to be installed on the system.
    """
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
            tmp.write(pcap_bytes)
            tmp_path = tmp.name

        cmd = [
            TSHARK_PATH,           # use full path on Windows
            "-r",
            tmp_path,
            "-Y",
            "sip",
            "-V",
            "-O",
            "sip",
        ]
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
        return out.decode("utf-8", errors="ignore")
    except subprocess.CalledProcessError as e:
        print("Error running tshark:")
        print(e.output.decode("utf-8", errors="ignore"))
        return ""
    except FileNotFoundError:
        # tshark.exe not found at the given path
        print(f"tshark not found at {TSHARK_PATH}")
        return ""
    except Exception as e:
        print("tshark error:", e)
        return ""
    finally:
        if tmp_path:
            try:
                os.remove(tmp_path)
            except Exception:
                pass



def get_age_days(dt):
    if not dt:
        return None
    return (datetime.utcnow() - dt).days

# ================== DOMAIN MODULE ==================

def classify_platform(domain):
    domain = domain.lower()
    mapping = {
        "voip": "VoIP / telephony",
        "sip": "SIP / PBX",
        "pbx": "PBX / VoIP",
        "call": "Calling service",
        "msg": "Messaging",
        "chat": "Messaging",
    }
    for k, v in mapping.items():
        if k in domain:
            return v
    return "Generic / unknown"


def score_domain(age_days, platform):
    platform = platform.lower()
    if age_days is None:
        return "medium"
    if age_days < 30:
        return "high"
    if ("voip" in platform or "sip" in platform or "pbx" in platform) and age_days < 90:
        return "high"
    if age_days <= 90:
        return "medium"
    return "low"


def http_whois_lookup(domain: str) -> dict:
    if not WHOISXML_API_KEY or WHOISXML_API_KEY == "YOUR_WHOISXML_KEY":
        return {"status": "error", "message": "WHOISXML API key not configured"}

    try:
        url = "https://www.whoisxmlapi.com/whoisserver/WhoisService"
        params = {
            "domainName": domain,
            "apiKey": WHOISXML_API_KEY,
            "outputFormat": "JSON",
        }
        resp = requests.get(url, params=params,timeout=(3, 15))
        resp.raise_for_status()
        data = resp.json()
        record = data.get("WhoisRecord")
        if not record:
            return {"status": "error", "message": "No WhoisRecord in response"}
        record["status"] = "ok"
        return record
    except Exception as e:
        return {"status": "error", "message": f"HTTP WHOIS failed: {e}"}


def domain_lookup(domain):
    result = {
        "domain": domain,
        "whois": {},
        "dns": {},
        "age_days": None,
        "platform": "",
        "score": "low",
        "summary": "",
        "error": None,
    }

    whois_data = http_whois_lookup(domain)
    if whois_data.get("status") == "error":
        result["error"] = whois_data.get("message", "WHOIS lookup error")
        registrar = "Unknown"
        country = "Unknown"
        creation_raw = None
    else:
        registrar = whois_data.get("registrarName") or "Unknown"
        creation_raw = (
            whois_data.get("createdDate")
            or whois_data.get("createdDateNormalized")
        )
        country = (
            (whois_data.get("registrant") or {}).get("country")
            or whois_data.get("registryData", {}).get("registrant", {}).get("country")
            or "Unknown"
        )

    created_at = parse_creation_date(creation_raw)
    age_days = get_age_days(created_at)
    platform = classify_platform(domain)
    score = score_domain(age_days, platform)

    ips = []
    try:
        answers = dns.resolver.resolve(domain, "A")
        ips = [r.to_text() for r in answers]
    except Exception:
        pass

    result["whois"] = {
        "registrar": registrar,
        "creation_date": str(creation_raw),
        "country": country,
    }
    result["dns"] = {"ips": ips}
    result["age_days"] = age_days
    result["platform"] = platform
    result["score"] = score

    if age_days is None:
        age_str = "with unknown registration age"
    else:
        age_str = f"registered {age_days} days ago"

    result["summary"] = (
        f"Domain {domain} is {age_str}, registered via {registrar}, "
        f"hosted in {country}, categorized as {platform}, "
        f"threat score: {score.upper()}."
    )
    return result

# ================== NUMBER MODULE (Twilio Lookup v2 clone of index.js) ==================


def compute_threat_score(line_type: str | None):
    """
    Compute a simple threat score based only on real line type
    from Twilio Lookup (voip / mobile / landline / etc.).
    """
    score = 0

    if not line_type:
        # Unknown type ⇒ mild risk
        score += 20
    else:
        t = line_type.lower()
        if "voip" in t:
            # VoIP / virtual numbers more risky
            score += 70
        elif "mobile" in t:
            score += 30
        elif "landline" in t:
            score += 10
        else:
            score += 20

    label = "low"
    if score > 60:
        label = "high"
    elif score > 30:
        label = "medium"

    return score, label


def build_summary(normalized: str, line_type: str | None, threat_label: str) -> str:
    type_text = line_type or "unknown type"
    return f"Number {normalized} is detected as a {type_text} line, threat level: {threat_label}."


def analyze_number_logic(phone_number: str):
    """
    Pure logic equivalent of index.js /analyze-number for reuse in route.
    """
    # 1) Parse & normalize (phonenumbers = libphonenumber port)
    try:
        parsed = phonenumbers.parse(phone_number, None)
    except phonenumbers.NumberParseException:
        parsed = None

    if not parsed or not phonenumbers.is_valid_number(parsed):
        return {
            "input": phone_number,
            "valid": False,
            "error": "Invalid phone number format",
        }

    # E.164, e.g. +14155550123
    normalized = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
    country_calling_code = parsed.country_code if parsed.country_code else None

    # 2) Twilio Lookup v2 with line_type_intelligence
    client = get_twilio_client()
    twilio_resp = client.lookups.v2.phone_numbers(normalized).fetch(
        fields="line_type_intelligence"
    )

    # Twilio response
    valid = True  # If resolved, treat as valid
    line_info = getattr(twilio_resp, "line_type_intelligence", {}) or {}
    # Keys from Twilio: "type", "carrier_name", ...
    if isinstance(line_info, dict):
        line_type = line_info.get("type") or None
        carrier = line_info.get("carrier_name") or None
    else:
        # Defensive fallback
        line_type = getattr(line_info, "type", None)
        carrier = getattr(line_info, "carrier_name", None)

    country_iso2 = getattr(twilio_resp, "country_code", None)  # e.g. "US"
    country_name = country_iso2  # Twilio only returns ISO2 here

    # 3) Reassignment + social presence: stubbed exactly like Node
    reassigned_recently = "unknown"
    social_platforms: list[str] = []

    # 4) Threat score based on real line type
    threat_score_numeric, threat_score_label = compute_threat_score(line_type)

    # 5) Summary sentence
    summary = build_summary(normalized, line_type, threat_score_label)

    # 6) Response JSON (Node parity)
    return {
        "input": phone_number,
        "normalized": normalized,
        "valid": valid,
        "country_code": country_calling_code,
        "country_iso2": country_iso2,
        "country_name": country_name,
        "type": line_type,
        "carrier_hint": carrier,
        "reassigned_recently": reassigned_recently,
        "social_platforms": social_platforms,
        "threat_score_numeric": threat_score_numeric,
        "threat_score_label": threat_score_label,
        "summary": summary,
        "raw_provider_response": twilio_resp.to_dict()
        if hasattr(twilio_resp, "to_dict")
        else str(twilio_resp),
    }

# ================== SIP MODULE ==================

import re


def port_scan(ip, ports=(5060, 5061, 80, 443, 8080)):
    """Scan ports on a given IP and return open ports as ints."""
    open_ports = []
    for p in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            res = sock.connect_ex((ip, p))
            sock.close()
            if res == 0:
                open_ports.append(p)
        except Exception:
            continue
    return open_ports


def ip_geo_lookup(ip):
    """
    IPinfo enrichment: return full JSON so frontend can show
    city/country/ASN + privacy flags if needed.
    """
    if not IPINFO_TOKEN or IPINFO_TOKEN == "YOUR_IPINFO_TOKEN":
        return {"ip": ip, "error": "IPINFO token not configured"}

    try:
        url = f"https://ipinfo.io/{ip}/json"
        params = {"token": IPINFO_TOKEN}
        resp = requests.get(url, params=params, timeout=3)
        if resp.status_code != 200:
            return {"ip": ip, "error": f"IPinfo HTTP {resp.status_code}"}
        data = resp.json()
        return data
    except Exception as e:
        return {"ip": ip, "error": f"IPinfo lookup failed: {e}"}


def parse_sip(sip_text):
    """
    Simple SIP parser to extract From/To URIs and all IPv4s.
    """
    from_uri = None
    to_uri = None
    ips = set()

    for line in sip_text.splitlines():
        line = line.strip()
        if line.lower().startswith("from:") and from_uri is None:
            from_uri = line.split(":", 1)[1].strip()
        if line.lower().startswith("to:") and to_uri is None:
            to_uri = line.split(":", 1)[1].strip()

        # crude IPv4 extraction
        for part in line.replace(";", " ").replace(",", " ").split():
            if part.count(".") == 3:
                try:
                    socket.inet_aton(part)
                    ips.add(part)
                except OSError:
                    pass

    # Also try to capture P-Asserted-Identity later in sip_lookup
    return {"from_uri": from_uri, "to_uri": to_uri, "ips": list(ips)}


def detect_spoof(from_uri, pai_uri):
    """
    Spoofing if From and P-Asserted-Identity differ.
    """
    if not from_uri or not pai_uri:
        return False
    return from_uri.strip() != pai_uri.strip()


def score_sip(open_ports, spoofing, ip_geo, sip_text):
    """
    Heuristic SIP threat scoring using:
    - open SIP ports
    - spoofing
    - IPinfo org/asn/privacy
    - weird INVITE targets
    - INVITE / REGISTER volume
    Returns score_label ("low"/"medium"/"high") and reasons list.
    """
    score = 0
    reasons = []

    # Open SIP ports 5060/5061
    if 5060 in open_ports or 5061 in open_ports:
        score += 1
        reasons.append("Open SIP port 5060/5061 detected")

    # Spoofing: From vs PAI mismatch
    if spoofing:
        score += 2
        reasons.append("From vs P-Asserted-Identity mismatch (possible caller ID spoofing)")

    # IPinfo context
    if isinstance(ip_geo, dict):
        org = str(ip_geo.get("org", "")).lower()
        asn_type = (
            ip_geo.get("asn", {}).get("type")
            if isinstance(ip_geo.get("asn"), dict)
            else None
        )
        privacy = ip_geo.get("privacy", {}) if isinstance(ip_geo.get("privacy"), dict) else {}

        if "datacenter" in org or "hosting" in org or "cloud" in org:
            score += 1
            reasons.append("Org looks like hosting/datacenter provider")

        if asn_type == "hosting":
            score += 1
            reasons.append("ASN type is hosting")

        if privacy.get("vpn") or privacy.get("tor"):
            score += 1
            reasons.append("Connection flagged as VPN/Tor/anonymized")

    # Suspicious INVITE target pattern
    if re.search(r"INVITE\s+sip:\s*@127\.0\.0\.1", sip_text):
        score += 2
        reasons.append("Suspicious INVITE target sip:@127.0.0.1 (Metasploit-style pattern)")

    # SIP method volume
    invite_count = len(re.findall(r"\nINVITE\s", sip_text))
    register_count = len(re.findall(r"\nREGISTER\s", sip_text))
    if invite_count > 20:
        score += 1
        reasons.append(f"High INVITE volume in log ({invite_count} requests)")
    if register_count > 20:
        score += 1
        reasons.append(f"High REGISTER volume in log ({register_count} requests)")

    # Label
    if score < 2:
        label = "low"
    elif score < 4:
        label = "medium"
    else:
        label = "high"

    if not reasons:
        reasons.append("No strong indicators; baseline low risk")

    return label, reasons


def sip_lookup(sip_text):
    """
    Flask-facing SIP lookup used by /api/sip.
    Aggregates all IPs, computes highest risk, and returns
    a compact JSON for the React dashboard.
    """
    result = {
        "from_uri": None,
        "to_uri": None,
        "ips": [],
        "open_ports": {},
        "ip_geo": {},
        "spoofing": False,
        "score": "low",
        "summary": "",
        "reasons": [],
        "error": None,
    }

    if not sip_text.strip():
        result["error"] = "Empty SIP log"
        return result

    parsed = parse_sip(sip_text)
    from_uri = parsed["from_uri"]
    to_uri = parsed["to_uri"]
    ips = parsed["ips"]

    if not ips:
        result["from_uri"] = from_uri
        result["to_uri"] = to_uri
        result["summary"] = "No IPs found in SIP log; unable to assess threats."
        return result

    # Extract P-Asserted-Identity
    pai_uri = None
    for line in sip_text.splitlines():
        if line.lower().startswith("p-asserted-identity"):
            pai_uri = line.split(":", 1)[1].strip()
            break

    spoofing = detect_spoof(from_uri, pai_uri)

    open_ports_map = {}
    ip_geo_map = {}
    per_ip_scores = []

    for ip in ips:
        ports = port_scan(ip)
        geo = ip_geo_lookup(ip)
        open_ports_map[ip] = ports
        ip_geo_map[ip] = geo

        # compute per-IP label/reasons
        label, reasons = score_sip(ports, spoofing, geo, sip_text)
        per_ip_scores.append(
            {
                "ip": ip,
                "label": label,
                "reasons": reasons,
                "ports": ports,
                "geo": geo,
            }
        )

    # choose highest risk IP for overall score & summary
    ranking = {"low": 0, "medium": 1, "high": 2}
    best = max(per_ip_scores, key=lambda r: ranking.get(r["label"], 0))

    result.update(
        {
            "from_uri": from_uri,
            "to_uri": to_uri,
            "ips": ips,
            "open_ports": open_ports_map,
            "ip_geo": ip_geo_map,
            "spoofing": spoofing,
            "score": best["label"],  # low / medium / high
            "summary": (
                f"SIP log shows {len(ips)} IP(s), spoofing={spoofing}, "
                f"highest risk IP {best['ip']} scored {best['label'].upper()}: "
                + "; ".join(best["reasons"])
            ),
            "reasons": best["reasons"],
        }
    )
    return result

# ================== API ROUTES FOR REACT DASHBOARD ==================

@app.route("/api/domain", methods=["POST"])
@limiter.limit("30 per minute")
def api_domain():
    try:
        data = request.get_json(force=True) or {}
    except Exception:
        return jsonify({"error": "Invalid JSON body"}), 400

    domain = (data.get("domain") or "").strip()
    if not domain:
        return jsonify({"error": "domain is required"}), 400

    result = domain_lookup(domain)
    status = 200 if not result.get("error") else 502
    return jsonify(result), status

def number_lookup(number_str: str):
    """
    Keep /api/number working by delegating to the same logic as /analyze-number.
    """
    return analyze_number_logic(number_str)

@app.route("/api/number", methods=["POST"])
@limiter.limit("30 per minute")
def api_number():
    try:
        data = request.get_json(force=True) or {}
    except Exception:
        return jsonify({"error": "Invalid JSON body"}), 400

    number = (data.get("number") or "").strip()
    if not number:
        return jsonify({"error": "number is required"}), 400

    result = number_lookup(number)
    status = 200 if not result.get("error") else 502
    return jsonify(result), status


@app.route("/api/sip", methods=["POST"])
@limiter.limit("20 per minute")
def api_sip():
    # Case 1: multipart/form-data with uploaded file
    if "file" in request.files:
        f = request.files["file"]
        filename = f.filename or ""
        data = f.read()

        if not data:
            return jsonify({"error": "Uploaded file is empty"}), 400

        # If pcap / pcapng, extract SIP text via tshark
        if filename.lower().endswith((".pcap", ".pcapng")):
            sip_text = sip_text_from_pcap_bytes(data)
            if not sip_text.strip():
                return jsonify({"error": "Could not extract SIP from pcap"}), 400
        else:
            # Treat as plain text log
            sip_text = data.decode("utf-8", errors="ignore")

    else:
        # Case 2: JSON body with sip_text (existing behaviour)
        try:
            data = request.get_json(force=True) or {}
        except Exception:
            return jsonify({"error": "Invalid JSON body"}), 400

        sip_text = (data.get("sip_text") or "")

    if not sip_text.strip():
        return jsonify({"error": "sip_text is required"}), 400

    result = sip_lookup(sip_text)
    status = 200 if not result.get("error") else 502
    return jsonify(result), status


# Custom rate-limit error
@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({
        "error": "rate_limit_exceeded",
        "message": "Too many requests, please slow down.",
    }), 429

if __name__ == "__main__":
    app.run(debug=True)

@app.route("/analyze-number", methods=["POST"])
@limiter.limit("30 per minute")
def analyze_number():
    try:
        data = request.get_json(force=True) or {}
    except Exception:
        return jsonify({"error": "Invalid JSON body"}), 400

    phone_number = (data.get("phoneNumber") or "").strip()
    if not phone_number:
        return jsonify({"error": "phoneNumber is required"}), 400

    try:
        result = analyze_number_logic(phone_number)
        # If invalid, keep 200 like Node does
        if result.get("valid") is False:
            return jsonify(result)
        return jsonify(result)
    except Exception as err:
        print("ERROR calling Twilio Lookup:")
        print("Message:", str(err))
        return jsonify({"error": "Internal error", "details": str(err)}), 500
