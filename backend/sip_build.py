import os
import socket
from datetime import datetime

from flask import Flask, request, jsonify
# import whois   # no longer needed
import dns.resolver
import phonenumbers
import requests
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS

app = Flask(__name__)

# Enable CORS so React (Vite) at localhost:5173 can call the API. [web:146][web:115]
CORS(app, origins=["http://localhost:5173"])

# Rate limiter: per-client IP limits, in-memory. [web:141][web:144]
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["60 per minute"],
    storage_uri="memory://",
)


# ================== CONFIG / KEYS ==================

ABSTRACTAPI_KEY = os.environ.get("ABSTRACTAPI_KEY", "YOUR_ABSTRACTAPI_KEY")
IPINFO_TOKEN = os.environ.get("IPINFO_TOKEN", "YOUR_IPINFO_TOKEN")  # optional
WHOISXML_API_KEY = os.environ.get("WHOISXML_API_KEY", "YOUR_WHOISXML_KEY")


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
    """
    Return categorical risk: 'low' | 'medium' | 'high'
    based on age and platform keywords.
    """
    platform_l = (platform or "").lower()

    if age_days is None:
        return "medium"

    # Very young domains (< 30 days)
    if age_days < 30:
        if any(p in platform_l for p in ("voip", "sip", "pbx")):
            return "high"
        return "high"

    # Moderately young (30–90 days)
    if age_days < 90:
        if any(p in platform_l for p in ("voip", "sip", "pbx")):
            return "high"
        return "medium"

    # 90–365 days
    if age_days < 365:
        if any(p in platform_l for p in ("voip", "sip", "pbx")):
            return "medium"
        return "low"

    # Very old (>= 1 year)
    if any(p in platform_l for p in ("voip", "sip", "pbx")):
        return "low"
    return "low"


def confidence_from_risk(risk: str, age_days: int | None) -> int:
    """
    Map 'low' / 'medium' / 'high' + age into a 0–100 confidence score.
    Older domains → slightly higher confidence; very new or unknown age → lower.
    """
    risk = (risk or "").lower()

    # Base per category
    if risk == "high":
        base = 80
    elif risk == "medium":
        base = 65
    else:  # low or unknown
        base = 75

    # Age-based adjustment
    if age_days is None:
        adjustment = -15
    elif age_days < 30:
        adjustment = -10
    elif age_days < 365:
        adjustment = 0
    else:
        adjustment = +5

    score = max(0, min(100, base + adjustment))
    return score


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
        resp = requests.get(url, params=params, timeout=5)
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
        "confidence": 0,
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
    confidence = confidence_from_risk(score, age_days)

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
    result["confidence"] = confidence

    if age_days is None:
        age_str = "with unknown registration age"
    else:
        age_str = f"registered {age_days} days ago"

    result["summary"] = (
        f"Domain {domain} is {age_str}, registered via {registrar}, "
        f"hosted in {country}, categorized as {platform}, "
        f"threat score: {score.upper()} (confidence {confidence}%)."
    )
    return result
# ================== NUMBER MODULE (AbstractAPI Phone Intelligence) ==================

def score_number(is_voip, valid, risk_level: str | None, api_type: str | None):
    """
    Map Phone Intelligence + heuristics to low / medium / high.
    """
    risk_level = (risk_level or "").lower()
    api_type = (api_type or "").lower()  # "mobile", "landline", "toll_free", "premium_rate", "voip", ...

    # 1) Trust explicit risk level from API first.
    if risk_level == "high":
        return "high"
    if risk_level == "medium":
        return "medium"

    # 2) Treat inherently risky categories as at least medium.
    risky_types = {"voip", "toll_free", "premium_rate", "shared_cost"}
    if api_type in risky_types or is_voip:
        return "medium"

    # 3) If the API cannot confirm validity, be cautious but not extreme.
    if valid is False:
        return "medium"

    # 4) Default: valid, non‑risky type, no risk flags.
    return "low"


def number_lookup(number_str):
    result = {
        "raw": number_str,
        "parsed": {},
        "score": "low",
        "summary": "",
        "error": None,
    }

    # Normalize with phonenumbers, but don't block on it.
    try:
        num_obj = phonenumbers.parse(number_str, None)
        country_code = num_obj.country_code
        national_number = num_obj.national_number
        region = phonenumbers.region_code_for_number(num_obj)
        number_type = phonenumbers.number_type(num_obj)
    except Exception:
        country_code = None
        national_number = None
        region = None
        number_type = None

    type_map = {
        0: "Fixed line",
        1: "Mobile",
        2: "Fixed or mobile",
        3: "Toll free",
        4: "Premium rate",
        5: "Shared cost",
        6: "VOIP",
        7: "Personal",
        8: "Pager",
        9: "UAN",
        10: "Voicemail",
        27: "Unknown",
    }
    type_str = type_map.get(number_type, "Unknown")
    is_voip = (number_type == 6)

    # ========== AbstractAPI Phone Intelligence real-time call ==========
    if not ABSTRACTAPI_KEY or ABSTRACTAPI_KEY == "YOUR_ABSTRACTAPI_KEY":
        result["error"] = "ABSTRACTAPI_KEY is not configured"
        return result

    try:
        url = "https://phoneintelligence.abstractapi.com/v1/"
        params = {"api_key": ABSTRACTAPI_KEY, "phone": number_str}
        resp = requests.get(url, params=params, timeout=5)
        if resp.status_code != 200:
            result["error"] = f"AbstractAPI error: HTTP {resp.status_code}, body={resp.text}"
            return result
        data = resp.json()
    except Exception as e:
        result["error"] = f"AbstractAPI error: {e}"
        return result

    # Map Phone Intelligence JSON – adjust keys if your dashboard shows different ones. [web:408]
    phone_valid = data.get("phone_valid", {})
    phone_type = data.get("phone_type", {})
    carrier_info = data.get("carrier", {})
    location_info = data.get("location", {})
    phone_risk = data.get("phone_risk", {})

    valid = phone_valid.get("is_valid", None)
    api_type = (phone_type.get("type") or "").lower()      # "mobile", "landline", "toll_free", "premium_rate", "voip", ...
    carrier_name = carrier_info.get("name")
    location = location_info.get("city")
    country_name = location_info.get("country")
    country_code_str = location_info.get("country_code")
    risk_level = phone_risk.get("risk_level")              # "low"/"medium"/"high"/None

    # If API says voip, override phonenumbers decision.
    if api_type == "voip":
        is_voip = True
        type_str = "VOIP"

    score = score_number(is_voip, valid, risk_level, api_type)

    result["parsed"] = {
        "country_code": country_code,
        "national_number": national_number,
        "region": region or country_code_str,
        "type": api_type or type_str,
        "is_voip": is_voip,
        "carrier": carrier_name,
        "location": location,
        "country_name": country_name,
        "valid": valid,
        "risk_level": risk_level,
    }
    result["score"] = score
    result["summary"] = (
        f"Number {number_str} is {api_type or type_str} from "
        f"{location or country_name or region}, "
        f"carrier={carrier_name or 'Unknown'}, valid={valid}, "
        f"VOIP={is_voip}, risk={risk_level or 'unknown'}, "
        f"threat score: {score.upper()}."
    )
    return result


# ================== SIP MODULE ==================

def port_scan(ip, ports=(5060, 5061, 80, 443, 8080)):
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
    if not IPINFO_TOKEN or IPINFO_TOKEN == "YOUR_IPINFO_TOKEN":
        return "Unknown"
    try:
        url = f"https://ipinfo.io/{ip}/json"
        params = {"token": IPINFO_TOKEN}
        resp = requests.get(url, params=params, timeout=2)
        if resp.status_code != 200:
            return "Unknown"
        data = resp.json()
        country = data.get("country", "Unknown")
        org = data.get("org", "Unknown")
        city = data.get("city", "")
        if city:
            return f"{country}, {city}, {org}"
        return f"{country}, {org}"
    except Exception:
        return "Unknown"


def parse_sip(sip_text):
    from_uri = None
    to_uri = None
    ips = set()
    for line in sip_text.splitlines():
        line = line.strip()
        if line.lower().startswith("from:") and from_uri is None:
            from_uri = line.split(":", 1)[1].strip()
        if line.lower().startswith("to:") and to_uri is None:
            to_uri = line.split(":", 1)[1].strip()
        for part in line.replace(";", " ").replace(",", " ").split():
            if part.count(".") == 3:
                try:
                    socket.inet_aton(part)
                    ips.add(part)
                except OSError:
                    pass
    return {"from_uri": from_uri, "to_uri": to_uri, "ips": list(ips)}


def detect_spoof(from_uri, pai_uri):
    if not from_uri or not pai_uri:
        return False
    return from_uri.strip() != pai_uri.strip()


def score_sip(open_ports, spoofing, geo_info):
    datacenter = ("AS" in geo_info) or ("Hosting" in geo_info) or ("Cloud" in geo_info)
    if spoofing and 5060 in open_ports and datacenter:
        return "high"
    if spoofing or 5060 in open_ports:
        return "medium"
    return "low"


def sip_lookup(sip_text):
    result = {
        "from_uri": None,
        "to_uri": None,
        "ips": [],
        "open_ports": {},
        "ip_geo": {},
        "spoofing": False,
        "score": "low",
        "summary": "",
        "error": None,
    }
    if not sip_text.strip():
        result["error"] = "Empty SIP log"
        return result

    parsed = parse_sip(sip_text)
    from_uri = parsed["from_uri"]
    to_uri = parsed["to_uri"]
    ips = parsed["ips"]

    pai_uri = None
    for line in sip_text.splitlines():
        if line.lower().startswith("p-asserted-identity"):
            pai_uri = line.split(":", 1)[1].strip()
            break

    spoofing = detect_spoof(from_uri, pai_uri)

    open_ports_map = {}
    ip_geo_map = {}

    for ip in ips:
        open_ports_map[ip] = port_scan(ip)
        ip_geo_map[ip] = ip_geo_lookup(ip)

    all_open_ports = [p for plist in open_ports_map.values() for p in plist]
    first_geo = next(iter(ip_geo_map.values()), "Unknown")

    score = score_sip(all_open_ports, spoofing, first_geo)

    result.update({
        "from_uri": from_uri,
        "to_uri": to_uri,
        "ips": ips,
        "open_ports": open_ports_map,
        "ip_geo": ip_geo_map,
        "spoofing": spoofing,
        "score": score,
        "summary": (
            f"SIP log shows {len(ips)} IP(s), spoofing={spoofing}, "
            f"open SIP 5060 present={5060 in all_open_ports}, "
            f"overall threat score: {score.upper()}."
        )
    })
    return result


# ================== API ROUTES FOR REACT DASHBOARD ==================

@app.route("/api/domain", methods=["POST"])
@limiter.limit("30 per minute")  # override default for this route [web:142]
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
