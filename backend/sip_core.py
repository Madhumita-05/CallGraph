# sip_core.py
import re
import socket
import requests

# Reuse your existing token if you like
IPINFO_TOKEN = "YOUR_IPINFO_TOKEN"
SCAN_PORTS = [5060, 5061, 80, 443, 8080]


def parse_sip_log(log: str):
    via_ips_received = re.findall(r"Via:.*?;received=(\d+\.\d+\.\d+\.\d+)", log)
    via_ips_udp = re.findall(r"Via:\s*SIP/2\.0/UDP\s+(\d+\.\d+\.\d+\.\d+)", log)
    contact_ips = re.findall(
        r"Contact:.*?sip:.*?@(\d+\.\d+\.\d+\.\d+):?(\d*)", log
    )

    from_addr = re.search(r"From:.*?sip:(\S+@\S+)", log)
    to_addr = re.search(r"To:.*?sip:(\S+@\S+)", log)
    pai_addr = re.search(r"P-Asserted-Identity:.*?sip:(\S+@\S+)", log)

    ips = list(set(via_ips_received + via_ips_udp + [c[0] for c in contact_ips]))
    ports = list(set([c[1] for c in contact_ips if c[1]]))

    return {
        "ips": ips,
        "ports": ports,
        "from": from_addr.group(1) if from_addr else None,
        "to": to_addr.group(1) if to_addr else None,
        "pai": pai_addr.group(1) if pai_addr else None,
    }


def scan_ports(ip, ports=None):
    if ports is None:
        ports = SCAN_PORTS
    open_ports = []
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, int(port)))
            if result == 0:
                open_ports.append(str(port))
            sock.close()
        except Exception:
            pass
    return open_ports


def get_geolocation(ip):
    try:
        url = f"https://ipinfo.io/{ip}/json?token={IPINFO_TOKEN}"
        resp = requests.get(url, timeout=3)
        return resp.json()
    except Exception:
        return {"ip": ip, "error": "Geolocation API failed"}


def detect_spoofing(from_addr, pai_addr):
    if not from_addr or not pai_addr:
        return "N/A"
    return "Yes" if from_addr != pai_addr else "No"


def threat_score_and_reasons(open_ports, spoof_status, ip_data, log):
    score = 0
    reasons = []

    if any(port in open_ports for port in ["5060", "5061", 5060, 5061]):
        score += 1
        reasons.append("Open SIP port 5060/5061 detected")

    if spoof_status == "Yes":
        score += 2
        reasons.append("From vs P-Asserted-Identity mismatch (possible caller ID spoofing)")

    if isinstance(ip_data, dict):
        org = str(ip_data.get("org", "")).lower()
        asn_type = (
            ip_data.get("asn", {}).get("type")
            if isinstance(ip_data.get("asn"), dict)
            else None
        )
        privacy = ip_data.get("privacy", {}) if isinstance(ip_data.get("privacy"), dict) else {}

        if "datacenter" in org or "hosting" in org or "cloud" in org:
            score += 1
            reasons.append("Org looks like hosting/datacenter provider")

        if asn_type == "hosting":
            score += 1
            reasons.append("ASN type is hosting")

        if privacy.get("vpn") or privacy.get("tor"):
            score += 1
            reasons.append("Connection flagged as VPN/Tor/anonymized")

    if re.search(r"INVITE\s+sip:\s*@127\.0\.0\.1", log):
        score += 2
        reasons.append("Suspicious INVITE target sip:@127.0.0.1 (Metasploit-style pattern)")

    invite_count = len(re.findall(r"\nINVITE\s", log))
    register_count = len(re.findall(r"\nREGISTER\s", log))
    if invite_count > 20:
        score += 1
        reasons.append(f"High INVITE volume in log ({invite_count} requests)")
    if register_count > 20:
        score += 1
        reasons.append(f"High REGISTER volume in log ({register_count} requests)")

    score_label = "low" if score < 2 else "medium" if score < 4 else "high"
    if not reasons:
        reasons.append("No strong indicators; baseline low risk")

    return score_label, reasons


def analyze_sip_log(log: str):
    parsed = parse_sip_log(log)
    results = []

    if not parsed["ips"]:
        return results

    for ip in parsed["ips"]:
        open_ports = scan_ports(ip)
        geo = get_geolocation(ip)
        spoof = detect_spoofing(parsed["from"], parsed["pai"])
        score, reasons = threat_score_and_reasons(open_ports, spoof, geo, log)

        results.append(
            {
                "ip": ip,
                "open_ports": [str(p) for p in open_ports],
                "from": parsed["from"],
                "to": parsed["to"],
                "spoof": spoof,
                "geo": geo,
                "score": score,
                "reasons": reasons,
            }
        )

    return results
