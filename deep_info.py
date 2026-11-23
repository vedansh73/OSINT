import os
import re
import ssl
import json
import socket
import hashlib
import argparse
from datetime import datetime, timezone as dt_timezone
from urllib.parse import quote

import phonenumbers
from phonenumbers import geocoder, carrier, timezone, number_type, PhoneNumberType
import requests

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)


def _save_report(category: str, target: str, data: dict) -> str:
    os.makedirs("reports", exist_ok=True)
    safe = re.sub(r"[^a-zA-Z0-9_.-]", "_", target)[:45] or "target"
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join("reports", f"deep_{category}_{safe}_{ts}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(
            {
                "timestamp_utc": datetime.now(dt_timezone.utc).isoformat(),
                "tool": "ELVORIX-OSINT Deep Info Extractor",
                "category": category,
                "target": target,
                "data": data,
            },
            f,
            indent=2,
            ensure_ascii=False,
        )
    return path


def deep_phone(phone_raw: str) -> dict:
    parsed = phonenumbers.parse(phone_raw.strip(), None)
    e164 = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
    intl = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
    natl = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL)
    rfc = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.RFC3966)
    digits = re.sub(r"\D", "", e164)
    type_map = {
        PhoneNumberType.MOBILE: "Mobile",
        PhoneNumberType.FIXED_LINE: "Fixed Line",
        PhoneNumberType.FIXED_LINE_OR_MOBILE: "Fixed Line or Mobile",
        PhoneNumberType.TOLL_FREE: "Toll Free",
        PhoneNumberType.VOIP: "VoIP",
    }
    return {
        "e164": e164,
        "international": intl,
        "national": natl,
        "rfc3966": rfc,
        "country_code": f"+{parsed.country_code}",
        "valid": phonenumbers.is_valid_number(parsed),
        "possible": phonenumbers.is_possible_number(parsed),
        "line_type": type_map.get(number_type(parsed), "Unknown"),
        "region": geocoder.description_for_number(parsed, "en") or "Unknown",
        "carrier": carrier.name_for_number(parsed, "en") or "Unknown / Ported",
        "timezones": list(timezone.time_zones_for_number(parsed)),
        "links_and_dorks": {
            "whatsapp": f"https://wa.me/{digits}",
            "telegram_search": f"https://www.google.com/search?q={quote(f'\"{e164}\" site:t.me OR telegram')}",
            "truecaller_dork": f"https://www.google.com/search?q={quote(f'\"{e164}\" site:truecaller.com')}",
            "general_web_dork": f"https://www.google.com/search?q={quote(f'\"{e164}\" OR \"{intl}\" OR \"{digits}\"')}",
        },
    }


def deep_domain(domain_raw: str) -> dict:
    domain = domain_raw.strip().replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
    info = {"domain": domain, "ipv4": [], "ipv6": [], "dns": {}, "ssl": {}, "http": {}, "crtsh_subdomains": []}
    try:
        info["ipv4"] = sorted({x[4][0] for x in socket.getaddrinfo(domain, None, socket.AF_INET)})
    except Exception:
        pass
    try:
        info["ipv6"] = sorted({x[4][0] for x in socket.getaddrinfo(domain, None, socket.AF_INET6)})
    except Exception:
        pass
    for rtype in ("A", "AAAA", "MX", "NS", "TXT", "CAA"):
        try:
            r = requests.get(f"https://dns.google/resolve?name={quote(domain)}&type={rtype}", headers={"User-Agent": USER_AGENT}, timeout=6)
            if r.status_code == 200:
                ans = [a.get("data") for a in r.json().get("Answer", []) if a.get("data")]
                if ans:
                    info["dns"][rtype] = ans
        except Exception:
            pass
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                info["ssl"] = {
                    "subject": dict(x[0] for x in cert.get("subject", [])),
                    "issuer": dict(x[0] for x in cert.get("issuer", [])),
                    "notBefore": cert.get("notBefore"),
                    "notAfter": cert.get("notAfter"),
                    "sans": [v for k, v in cert.get("subjectAltName", []) if k == "DNS"][:30],
                }
    except Exception as e:
        info["ssl"] = {"error": str(e)}
    try:
        resp = requests.get(f"https://{domain}", headers={"User-Agent": USER_AGENT}, timeout=8)
        info["http"] = {
            "status_code": resp.status_code,
            "final_url": resp.url,
            "server": resp.headers.get("Server"),
            "x_powered_by": resp.headers.get("X-Powered-By"),
            "security_headers": {
                h: resp.headers.get(h, "MISSING")
                for h in ("Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options")
            },
        }
    except Exception as e:
        info["http"] = {"error": str(e)}
    try:
        r_crt = requests.get(f"https://crt.sh/?q=%25.{quote(domain)}&output=json", headers={"User-Agent": USER_AGENT}, timeout=10)
        if r_crt.status_code == 200:
            subs = {
                s.strip().lstrip("*.")
                for row in r_crt.json()
                for s in str(row.get("name_value", "")).splitlines()
                if s.strip().lstrip("*.").endswith(domain)
            }
            info["crtsh_subdomains"] = sorted(subs)[:50]
    except Exception:
        pass
    return info


def deep_ip(ip_query: str = "") -> dict:
    q = ip_query.strip()
    url = f"http://ip-api.com/json/{quote(q)}?fields=status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,query,proxy,hosting"
    r = requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=7)
    data = r.json()
    shodan = {}
    target_ip = data.get("query") or q
    if target_ip:
        try:
            sr = requests.get(f"https://internetdb.shodan.io/{quote(target_ip)}", timeout=6)
            if sr.status_code == 200:
                shodan = sr.json()
        except Exception:
            pass
    return {"geo_isp": data, "shodan_internetdb": shodan}


def deep_github(username: str) -> dict:
    u = username.strip().lstrip("@")
    user_r = requests.get(f"https://api.github.com/users/{quote(u)}", headers={"User-Agent": USER_AGENT}, timeout=8).json()
    repos_r = requests.get(f"https://api.github.com/users/{quote(u)}/repos?per_page=15&sort=updated", headers={"User-Agent": USER_AGENT}, timeout=8).json()
    repos = [
        {"name": x.get("name"), "html_url": x.get("html_url"), "language": x.get("language"), "stars": x.get("stargazers_count")}
        for x in repos_r if isinstance(x, dict)
    ] if isinstance(repos_r, list) else []
    return {"profile": user_r, "recent_repos": repos}


def deep_file(filepath: str) -> dict:
    if not os.path.isfile(filepath):
        return {"error": f"File not found: {filepath}"}
    with open(filepath, "rb") as f:
        data = f.read()
    strings = [s.decode("ascii", errors="ignore") for s in re.findall(rb"[\x20-\x7e]{6,}", data)]
    urls = sorted({m.group(0) for s in strings for m in re.finditer(r"https?://[^\s\"'<>]+", s)})
    emails = sorted({m.group(0) for s in strings for m in re.finditer(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", s)})
    return {
        "path": os.path.abspath(filepath),
        "size_bytes": len(data),
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
        "header_hex": data[:24].hex(" "),
        "urls_found": urls[:30],
        "emails_found": emails[:30],
        "strings_sample": strings[:30],
    }


def main():
    parser = argparse.ArgumentParser(description="ELVORIX-OSINT Deep Info Extractor")
    sub = parser.add_subparsers(dest="mode", required=True)
    p_ph = sub.add_parser("phone"); p_ph.add_argument("target")
    p_do = sub.add_parser("domain"); p_do.add_argument("target")
    p_ip = sub.add_parser("ip"); p_ip.add_argument("target", nargs="?", default="")
    p_gh = sub.add_parser("github"); p_gh.add_argument("target")
    p_fl = sub.add_parser("file"); p_fl.add_argument("target")
    args = parser.parse_args()

    dispatch = {
        "phone": (deep_phone, args.target),
        "domain": (deep_domain, args.target),
        "ip": (deep_ip, args.target),
        "github": (deep_github, args.target),
        "file": (deep_file, args.target),
    }
    fn, val = dispatch[args.mode]
    out = fn(val)
    print(json.dumps(out, indent=2, ensure_ascii=False))
    saved = _save_report(args.mode, val or "self", out)
    print(f"\n[+] Saved report: {saved}")


if __name__ == "__main__":
    main()
