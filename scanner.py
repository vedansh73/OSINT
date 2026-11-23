import os
import re
import sys
import ssl
import json
import math
import base64
import codecs
import socket
import hashlib
import ipaddress
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone as dt_timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, quote, unquote

import phonenumbers
from phonenumbers import geocoder, carrier, timezone, number_type, PhoneNumberType
import requests
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

try:
    from PIL import Image, ExifTags
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

console = Console()

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

MAGIC_SIGNATURES = {
    b"\x89PNG\r\n\x1a\n": "PNG Image",
    b"\xff\xd8\xff": "JPEG Image",
    b"GIF87a": "GIF87a Image",
    b"GIF89a": "GIF89a Image",
    b"RIFF": "WEBP / WAV / AVI (RIFF Container)",
    b"%PDF-": "PDF Document",
    b"PK\x03\x04": "ZIP / DOCX / XLSX / JAR / APK Archive",
    b"Rar!\x1a\x07": "RAR Archive",
    b"\x1f\x8b": "GZIP Compressed Archive",
    b"\x7fELF": "Linux ELF Binary",
    b"MZ": "Windows PE Executable (EXE/DLL)",
    b"ID3": "MP3 Audio (ID3v2)",
    b"OggS": "OGG Media",
    b"SQLite format 3\x00": "SQLite 3 Database",
}


def banner():
    console.print(
        Panel(
            "[bold red]ELVORIX-OSINT[/bold red] [bold white]- 500-Module Deep Reconnaissance & Forensics Suite[/bold white]\n"
            "[cyan]Repo: https://github.com/vedansh73/ELVORIX-OSINT.git | Developer: Vedansh Srivastava[/cyan]",
            border_style="yellow",
        )
    )


def save_json_report(target_name: str, module_name: str, payload: dict) -> str:
    os.makedirs("reports", exist_ok=True)
    safe_target = re.sub(r"[^a-zA-Z0-9_.-]", "_", target_name)[:40] or "target"
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filepath = os.path.join("reports", f"{module_name}_{safe_target}_{ts}.json")
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(
            {
                "timestamp": datetime.now().isoformat(),
                "suite": "ELVORIX-OSINT",
                "module": module_name,
                "target": target_name,
                "results": payload,
            },
            f,
            indent=2,
            ensure_ascii=False,
        )
    return filepath


def _clean_domain(raw: str) -> str:
    val = raw.strip()
    if "://" in val:
        return urlparse(val).netloc.strip().split(":")[0]
    return val.split("/")[0].split(":")[0].strip()


def _normalize_url(raw: str, default_scheme: str = "https") -> str:
    val = raw.strip()
    return val if val.startswith(("http://", "https://")) else f"{default_scheme}://{val}"


def get_number_type_label(num):
    t = number_type(num)
    mapping = {
        PhoneNumberType.MOBILE: "Mobile",
        PhoneNumberType.FIXED_LINE: "Fixed Line",
        PhoneNumberType.FIXED_LINE_OR_MOBILE: "Fixed Line or Mobile",
        PhoneNumberType.TOLL_FREE: "Toll Free",
        PhoneNumberType.PREMIUM_RATE: "Premium Rate",
        PhoneNumberType.VOIP: "VoIP",
        PhoneNumberType.PERSONAL_NUMBER: "Personal Number",
        PhoneNumberType.PAGER: "Pager",
        PhoneNumberType.UAN: "UAN",
        PhoneNumberType.VOICEMAIL: "Voicemail",
    }
    return mapping.get(t, "Unknown")


def _doh_query(domain: str, rtype: str) -> list:
    try:
        r = requests.get(
            f"https://dns.google/resolve?name={quote(domain)}&type={quote(rtype)}",
            headers={"User-Agent": USER_AGENT},
            timeout=6,
        )
        if r.status_code == 200:
            data = r.json()
            return [ans.get("data") for ans in data.get("Answer", []) if ans.get("data")]
    except Exception:
        pass
    return []


def fetch_ip_data(ip_query: str = ""):
    target = ip_query.strip()
    sources = [
        f"http://ip-api.com/json/{target}?fields=status,message,country,regionName,city,zip,lat,lon,timezone,isp,org,as,query,hosting,proxy",
        f"https://ipapi.co/{target + '/' if target else ''}json/",
        f"https://ipinfo.io/{target + '/' if target else ''}json",
    ]
    for url in sources:
        try:
            resp = requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=6)
            if resp.status_code != 200:
                continue
            data = resp.json()
            if data.get("status") == "success":
                return {
                    "ip": data.get("query"),
                    "city": data.get("city"),
                    "region": data.get("regionName"),
                    "country": data.get("country"),
                    "postal": data.get("zip"),
                    "lat": data.get("lat"),
                    "lon": data.get("lon"),
                    "timezone": data.get("timezone"),
                    "isp": data.get("isp"),
                    "org": data.get("org"),
                    "asn": data.get("as"),
                    "proxy_hosting": f"Proxy: {data.get('proxy')} | Hosting: {data.get('hosting')}",
                }
            if "ip" in data and not data.get("error"):
                loc_parts = str(data.get("loc", ",")).split(",")
                return {
                    "ip": data.get("ip"),
                    "city": data.get("city"),
                    "region": data.get("region"),
                    "country": data.get("country_name") or data.get("country"),
                    "postal": data.get("postal"),
                    "lat": data.get("latitude") or (loc_parts[0] if len(loc_parts) > 0 else "N/A"),
                    "lon": data.get("longitude") or (loc_parts[1] if len(loc_parts) > 1 else "N/A"),
                    "timezone": data.get("timezone"),
                    "isp": data.get("org"),
                    "org": data.get("org"),
                    "asn": data.get("asn") or data.get("org"),
                    "proxy_hosting": "N/A",
                }
        except Exception:
            continue
    return None


def deep_domain_audit(raw_domain: str) -> dict:
    domain = _clean_domain(raw_domain)
    report = {
        "domain": domain,
        "ipv4": [],
        "ipv6": [],
        "reverse_dns": None,
        "dns_records": {},
        "ssl": {},
        "security_headers": {},
        "rdap": {},
        "crtsh_subdomains": [],
        "wayback_snapshot": None,
    }
    try:
        report["ipv4"] = sorted({x[4][0] for x in socket.getaddrinfo(domain, None, socket.AF_INET)})
    except Exception:
        pass
    try:
        report["ipv6"] = sorted({x[4][0] for x in socket.getaddrinfo(domain, None, socket.AF_INET6)})
    except Exception:
        pass
    if report["ipv4"]:
        try:
            report["reverse_dns"] = socket.gethostbyaddr(report["ipv4"][0])[0]
        except Exception:
            pass

    for rtype in ["MX", "NS", "TXT", "CAA", "SOA"]:
        ans = _doh_query(domain, rtype)
        if ans:
            report["dns_records"][rtype] = ans

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                issuer = dict(x[0] for x in cert.get("issuer", []))
                subject = dict(x[0] for x in cert.get("subject", []))
                sans = [v for k, v in cert.get("subjectAltName", []) if k == "DNS"]
                report["ssl"] = {
                    "common_name": subject.get("commonName"),
                    "issuer": issuer.get("organizationName"),
                    "valid_from": cert.get("notBefore"),
                    "valid_until": cert.get("notAfter"),
                    "san_count": len(sans),
                    "sans_sample": sans[:20],
                }
    except Exception as e:
        report["ssl"] = {"error": str(e)}

    try:
        resp = requests.get(f"https://{domain}", headers={"User-Agent": USER_AGENT}, timeout=8)
        important_headers = [
            "Server",
            "X-Powered-By",
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Referrer-Policy",
            "Permissions-Policy",
        ]
        report["security_headers"] = {
            "status_code": resp.status_code,
            "final_url": resp.url,
            "headers": {h: resp.headers.get(h, "MISSING") for h in important_headers},
        }
    except Exception as e:
        report["security_headers"] = {"error": str(e)}

    try:
        r_rdap = requests.get(f"https://rdap.org/domain/{domain}", headers={"User-Agent": USER_AGENT}, timeout=8)
        if r_rdap.status_code == 200:
            rd = r_rdap.json()
            report["rdap"] = {
                "handle": rd.get("handle"),
                "status": rd.get("status", []),
                "events": {ev.get("eventAction"): ev.get("eventDate") for ev in rd.get("events", [])},
                "nameservers": [ns.get("ldhName") for ns in rd.get("nameservers", []) if ns.get("ldhName")],
            }
    except Exception:
        pass

    try:
        r_crt = requests.get(f"https://crt.sh/?q=%25.{quote(domain)}&output=json", headers={"User-Agent": USER_AGENT}, timeout=10)
        if r_crt.status_code == 200:
            subs = set()
            for item in r_crt.json():
                for line in str(item.get("name_value", "")).splitlines():
                    clean = line.strip().lstrip("*.")
                    if clean.endswith(domain):
                        subs.add(clean)
            report["crtsh_subdomains"] = sorted(subs)[:60]
    except Exception:
        pass

    try:
        r_wb = requests.get(f"https://archive.org/wayback/available?url={quote(domain)}", headers={"User-Agent": USER_AGENT}, timeout=8)
        if r_wb.status_code == 200:
            closest = r_wb.json().get("archived_snapshots", {}).get("closest")
            if closest:
                report["wayback_snapshot"] = {
                    "timestamp": closest.get("timestamp"),
                    "url": closest.get("url"),
                }
    except Exception:
        pass

    return report


def inspect_file_deep(file_path: str) -> dict:
    if not os.path.isfile(file_path):
        return {"error": "File not found"}
    size = os.path.getsize(file_path)
    with open(file_path, "rb") as f:
        header = f.read(32)
        f.seek(0)
        raw = f.read(1024 * 1024)

    magic_type = "Unknown / Plain Text"
    for sig, desc in MAGIC_SIGNATURES.items():
        if header.startswith(sig):
            magic_type = desc
            break

    entropy = 0.0
    if raw:
        freq = [0] * 256
        for b in raw:
            freq[b] += 1
        for c in freq:
            if c:
                p = c / len(raw)
                entropy -= p * math.log2(p)

    md5_h = hashlib.md5()
    sha1_h = hashlib.sha1()
    sha256_h = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            md5_h.update(chunk)
            sha1_h.update(chunk)
            sha256_h.update(chunk)

    strings = re.findall(rb"[\x20-\x7e]{6,}", raw)
    decoded_strings = [s.decode("ascii", errors="ignore") for s in strings[:80]]
    urls = sorted({m.group(0) for s in decoded_strings for m in re.finditer(r"https?://[^\s\"'<>]+", s)})
    emails = sorted({m.group(0) for s in decoded_strings for m in re.finditer(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", s)})

    exif_data = {}
    img_info = None
    if PIL_AVAILABLE:
        try:
            with Image.open(file_path) as img:
                img_info = f"{img.format} | {img.width}x{img.height} | Mode: {img.mode}"
                raw_exif = img.getexif()
                if raw_exif:
                    for tag_id, val in raw_exif.items():
                        tag_name = ExifTags.TAGS.get(tag_id, str(tag_id))
                        exif_data[str(tag_name)] = str(val)[:120]
        except Exception:
            pass

    return {
        "file": os.path.abspath(file_path),
        "size_bytes": size,
        "header_hex": header[:16].hex(" "),
        "detected_magic_type": magic_type,
        "shannon_entropy": round(entropy, 4),
        "md5": md5_h.hexdigest(),
        "sha1": sha1_h.hexdigest(),
        "sha256": sha256_h.hexdigest(),
        "image_dimensions": img_info,
        "exif": exif_data,
        "embedded_urls": urls[:25],
        "embedded_emails": emails[:25],
        "sample_strings": decoded_strings[:25],
    }


def decode_jwt_unverified(token: str) -> dict:
    parts = token.strip().split(".")
    if len(parts) < 2:
        return {"error": "Invalid JWT format (expected header.payload[.signature])"}

    def b64url_decode(seg: str) -> dict:
        pad = "=" * ((4 - len(seg) % 4) % 4)
        return json.loads(base64.urlsafe_b64decode(seg + pad).decode("utf-8"))

    try:
        header = b64url_decode(parts[0])
        payload = b64url_decode(parts[1])
        timestamps = {}
        for k in ("iat", "exp", "nbf"):
            if isinstance(payload.get(k), (int, float)):
                timestamps[k] = datetime.fromtimestamp(payload[k], tz=dt_timezone.utc).isoformat()
        return {
            "header": header,
            "payload": payload,
            "decoded_timestamps_utc": timestamps,
            "has_signature": len(parts) == 3 and bool(parts[2]),
        }
    except Exception as e:
        return {"error": f"Decode failed: {e}"}


PLATFORMS_200 = [
    ("GitHub", "https://github.com/{target}", ["not found"]),
    ("GitLab", "https://gitlab.com/{target}", ["page not found", "sign in"]),
    ("Reddit", "https://www.reddit.com/user/{target}/", ["sorry, nobody on reddit goes by that name"]),
    ("YouTube", "https://www.youtube.com/@{target}", ["this page isn't available"]),
    ("Medium", "https://medium.com/@{target}", ["page not found", "out of nothing"]),
    ("Dev.to", "https://dev.to/{target}", ["this page does not exist"]),
    ("PyPI", "https://pypi.org/user/{target}/", ["we looked everywhere"]),
    ("NPM", "https://www.npmjs.com/~{target}", ["not found"]),
    ("DockerHub", "https://hub.docker.com/u/{target}", ["page not found"]),
    ("Keybase", "https://keybase.io/{target}", ["no such user"]),
    ("Replit", "https://replit.com/@{target}", ["page not found"]),
    ("Kaggle", "https://www.kaggle.com/{target}", ["page not found"]),
    ("CodePen", "https://codepen.io/{target}", ["not found"]),
    ("TryHackMe", "https://tryhackme.com/p/{target}", ["user not found"]),
    ("HackTheBox", "https://app.hackthebox.com/profile/{target}", ["not found"]),
    ("HackerNews", "https://news.ycombinator.com/user?id={target}", ["no such user"]),
    ("LeetCode", "https://leetcode.com/u/{target}/", ["page not found"]),
    ("Codeforces", "https://codeforces.com/profile/{target}", ["not found"]),
    ("AtCoder", "https://atcoder.jp/users/{target}", ["404 not found"]),
    ("GeeksforGeeks", "https://www.geeksforgeeks.org/user/{target}/", ["page not found"]),
    ("StackOverflow", "https://stackoverflow.com/users/{target}", ["page not found"]),
    ("Bitbucket", "https://bitbucket.org/{target}/", ["repository unavailable", "not found"]),
    ("SourceForge", "https://sourceforge.net/u/{target}/profile/", ["whoops"]),
    ("Behance", "https://www.behance.net/{target}", ["oops! we can't find that page"]),
    ("Dribbble", "https://dribbble.com/{target}", ["whoops, that page is gone"]),
    ("DeviantArt", "https://www.deviantart.com/{target}", ["page not found"]),
    ("ArtStation", "https://www.artstation.com/{target}", ["page not found"]),
    ("Pixiv", "https://www.pixiv.net/en/users/{target}", ["page not found"]),
    ("Flickr", "https://www.flickr.com/people/{target}/", ["page not found"]),
    ("500px", "https://500px.com/p/{target}", ["page not found"]),
    ("Unsplash", "https://unsplash.com/@{target}", ["page not found"]),
    ("Pexels", "https://www.pexels.com/@{target}/", ["page not found"]),
    ("Vimeo", "https://vimeo.com/{target}", ["sorry, we couldn’t find that page"]),
    ("Dailymotion", "https://www.dailymotion.com/{target}", ["page not found"]),
    ("Twitch", "https://www.twitch.tv/{target}", ["unless you’ve got a time machine"]),
    ("Kick", "https://kick.com/{target}", ["not found"]),
    ("Steam", "https://steamcommunity.com/id/{target}", ["the specified profile could not be found"]),
    ("Roblox", "https://www.roblox.com/user.aspx?username={target}", ["page cannot be found"]),
    ("Chess.com", "https://www.chess.com/member/{target}", ["the page you are looking for doesn’t exist"]),
    ("Lichess", "https://lichess.org/@/{target}", ["page not found"]),
    ("Scratch", "https://scratch.mit.edu/users/{target}/", ["whoops! our server is scratch'ing its head"]),
    ("Duolingo", "https://www.duolingo.com/profile/{target}", ["page not found"]),
    ("Goodreads", "https://www.goodreads.com/{target}", ["page not found"]),
    ("Letterboxd", "https://letterboxd.com/{target}/", ["sorry, we can’t find the page"]),
    ("Last.fm", "https://www.last.fm/user/{target}", ["page not found"]),
    ("SoundCloud", "https://soundcloud.com/{target}", ["we can’t find that user"]),
    ("Bandcamp", "https://{target}.bandcamp.com/", ["sorry, that something isn’t here"]),
    ("Mixcloud", "https://www.mixcloud.com/{target}/", ["page not found"]),
    ("Spotify", "https://open.spotify.com/user/{target}", ["page not found"]),
    ("Genius", "https://genius.com/{target}", ["page not found"]),
    ("Mastodon.social", "https://mastodon.social/@{target}", ["the page you are looking for isn't here"]),
    ("Bluesky", "https://bsky.app/profile/{target}.bsky.social", ["profile not found"]),
    ("Threads", "https://www.threads.net/@{target}", ["page not found"]),
    ("Pinterest", "https://www.pinterest.com/{target}/", ["user not found"]),
    ("Tumblr", "https://{target}.tumblr.com/", ["there's nothing here"]),
    ("Quora", "https://www.quora.com/profile/{target}", ["page not found"]),
    ("Wattpad", "https://www.wattpad.com/user/{target}", ["user not found"]),
    ("Substack", "https://{target}.substack.com/", ["no publication found"]),
    ("Hashnode", "https://hashnode.com/@{target}", ["page not found"]),
    ("Patreon", "https://www.patreon.com/{target}", ["this page could not be found"]),
    ("Ko-fi", "https://ko-fi.com/{target}", ["page not found"]),
    ("BuyMeACoffee", "https://www.buymeacoffee.com/{target}", ["page not found"]),
    ("Gumroad", "https://{target}.gumroad.com/", ["page not found"]),
    ("ProductHunt", "https://www.producthunt.com/@{target}", ["we couldn't find that page"]),
    ("Crunchbase", "https://www.crunchbase.com/person/{target}", ["page not found"]),
    ("Fiverr", "https://www.fiverr.com/{target}", ["page not found"]),
    ("Freelancer", "https://www.freelancer.com/u/{target}", ["page not found"]),
    ("Linktree", "https://linktr.ee/{target}", ["the page you're looking for doesn't exist"]),
    ("Carrd", "https://{target}.carrd.co/", ["page not found"]),
    ("About.me", "https://about.me/{target}", ["page not found"]),
    ("Gravatar", "https://en.gravatar.com/{target}", ["not found"]),
    ("WordPress", "https://{target}.wordpress.com/", ["doesn’t exist"]),
    ("Blogger", "https://{target}.blogspot.com/", ["blog not found"]),
    ("Telegram", "https://t.me/{target}", ["if you have telegram, you can contact"]),
    ("Pastebin", "https://pastebin.com/u/{target}", ["not found"]),
    ("GitHub Gist", "https://gist.github.com/{target}", ["not found"]),
    ("Rentry", "https://rentry.co/{target}", ["404 not found"]),
    ("Trello", "https://trello.com/u/{target}", ["model not found"]),
    ("Slack Community", "https://{target}.slack.com/", ["there's been a glitch"]),
    ("Viber", "https://chats.viber.com/{target}", ["not found"]),
    ("Snapchat", "https://www.snapchat.com/add/{target}", ["sorry, we couldn't find"]),
    ("TikTok", "https://www.tiktok.com/@{target}", ["couldn't find this account"]),
    ("Instagram", "https://www.instagram.com/{target}/", ["page isn't available"]),
    ("Facebook", "https://www.facebook.com/{target}", ["this content isn't available"]),
    ("X (Twitter)", "https://x.com/{target}", ["this account doesn’t exist"]),
    ("LinkedIn", "https://www.linkedin.com/in/{target}/", ["page not found"]),
    ("VK", "https://vk.com/{target}", ["page not found"]),
    ("OK.ru", "https://ok.ru/{target}", ["page not found"]),
    ("Weibo", "https://weibo.com/{target}", ["404"]),
    ("Bilibili", "https://space.bilibili.com/{target}", ["404"]),
    ("AniList", "https://anilist.co/user/{target}/", ["404"]),
    ("MyAnimeList", "https://myanimelist.net/profile/{target}", ["404 not found"]),
    ("Crunchyroll", "https://www.crunchyroll.com/user/{target}", ["404"]),
    ("IMDb", "https://www.imdb.com/user/{target}/", ["404 error"]),
    ("Discogs", "https://www.discogs.com/user/{target}", ["404"]),
    ("RateYourMusic", "https://rateyourmusic.com/~{target}", ["page not found"]),
    ("BandLab", "https://www.bandlab.com/{target}", ["page not found"]),
    ("Audiomack", "https://audiomack.com/{target}", ["page not found"]),
    ("ReverbNation", "https://www.reverbnation.com/{target}", ["page not found"]),
    ("Houzz", "https://www.houzz.com/user/{target}", ["page not found"]),
]
_EXTRA_PLATFORMS = [
    ("Airbnb", "https://www.airbnb.com/users/show/{target}"),
    ("TripAdvisor", "https://www.tripadvisor.com/Profile/{target}"),
    ("Yelp", "https://www.yelp.com/user_details?userid={target}"),
    ("Zomato", "https://www.zomato.com/{target}"),
    ("eBay", "https://www.ebay.com/usr/{target}"),
    ("Etsy", "https://www.etsy.com/shop/{target}"),
    ("Shopify", "https://{target}.myshopify.com/"),
    ("Mercari", "https://www.mercari.com/u/{target}/"),
    ("Indeed", "https://my.indeed.com/p/{target}"),
    ("Topcoder", "https://www.topcoder.com/members/{target}"),
    ("HackerRank", "https://www.hackerrank.com/profile/{target}"),
    ("CodeChef", "https://www.codechef.com/users/{target}"),
    ("SPOJ", "https://www.spoj.com/users/{target}/"),
    ("Exercism", "https://exercism.org/profiles/{target}"),
    ("Codecademy", "https://www.codecademy.com/profiles/{target}"),
    ("Coursera", "https://www.coursera.org/user/{target}"),
    ("Udemy", "https://www.udemy.com/user/{target}/"),
    ("KhanAcademy", "https://www.khanacademy.org/profile/{target}"),
    ("Quizlet", "https://quizlet.com/{target}"),
    ("Brainly", "https://brainly.com/app/profile/{target}"),
    ("ResearchGate", "https://www.researchgate.net/profile/{target}"),
    ("Academia.edu", "https://independent.academia.edu/{target}"),
    ("ORCID", "https://orcid.org/{target}"),
    ("SlideShare", "https://www.slideshare.net/{target}"),
    ("Scribd", "https://www.scribd.com/{target}"),
    ("Issuu", "https://issuu.com/{target}"),
    ("Archive.org", "https://archive.org/details/@{target}"),
    ("Wikipedia", "https://en.wikipedia.org/wiki/User:{target}"),
    ("Wikimedia", "https://commons.wikimedia.org/wiki/User:{target}"),
    ("OpenStreetMap", "https://www.openstreetmap.org/user/{target}"),
    ("Strava", "https://www.strava.com/athletes/{target}"),
    ("Garmin", "https://connect.garmin.com/modern/profile/{target}"),
    ("AllTrails", "https://www.alltrails.com/members/{target}"),
    ("Komoot", "https://www.komoot.com/user/{target}"),
    ("Geocaching", "https://www.geocaching.com/p/?u={target}"),
    ("iNaturalist", "https://www.inaturalist.org/people/{target}"),
    ("Meetup", "https://www.meetup.com/members/{target}/"),
    ("Eventbrite", "https://www.eventbrite.com/o/{target}"),
    ("Kickstarter", "https://www.kickstarter.com/profile/{target}"),
    ("Indiegogo", "https://www.indiegogo.com/individuals/{target}"),
    ("OpenCollective", "https://opencollective.com/{target}"),
    ("Liberapay", "https://liberapay.com/{target}/"),
    ("Odysee", "https://odysee.com/@{target}"),
    ("Rumble", "https://rumble.com/user/{target}"),
    ("BitChute", "https://www.bitchute.com/channel/{target}/"),
    ("Minds", "https://www.minds.com/{target}/"),
    ("Gab", "https://gab.com/{target}"),
    ("Gettr", "https://gettr.com/user/{target}"),
    ("TruthSocial", "https://truthsocial.com/@{target}"),
    ("MeWe", "https://mewe.com/i/{target}"),
    ("Couchsurfing", "https://www.couchsurfing.com/people/{target}"),
    ("RubyGems", "https://rubygems.org/profiles/{target}"),
    ("Packagist", "https://packagist.org/users/{target}/"),
    ("Crates.io", "https://crates.io/users/{target}"),
    ("NuGet", "https://www.nuget.org/profiles/{target}"),
    ("HuggingFace", "https://huggingface.co/{target}"),
    ("Civitai", "https://civitai.com/user/{target}"),
    ("ObservableHQ", "https://observablehq.com/@{target}"),
    ("Glitch", "https://glitch.com/@{target}"),
    ("Vercel", "https://{target}.vercel.app/"),
    ("Netlify", "https://{target}.netlify.app/"),
    ("GitHub Pages", "https://{target}.github.io/"),
    ("GitLab Pages", "https://{target}.gitlab.io/"),
    ("Render", "https://{target}.onrender.com/"),
    ("Railway", "https://{target}.up.railway.app/"),
    ("Fly.io", "https://{target}.fly.dev/"),
    ("Heroku", "https://{target}.herokuapp.com/"),
    ("Firebase App", "https://{target}.web.app/"),
    ("Pages.dev", "https://{target}.pages.dev/"),
    ("Surge.sh", "https://{target}.surge.sh/"),
    ("ReadTheDocs", "https://{target}.readthedocs.io/"),
    ("GitBook", "https://{target}.gitbook.io/"),
    ("Notion Site", "https://{target}.notion.site/"),
    ("Wixsite", "https://{target}.wixsite.com/"),
    ("Weebly", "https://{target}.weebly.com/"),
    ("Jimdo", "https://{target}.jimdofree.com/"),
    ("Strikingly", "https://{target}.mystrikingly.com/"),
    ("Webflow", "https://{target}.webflow.io/"),
    ("Framer", "https://{target}.framer.website/"),
    ("Hashnode Blog", "https://{target}.hashnode.dev/"),
    ("Devpost", "https://devpost.com/{target}"),
    ("Hackaday.io", "https://hackaday.io/{target}"),
    ("Instructables", "https://www.instructables.com/member/{target}/"),
    ("Thingiverse", "https://www.thingiverse.com/{target}"),
    ("Printables", "https://www.printables.com/@{target}"),
    ("Cults3D", "https://cults3d.com/en/users/{target}"),
    ("MyMiniFactory", "https://www.myminifactory.com/users/{target}"),
    ("GrabCAD", "https://grabcad.com/{target}"),
    ("Shadertoy", "https://www.shadertoy.com/user/{target}"),
    ("Sketchfab", "https://sketchfab.com/{target}"),
    ("Itch.io", "https://{target}.itch.io/"),
    ("GameJolt", "https://gamejolt.com/@{target}"),
    ("Newgrounds", "https://{target}.newgrounds.com/"),
    ("Kongregate", "https://www.kongregate.com/accounts/{target}"),
    ("Speedrun.com", "https://www.speedrun.com/users/{target}"),
    ("osu!", "https://osu.ppy.sh/users/{target}"),
    ("NameMC", "https://namemc.com/profile/{target}"),
    ("Modrinth", "https://modrinth.com/user/{target}"),
    ("CurseForge", "https://www.curseforge.com/members/{target}"),
    ("NexusMods", "https://www.nexusmods.com/users/{target}"),
]
for _n, _u in _EXTRA_PLATFORMS:
    PLATFORMS_200.append((_n, _u, ["not found", "page not found", "404"]))

WEB_ENDPOINTS_120 = [
    "robots.txt", "sitemap.xml", "sitemap_index.xml", ".well-known/security.txt",
    "security.txt", "humans.txt", "ads.txt", "app-ads.txt", "sellers.json",
    "manifest.json", "site.webmanifest", ".well-known/assetlinks.json",
    ".well-known/apple-app-site-association", "apple-app-site-association",
    ".well-known/openid-configuration", ".well-known/oauth-authorization-server",
    ".well-known/jwks.json", ".well-known/webfinger", ".well-known/host-meta",
    ".well-known/nodeinfo", ".well-known/change-password", ".well-known/dnt-policy.txt",
    ".well-known/gpc.json", ".well-known/brave-rewards-verification.txt",
    "swagger.json", "openapi.json", "openapi.yaml", "api-docs", "v1/api-docs",
    "v2/api-docs", "v3/api-docs", "graphql", "graphiql", "health", "healthz",
    "readyz", "livez", "status", "version", "info", "metrics", "ping",
    "heartbeat", "feed.xml", "rss.xml", "atom.xml", "feed", "rss",
    "crossdomain.xml", "clientaccesspolicy.xml", "browserconfig.xml",
    "favicon.ico", "apple-touch-icon.png", "service-worker.js", "sw.js",
    "workbox.js", "package.json", "composer.json", "Gemfile", "requirements.txt",
    "Cargo.toml", "go.mod", "pom.xml", "build.gradle", "Dockerfile",
    "docker-compose.yml", ".well-known/mta-sts.txt", "mta-sts.txt",
    ".well-known/matrix/server", ".well-known/matrix/client", "keybase.txt",
    ".well-known/keybase.txt", "pgp-key.asc", "publickey.asc", "SECURITY.md",
    "CHANGELOG.md", "LICENSE", "LICENSE.txt", "README.md", "CONTRIBUTING.md",
    "privacy.txt", "terms.txt", "cookies.txt", "accessibility.txt", "llms.txt",
    "llms-full.txt", "ai.txt", "tdmrep.json", "bimi.svg", "logo.svg",
    "bug-bounty.json", "vdp.json", "hall-of-fame.html", "acknowledgments.txt",
    "careers.json", "jobs.json", "team.json", "about.json", "contact.json",
    "locations.json", "stores.json", "faq.json", "pricing.json", "plans.json",
    "changelog.json", "releases.json", "updates.json", "announcements.json",
    "blog.json", "posts.json", "categories.json", "tags.json", "authors.json",
    "events.json", "webinars.json", "partners.json", "sponsors.json",
    "testimonials.json", "reviews.json", "config.json",
]


def _check_single_platform(name: str, template: str, markers: list):
    username = console.input(f"Enter target username for {name}: ").strip()
    if not username:
        console.print("[red][-] Username cannot be empty.[/red]")
        return
    url = template.format(target=quote(username))
    try:
        resp = requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=7, allow_redirects=True)
        low = resp.text.lower()
        exists = resp.status_code == 200 and not any(m in low for m in markers)
        if "login" in resp.url.lower() and "login" not in url.lower():
            exists = False
        console.print(
            f"[bold green][+] FOUND[/bold green] | {name} -> {resp.url} (HTTP {resp.status_code}, {len(resp.text)} bytes)"
            if exists
            else f"[yellow][-] NOT FOUND / PRIVATE[/yellow] | {name} -> {url} (HTTP {resp.status_code})"
        )
    except Exception as e:
        console.print(f"[red][-] {name} request error: {e}[/red]")


def _check_single_endpoint(path: str):
    domain = _clean_domain(console.input(f"Enter domain to check '/{path}': "))
    if not domain:
        console.print("[red][-] Domain cannot be empty.[/red]")
        return
    url = f"https://{domain}/{path}"
    try:
        resp = requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=7, allow_redirects=True)
        ct = resp.headers.get("Content-Type", "unknown")
        found = resp.status_code == 200 and "page not found" not in resp.text.lower()
        color = "bold green" if found else "yellow"
        console.print(f"[{color}][{'+' if found else '-'}] {resp.url} -> HTTP {resp.status_code} | Content-Type: {ct} | Size: {len(resp.content)}B[/{color}]")
        if found and resp.text.strip():
            preview = "\n".join(resp.text.strip().splitlines()[:8])
            console.print(Panel(preview, title=f"Preview: {path}", border_style="cyan"))
    except Exception as e:
        console.print(f"[red][-] Request error: {e}[/red]")


def _check_single_port(port: int, svc: str):
    host = _clean_domain(console.input(f"Enter domain or IP for TCP Port {port} ({svc}): "))
    if not host:
        console.print("[red][-] Target cannot be empty.[/red]")
        return
    try:
        ip = socket.gethostbyname(host)
        t0 = time.time()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.5)
        res = s.connect_ex((ip, port))
        ms = round((time.time() - t0) * 1000, 2)
        banner_txt = ""
        if res == 0:
            try:
                if port in (80, 81, 8080):
                    s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                banner_txt = s.recv(128).decode("utf-8", errors="ignore").strip().splitlines()[0]
            except Exception:
                pass
        s.close()
        state = "[bold green]OPEN[/bold green]" if res == 0 else "[red]CLOSED / FILTERED[/red]"
        console.print(f"[+] {ip}:{port} ({svc}) -> {state} ({ms} ms)")
        if banner_txt:
            console.print(f"    [cyan]Banner:[/cyan] {banner_txt}")
    except Exception as e:
        console.print(f"[red][-] Port scan error: {e}[/red]")


def phone_osint():
    console.print("\n[bold yellow][1] Phone Number OSINT Intelligence[/bold yellow]")
    raw = console.input("Enter phone with country code (e.g., +919876543210): ").strip()
    try:
        parsed = phonenumbers.parse(raw, None)
        e164 = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
        intl = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
        natl = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL)
        digits = re.sub(r"\D", "", e164)
        region = geocoder.description_for_number(parsed, "en") or "Unknown"
        sim_carrier = carrier.name_for_number(parsed, "en") or "Unknown / Ported"
        tz_list = timezone.time_zones_for_number(parsed)
        ntype = get_number_type_label(parsed)

        data = {
            "e164": e164,
            "international": intl,
            "national": natl,
            "country_code": f"+{parsed.country_code}",
            "valid": phonenumbers.is_valid_number(parsed),
            "possible": phonenumbers.is_possible_number(parsed),
            "line_type": ntype,
            "region": region,
            "carrier": sim_carrier,
            "timezones": list(tz_list),
            "wa_me": f"https://wa.me/{digits}",
        }
        table = Table(title="Phone Intelligence Report", border_style="cyan")
        table.add_column("Field", style="green")
        table.add_column("Value", style="white")
        for k, v in data.items():
            table.add_row(k, ", ".join(v) if isinstance(v, list) else str(v))
        console.print(table)
        saved = save_json_report(digits, "phone_osint", data)
        console.print(f"[dim][+] Report saved: {saved}[/dim]")
    except Exception as e:
        console.print(f"[red][-] Phone error: {e}[/red]")


def username_batch_osint():
    console.print("\n[bold yellow][2] Multi-Platform Username OSINT (Top 30 Platforms)[/bold yellow]")
    username = console.input("Enter target username: ").strip()
    if not username:
        return
    subset = PLATFORMS_200[:30]
    console.print(f"[cyan][*] Scanning {len(subset)} platforms for '{username}'...[/cyan]\n")
    matches = []

    def check(item):
        n, tpl, mk = item
        u = tpl.format(target=quote(username))
        try:
            r = requests.get(u, headers={"User-Agent": USER_AGENT}, timeout=6, allow_redirects=True)
            if r.status_code == 200 and not any(m in r.text.lower() for m in mk):
                return {"platform": n, "url": r.url}
        except Exception:
            pass
        return None

    with ThreadPoolExecutor(max_workers=12) as pool:
        for res in as_completed([pool.submit(check, i) for i in subset]):
            hit = res.result()
            if hit:
                matches.append(hit)
                console.print(f"    [bold green][+] {hit['platform']:<16}:[/bold green] {hit['url']}")

    console.print(f"\n[bold cyan][*] Matches found: {len(matches)}/{len(subset)}[/bold cyan]")
    saved = save_json_report(username, "username_osint", {"matches": matches})
    console.print(f"[dim][+] Report saved: {saved}[/dim]")


def domain_deep_osint():
    console.print("\n[bold yellow][3] Deep Domain, DNS, SSL, RDAP & crt.sh Recon[/bold yellow]")
    domain = console.input("Enter domain (e.g., example.com): ").strip()
    if not domain:
        return
    report = deep_domain_audit(domain)
    console.print(json.dumps(report, indent=2))
    saved = save_json_report(report["domain"], "domain_deep", report)
    console.print(f"[dim][+] Report saved: {saved}[/dim]")


def web_paths_audit():
    console.print("\n[bold yellow][4] Web Public Endpoints Audit (Top 25 Files)[/bold yellow]")
    domain = _clean_domain(console.input("Enter domain (e.g., example.com): "))
    if not domain:
        return
    subset = WEB_ENDPOINTS_120[:25]
    matches = []

    def check(ep):
        u = f"https://{domain}/{ep}"
        try:
            r = requests.get(u, headers={"User-Agent": USER_AGENT}, timeout=6, allow_redirects=True)
            if r.status_code == 200 and "page not found" not in r.text.lower():
                return {"endpoint": ep, "url": r.url, "size": len(r.content)}
        except Exception:
            pass
        return None

    with ThreadPoolExecutor(max_workers=10) as pool:
        for res in as_completed([pool.submit(check, ep) for ep in subset]):
            hit = res.result()
            if hit:
                matches.append(hit)
                console.print(f"    [bold green][+] {hit['endpoint']:<32}:[/bold green] {hit['url']} ({hit['size']}B)")

    saved = save_json_report(domain, "web_endpoints", {"matches": matches})
    console.print(f"[dim][+] Report saved: {saved}[/dim]")


def ip_lookup():
    console.print("\n[bold yellow][5] IP Address Intelligence Lookup[/bold yellow]")
    ip = console.input("Enter IP address (blank for current public IP): ").strip()
    info = fetch_ip_data(ip)
    if not info:
        console.print("[red][-] Could not fetch IP data.[/red]")
        return
    table = Table(title="IP Intelligence", border_style="green")
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="white")
    for k, v in info.items():
        table.add_row(k.upper(), str(v if v not in (None, "") else "N/A"))
    if info.get("lat") and info.get("lon") and info.get("lat") != "N/A":
        table.add_row("GOOGLE MAPS", f"https://www.google.com/maps?q={info['lat']},{info['lon']}")
    console.print(table)
    saved = save_json_report(str(info.get("ip") or ip or "self"), "ip_intel", info)
    console.print(f"[dim][+] Report saved: {saved}[/dim]")


def youtube_channel_osint():
    console.print("\n[bold yellow][6] YouTube Channel Public Metadata, Avatar & RSS OSINT[/bold yellow]")
    yt_in = console.input("Enter YouTube @handle or username: ").strip()
    if not yt_in:
        return
    handle = yt_in.lstrip("@").strip()
    url = f"https://www.youtube.com/@{handle}"
    try:
        resp = requests.get(url, headers={"User-Agent": USER_AGENT, "Accept-Language": "en-US,en;q=0.9"}, timeout=10)
        html = resp.text
        title_m = re.search(r"<title>(.*?)</title>", html)
        title = title_m.group(1).replace(" - YouTube", "").strip() if title_m else "Unknown"
        id_m = None
        for pat in [
            r'"channelId"\s*:\s*"(UC[\w-]+)"',
            r'"externalId"\s*:\s*"(UC[\w-]+)"',
            r'"browseId"\s*:\s*"(UC[\w-]+)"',
            r'https://www\.youtube\.com/channel/(UC[\w-]+)',
        ]:
            m = re.search(pat, html)
            if m:
                id_m = m.group(1)
                break
        avatar_m = re.search(r'"avatar"\s*:\s*\{"thumbnails"\s*:\s*\[\{"url"\s*:\s*"(https://[^"]+)"', html)
        if not avatar_m:
            avatar_m = re.search(r'<meta\s+property="og:image"\s+content="(https://[^"]+)"', html)
        avatar_url = avatar_m.group(1) if avatar_m else "Not found in static HTML"

        console.print(f"[green][+] Channel Name :[/green] {title}")
        console.print(f"[green][+] Handle       :[/green] @{handle}")
        console.print(f"[green][+] Channel ID   :[/green] {id_m or 'Not found'}")
        console.print(f"[green][+] Avatar URL   :[/green] {avatar_url}")

        videos = []
        if id_m:
            rss_url = f"https://www.youtube.com/feeds/videos.xml?channel_id={id_m}"
            console.print(f"[green][+] RSS Feed     :[/green] {rss_url}")
            r_rss = requests.get(rss_url, headers={"User-Agent": USER_AGENT}, timeout=8)
            if r_rss.status_code == 200 and "<feed" in r_rss.text:
                root = ET.fromstring(r_rss.text)
                ns = {"atom": "http://www.w3.org/2005/Atom", "yt": "http://www.youtube.com/xml/schemas/yt/2015"}
                for idx, ent in enumerate(root.findall("atom:entry", ns)[:5], 1):
                    v_title = ent.findtext("atom:title", default="Untitled", namespaces=ns)
                    v_id = ent.findtext("yt:videoId", default="", namespaces=ns)
                    pub = ent.findtext("atom:published", default="", namespaces=ns)[:10]
                    v_url = f"https://www.youtube.com/watch?v={v_id}"
                    videos.append({"title": v_title, "video_id": v_id, "published": pub, "url": v_url})
                    console.print(f"    {idx}. [{pub}] {v_title} -> {v_url}")

        saved = save_json_report(
            handle,
            "youtube_osint",
            {"title": title, "handle": f"@{handle}", "channel_id": id_m, "avatar_url": avatar_url, "recent_videos": videos},
        )
        console.print(f"[dim][+] Report saved: {saved}[/dim]")
    except Exception as e:
        console.print(f"[red][-] YouTube OSINT error: {e}[/red]")


def file_forensics():
    console.print("\n[bold yellow][7] Local File Forensics (Magic Bytes, Entropy, EXIF, Strings)[/bold yellow]")
    path = console.input("Enter local file path: ").strip().strip('"').strip("'")
    res = inspect_file_deep(path)
    if "error" in res:
        console.print(f"[red][-] {res['error']}[/red]")
        return
    console.print(json.dumps(res, indent=2))
    saved = save_json_report(os.path.basename(path), "file_forensics", res)
    console.print(f"[dim][+] Report saved: {saved}[/dim]")


def jwt_decoder_tool():
    console.print("\n[bold yellow][8] JWT Header, Payload & Timestamp Decoder[/bold yellow]")
    token = console.input("Paste JWT token: ").strip()
    console.print(json.dumps(decode_jwt_unverified(token), indent=2))


def hash_tool():
    console.print("\n[bold yellow][9] Cryptographic Hash Generator[/bold yellow]")
    text = console.input("Enter text: ")
    b = text.encode("utf-8")
    console.print(f"MD5    : {hashlib.md5(b).hexdigest()}")
    console.print(f"SHA1   : {hashlib.sha1(b).hexdigest()}")
    console.print(f"SHA256 : {hashlib.sha256(b).hexdigest()}")
    console.print(f"SHA512 : {hashlib.sha512(b).hexdigest()}")


def google_dork_builder():
    console.print("\n[bold yellow][10] Targeted OSINT Search Query Builder[/bold yellow]")
    target = console.input("Enter domain, handle, or keyword: ").strip()
    if not target:
        return
    queries = [
        f"site:{target}",
        f'"{target}" filetype:pdf OR filetype:xlsx OR filetype:csv',
        f'"{target}" site:github.com OR site:gitlab.com',
        f'"{target}" intitle:"index of"',
    ]
    for q in queries:
        console.print(f"• {q} -> https://www.google.com/search?q={quote(q)}")


def fast_username_osint():
    console.print("\n[bold yellow][11] Fast Multi-Threaded Username OSINT (60 Platforms)[/bold yellow]")
    username = console.input("Enter target username: ").strip()
    if not username:
        return
    subset = PLATFORMS_200[:60]
    found = []

    def check(item):
        n, tpl, mk = item
        u = tpl.format(target=quote(username))
        try:
            r = requests.get(u, headers={"User-Agent": USER_AGENT}, timeout=6, allow_redirects=True)
            if r.status_code == 200 and not any(m in r.text.lower() for m in mk):
                return {"platform": n, "url": r.url}
        except Exception:
            pass
        return None

    with ThreadPoolExecutor(max_workers=15) as pool:
        for res in as_completed([pool.submit(check, i) for i in subset]):
            hit = res.result()
            if hit:
                found.append(hit)
                console.print(f"    [bold green][+] {hit['platform']:<18}:[/bold green] {hit['url']}")

    console.print(f"\n[bold cyan][*] Found {len(found)}/{len(subset)} matches.[/bold cyan]")
    saved = save_json_report(username, "fast_username_60", {"found": found})
    console.print(f"[dim][+] Report saved: {saved}[/dim]")


def headers_and_waf_audit():
    console.print("\n[bold yellow][12] HTTP Security Headers & WAF / CDN Detector[/bold yellow]")
    raw = console.input("Enter URL or domain: ").strip()
    if not raw:
        return
    url = _normalize_url(raw)
    try:
        resp = requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=8)
        console.print(f"[green][+] Final URL    :[/green] {resp.url}")
        console.print(f"[green][+] Status Code  :[/green] {resp.status_code}")
        for h in [
            "Server",
            "X-Powered-By",
            "X-Frame-Options",
            "Content-Security-Policy",
            "Strict-Transport-Security",
            "X-Content-Type-Options",
            "Referrer-Policy",
        ]:
            val = resp.headers.get(h, "MISSING")
            color = "green" if val != "MISSING" else "red"
            console.print(f"    [{color}]• {h:<28}: {val}[/{color}]")
        hdrs_str = str(resp.headers).lower()
        waf_sigs = {
            "Cloudflare": ["cloudflare", "cf-ray"],
            "AWS CloudFront": ["cloudfront", "x-amz-cf-id"],
            "Akamai": ["akamai", "akamai-ghost"],
            "Fastly": ["fastly", "x-fastly-request-id"],
            "Sucuri": ["sucuri", "x-sucuri-id"],
            "Imperva / Incapsula": ["incapsula", "imperva"],
        }
        detected = [w for w, markers in waf_sigs.items() if any(m in hdrs_str for m in markers)]
        console.print(f"[bold green][+] WAF / CDN    :[/bold green] {', '.join(detected) if detected else 'No major WAF signature'}")
    except Exception as e:
        console.print(f"[red][-] Audit failed: {e}[/red]")


def deep_whatsapp_osint():
    console.print("\n[bold yellow][13] Deep WhatsApp Public Link & Dork Helper[/bold yellow]")
    raw = console.input("Enter phone with country code (e.g., +919876543210): ").strip()
    try:
        parsed = phonenumbers.parse(raw, None)
        e164 = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
        intl = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
        digits = re.sub(r"\D", "", e164)
        table = Table(title="WhatsApp Public OSINT Helper", border_style="green")
        table.add_column("Field", style="cyan")
        table.add_column("Value", style="white")
        table.add_row("E.164 Number", e164)
        table.add_row("Valid Format", str(phonenumbers.is_valid_number(parsed)))
        table.add_row("wa.me Link", f"https://wa.me/{digits}")
        table.add_row("API Send Link", f"https://api.whatsapp.com/send?phone={digits}")
        table.add_row("wa.me Google Dork", f"https://www.google.com/search?q={quote(f'site:wa.me/{digits}')}")
        table.add_row("Public Mentions Dork", f"https://www.google.com/search?q={quote(f'\"{e164}\" OR \"{intl}\" OR \"{digits}\" whatsapp')}")
        console.print(table)
    except Exception as e:
        console.print(f"[red][-] Error: {e}[/red]")


def codec_utility():
    console.print("\n[bold yellow][14] Base64 & URL Encoder / Decoder[/bold yellow]")
    kind = console.input("Codec type - (b)ase64 or (u)rl: ").strip().lower()
    mode = console.input("Mode - (e)ncode or (d)ecode: ").strip().lower()
    data = console.input("Enter text/string: ").strip()
    try:
        if kind.startswith("u"):
            out = quote(data) if mode.startswith("e") else unquote(data)
        else:
            out = (
                base64.b64encode(data.encode("utf-8")).decode("utf-8")
                if mode.startswith("e")
                else base64.b64decode(data.encode("utf-8")).decode("utf-8")
            )
        console.print(f"[green][+] Result:[/green] {out}")
    except Exception as e:
        console.print(f"[red][-] Codec error: {e}[/red]")



def _run_dork(prompt_label: str, query_template: str):
    target = _clean_domain(console.input(prompt_label))
    if not target:
        console.print("[red][-] Input cannot be empty.[/red]")
        return
    q = query_template.format(d=target)
    console.print(f"https://www.google.com/search?q={quote(q)}")


def _build_domain_60() -> list:
    def _fetch_html(d: str):
        return requests.get(f"https://{_clean_domain(d)}", headers={"User-Agent": USER_AGENT}, timeout=8)

    return [
        ("Domain: Full Deep Recon Report", domain_deep_osint),
        ("DNS: IPv4 (A) Records Lookup", lambda: console.print(_doh_query(_clean_domain(console.input("Domain: ")), "A"))),
        ("DNS: IPv6 (AAAA) Records Lookup", lambda: console.print(_doh_query(_clean_domain(console.input("Domain: ")), "AAAA"))),
        ("DNS: Mail Exchange (MX) Records", lambda: console.print(_doh_query(_clean_domain(console.input("Domain: ")), "MX"))),
        ("DNS: Name Servers (NS) Records", lambda: console.print(_doh_query(_clean_domain(console.input("Domain: ")), "NS"))),
        ("DNS: TXT Records (SPF/Verification)", lambda: console.print(_doh_query(_clean_domain(console.input("Domain: ")), "TXT"))),
        ("DNS: CNAME Alias Record", lambda: console.print(_doh_query(_clean_domain(console.input("Domain: ")), "CNAME"))),
        ("DNS: SOA Authority Record", lambda: console.print(_doh_query(_clean_domain(console.input("Domain: ")), "SOA"))),
        ("DNS: CAA Certificate Authority Policy", lambda: console.print(_doh_query(_clean_domain(console.input("Domain: ")), "CAA"))),
        ("DNS: DMARC Policy (_dmarc TXT)", lambda: console.print(_doh_query(f"_dmarc.{_clean_domain(console.input('Domain: '))}", "TXT"))),
        ("DNS: MTA-STS Record (_mta-sts TXT)", lambda: console.print(_doh_query(f"_mta-sts.{_clean_domain(console.input('Domain: '))}", "TXT"))),
        ("DNS: BIMI Brand Logo Record", lambda: console.print(_doh_query(f"default._bimi.{_clean_domain(console.input('Domain: '))}", "TXT"))),
        ("DNS: Reverse PTR Lookup", lambda: console.print(socket.gethostbyaddr(console.input("IP: ").strip())[0])),
        ("SSL: Certificate Subject & Issuer", lambda: console.print(deep_domain_audit(console.input("Domain: ")).get("ssl"))),
        ("SSL: Subject Alternative Names (SANs)", lambda: console.print(deep_domain_audit(console.input("Domain: ")).get("ssl", {}).get("sans_sample"))),
        ("RDAP: Registrar Handle & Status", lambda: console.print(deep_domain_audit(console.input("Domain: ")).get("rdap"))),
        ("RDAP: Domain Registration & Expiry Dates", lambda: console.print(deep_domain_audit(console.input("Domain: ")).get("rdap", {}).get("events"))),
        ("RDAP: Authoritative Nameservers", lambda: console.print(deep_domain_audit(console.input("Domain: ")).get("rdap", {}).get("nameservers"))),
        ("CT Logs: crt.sh Subdomain Enumerator", lambda: console.print("\n".join(deep_domain_audit(console.input("Domain: ")).get("crtsh_subdomains", [])))),
        ("Archive: Wayback Machine Latest Snapshot", lambda: console.print(deep_domain_audit(console.input("Domain: ")).get("wayback_snapshot"))),
        ("Web: HTTP Response Headers Full Dump", lambda: console.print(dict(_fetch_html(console.input("Domain: ")).headers))),
        ("Web: Security Headers Audit", headers_and_waf_audit),
        ("Web: CORS Policy Inspector", lambda: console.print({k: v for k, v in _fetch_html(console.input("Domain: ")).headers.items() if "access-control" in k.lower()})),
        ("Web: Cookie Security Flags Inspector", lambda: console.print(_fetch_html(console.input("Domain: ")).headers.get("Set-Cookie", "No Set-Cookie header"))),
        ("Web: Page Title & Meta Description", lambda: (lambda h: console.print({"title": re.findall(r"<title>(.*?)</title>", h, re.I), "meta_desc": re.findall(r'<meta[^>]+name=["\']description["\'][^>]+content=["\'](.*?)["\']', h, re.I)}))(_fetch_html(console.input("Domain: ")).text)),
        ("Web: OpenGraph (og:*) Metadata Extractor", lambda: console.print(re.findall(r'<meta[^>]+property=["\'](og:[^"\']+)["\'][^>]+content=["\'](.*?)["\']', _fetch_html(console.input("Domain: ")).text, re.I))),
        ("Web: HTML Generator & CMS Fingerprint", lambda: console.print(re.findall(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\'](.*?)["\']', _fetch_html(console.input("Domain: ")).text, re.I))),
        ("Web: Public Emails Scraper from HTML", lambda: console.print(sorted(set(re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", _fetch_html(console.input("Domain: ")).text))))),
        ("Web: External Outbound Links Extractor", lambda: console.print(sorted(set(re.findall(r'href=["\'](https?://[^"\']+)["\']', _fetch_html(console.input("Domain: ")).text)))[:40])),
        ("Web: JavaScript Bundle URLs Extractor", lambda: console.print(sorted(set(re.findall(r'src=["\']([^"\']+\.js[^"\']*)["\']', _fetch_html(console.input("Domain: ")).text)))[:40])),
        ("Web: Stylesheet (CSS) URLs Extractor", lambda: console.print(sorted(set(re.findall(r'href=["\']([^"\']+\.css[^"\']*)["\']', _fetch_html(console.input("Domain: ")).text)))[:40])),
        ("Web: HTML Forms & Action Endpoints", lambda: console.print(re.findall(r"<form[^>]*>", _fetch_html(console.input("Domain: ")).text, re.I))),
        ("Web: Social Media Links Extractor", lambda: console.print(sorted(set(re.findall(r'https?://(?:www\.)?(?:youtube\.com|instagram\.com|x\.com|twitter\.com|facebook\.com|linkedin\.com|github\.com|t\.me)/[^\s"\'<>]+', _fetch_html(console.input("Domain: ")).text))))),
        ("Web: Favicon MD5 & SHA256 Hash", lambda: (lambda b: console.print({"md5": hashlib.md5(b).hexdigest(), "sha256": hashlib.sha256(b).hexdigest(), "bytes": len(b)}))(requests.get(f"https://{_clean_domain(console.input('Domain: '))}/favicon.ico", timeout=6).content)),
        ("Web: robots.txt Disallow Rules Parser", lambda: console.print([l for l in requests.get(f"https://{_clean_domain(console.input('Domain: '))}/robots.txt", timeout=6).text.splitlines() if "disallow" in l.lower() or "sitemap" in l.lower()])),
        ("Web: sitemap.xml URL Counter", lambda: (lambda d: console.print(f"URLs found in sitemap.xml: {len(re.findall(r'<loc>(.*?)</loc>', requests.get(f'https://{d}/sitemap.xml', timeout=6).text))}"))(_clean_domain(console.input("Domain: ")))),
        ("Web: HTTP Redirect Chain Tracer", lambda: (lambda r: console.print([f"{h.status_code} -> {h.url}" for h in r.history] + [f"{r.status_code} -> {r.url}"]))(requests.get(_normalize_url(console.input("URL: ")), headers={"User-Agent": USER_AGENT}, timeout=8))),
        ("Web: HTTP Latency Benchmark (3 Pings)", lambda: (lambda u: console.print([round((lambda t0: (requests.get(u, timeout=6), time.time() - t0)[1])(time.time()) * 1000, 2) for _ in range(3)]))(_normalize_url(console.input("URL: ")))),
        ("Intel: Shodan InternetDB IP Lookup", lambda: console.print(requests.get(f"https://internetdb.shodan.io/{socket.gethostbyname(_clean_domain(console.input('Domain or IP: ')))}", timeout=6).json())),
        ("Intel: HackerTarget Host Search", lambda: console.print(requests.get(f"https://api.hackertarget.com/hostsearch/?q={_clean_domain(console.input('Domain: '))}", timeout=8).text)),
        ("Intel: HackerTarget DNS Lookup", lambda: console.print(requests.get(f"https://api.hackertarget.com/dnslookup/?q={_clean_domain(console.input('Domain: '))}", timeout=8).text)),
        ("Intel: HackerTarget HTTP Headers", lambda: console.print(requests.get(f"https://api.hackertarget.com/httpheaders/?q={_clean_domain(console.input('Domain: '))}", timeout=8).text)),
        ("Intel: HackerTarget Page Links", lambda: console.print(requests.get(f"https://api.hackertarget.com/pagelinks/?q={_clean_domain(console.input('Domain: '))}", timeout=8).text)),
        ("Intel: URLScan.io Public Search API", lambda: console.print([x.get("page", {}).get("url") for x in requests.get(f"https://urlscan.io/api/v1/search/?q=domain:{_clean_domain(console.input('Domain: '))}", timeout=8).json().get("results", [])[:15]])),
        ("Dork: Exposed Documents (PDF/XLSX/DOCX)", lambda p="Domain: ", qt='site:{d} (filetype:pdf OR filetype:xlsx OR filetype:docx OR filetype:csv)': _run_dork(p, qt)),
        ("Dork: Exposed Config & Env Files", lambda p="Domain: ", qt='site:{d} (ext:env OR ext:log OR ext:bak OR ext:sql OR ext:yml)': _run_dork(p, qt)),
        ("Dork: Open Directory Listings", lambda p="Domain: ", qt='site:{d} intitle:"index of"': _run_dork(p, qt)),
        ("Dork: Login & Admin Portals", lambda p="Domain: ", qt='site:{d} (inurl:login OR inurl:admin OR inurl:signin OR inurl:portal)': _run_dork(p, qt)),
        ("Dork: GitHub Code Mentions", lambda p="Domain: ", qt='site:github.com "{d}"': _run_dork(p, qt)),
        ("Dork: Pastebin Mentions", lambda p="Domain: ", qt='site:pastebin.com "{d}"': _run_dork(p, qt)),
        ("Dork: Subdomain Discovery Search", lambda p="Domain: ", qt='site:*.{d} -www': _run_dork(p, qt)),
        ("Dork: Cloud S3 / Blob Buckets", lambda p="Keyword/Domain: ", qt='(site:s3.amazonaws.com OR site:blob.core.windows.net OR site:storage.googleapis.com) "{d}"': _run_dork(p, qt)),
        ("Dork: Trello & Notion Public Boards", lambda p="Keyword/Domain: ", qt='(site:trello.com OR site:notion.site) "{d}"': _run_dork(p, qt)),
        ("Dork: Censys Public Host Link", lambda: console.print(f"https://search.censys.io/search?resource=hosts&q={quote(_clean_domain(console.input('Domain or IP: ')))}")),
        ("Dork: VirusTotal Domain Report Link", lambda: console.print(f"https://www.virustotal.com/gui/domain/{_clean_domain(console.input('Domain: '))}")),
        ("Dork: SecurityTrails DNS History Link", lambda: console.print(f"https://securitytrails.com/domain/{_clean_domain(console.input('Domain: '))}/dns")),
        ("Dork: BuiltWith Tech Stack Link", lambda: console.print(f"https://builtwith.com/{_clean_domain(console.input('Domain: '))}")),
        ("Dork: Netcraft Site Report Link", lambda: console.print(f"https://sitereport.netcraft.com/?url={_clean_domain(console.input('Domain: '))}")),
        ("Dork: ICANN WHOIS Lookup Link", lambda: console.print(f"https://lookup.icann.org/en/lookup?name={_clean_domain(console.input('Domain: '))}")),
        ("Web: Extract HTML Comments (<!-- -->)", lambda: console.print(re.findall(r"<!--(.*?)-->", _fetch_html(console.input("Domain: ")).text, re.S)[:20])),
    ]


PORTS_55 = [
    (20, "FTP-Data"), (21, "FTP"), (22, "SSH"), (23, "Telnet"), (25, "SMTP"),
    (43, "WHOIS"), (53, "DNS"), (67, "DHCP-Server"), (68, "DHCP-Client"), (69, "TFTP"),
    (79, "Finger"), (80, "HTTP"), (81, "HTTP-Alt"), (88, "Kerberos"), (110, "POP3"),
    (111, "RPCBind"), (119, "NNTP"), (123, "NTP"), (135, "MSRPC"), (137, "NetBIOS-NS"),
    (138, "NetBIOS-DGM"), (139, "NetBIOS-SSN"), (143, "IMAP"), (161, "SNMP"), (179, "BGP"),
    (389, "LDAP"), (443, "HTTPS"), (445, "SMB"), (465, "SMTPS"), (500, "ISAKMP-VPN"),
    (514, "Syslog"), (515, "LPD"), (587, "SMTP-Submission"), (631, "IPP-CUPS"), (636, "LDAPS"),
    (873, "Rsync"), (993, "IMAPS"), (995, "POP3S"), (1080, "SOCKS-Proxy"), (1433, "MSSQL"),
    (1521, "Oracle-DB"), (1723, "PPTP-VPN"), (1883, "MQTT"), (2049, "NFS"), (2082, "cPanel"),
    (2083, "cPanel-SSL"), (2086, "WHM"), (2087, "WHM-SSL"), (3306, "MySQL"), (3389, "RDP"),
    (5432, "PostgreSQL"), (5900, "VNC"), (6379, "Redis"), (8080, "HTTP-Proxy"), (8443, "HTTPS-Alt"),
]


def _build_ip_60() -> list:
    items = [
        ("IP: Full Geolocation & ISP Intelligence", ip_lookup),
        ("IP: CIDR Subnet Network & Host Range", lambda: (lambda n: console.print({"network": str(n.network_address), "broadcast": str(n.broadcast_address), "netmask": str(n.netmask), "total_hosts": n.num_addresses}))(ipaddress.ip_network(console.input("CIDR (e.g., 192.168.1.0/24): ").strip(), strict=False))),
        ("IP: Private / Public / Global Classification", lambda: (lambda ip: console.print({"ip": str(ip), "version": ip.version, "is_private": ip.is_private, "is_global": ip.is_global, "is_loopback": ip.is_loopback, "is_multicast": ip.is_multicast}))(ipaddress.ip_address(console.input("IP: ").strip()))),
        ("IP: Integer, Binary & Hex Representation", lambda: (lambda ip: console.print({"ip": str(ip), "int": int(ip), "hex": hex(int(ip)), "bin": bin(int(ip))}))(ipaddress.ip_address(console.input("IPv4: ").strip()))),
        ("IP: Shodan InternetDB Open Ports & Vulns", lambda: console.print(requests.get(f"https://internetdb.shodan.io/{console.input('Public IP: ').strip()}", timeout=6).json())),
    ]
    for p, svc in PORTS_55:
        items.append((f"Port Scan: TCP {p} ({svc}) + Banner", lambda port=p, name=svc: _check_single_port(port, name)))
    return items


def _yt_video_deep():
    vid = console.input("Enter YouTube Video ID or URL: ").strip()
    m = re.search(r"(?:v=|youtu\.be/|shorts/)([\w-]{11})", vid)
    video_id = m.group(1) if m else vid
    oembed = requests.get(f"https://www.youtube.com/oembed?url=https://www.youtube.com/watch?v={video_id}&format=json", timeout=6)
    data = oembed.json() if oembed.status_code == 200 else {}
    data["video_id"] = video_id
    data["thumbnails"] = {
        "maxres": f"https://i.ytimg.com/vi/{video_id}/maxresdefault.jpg",
        "hq": f"https://i.ytimg.com/vi/{video_id}/hqdefault.jpg",
        "sd": f"https://i.ytimg.com/vi/{video_id}/sddefault.jpg",
    }
    console.print(json.dumps(data, indent=2))


def _yt_channel_id_rss():
    cid = console.input("Enter YouTube Channel ID (UC...): ").strip()
    rss_url = f"https://www.youtube.com/feeds/videos.xml?channel_id={cid}"
    r = requests.get(rss_url, headers={"User-Agent": USER_AGENT}, timeout=8)
    if r.status_code != 200:
        console.print("[red][-] Could not fetch RSS for that Channel ID.[/red]")
        return
    root = ET.fromstring(r.text)
    ns = {"atom": "http://www.w3.org/2005/Atom", "yt": "http://www.youtube.com/xml/schemas/yt/2015"}
    for idx, ent in enumerate(root.findall("atom:entry", ns)[:10], 1):
        t = ent.findtext("atom:title", default="", namespaces=ns)
        vid = ent.findtext("yt:videoId", default="", namespaces=ns)
        pub = ent.findtext("atom:published", default="", namespaces=ns)
        console.print(f"{idx:02d}. [{pub}] {t} -> https://youtu.be/{vid}")


def _build_deep_60() -> list:
    return [
        ("YouTube: Full Channel Metadata & RSS OSINT", youtube_channel_osint),
        ("YouTube: Video oEmbed & HD Thumbnails Extractor", _yt_video_deep),
        ("YouTube: Direct Channel ID (UC...) RSS Feed Reader", _yt_channel_id_rss),
        ("YouTube: Channel About/Community Dork Builder", lambda: (lambda h: console.print([f"https://www.google.com/search?q={quote(f'site:youtube.com/@{h}')}", f"https://www.google.com/search?q={quote(f'\"{h}\" site:youtube.com')}"]))(console.input("Handle: ").strip().lstrip("@"))),
        ("YouTube: Extract Channel ID from Any Video URL", lambda: (lambda u: console.print(re.findall(r'"channelId"\s*:\s*"(UC[\w-]+)"', requests.get(u, headers={"User-Agent": USER_AGENT}, timeout=8).text)[:3]))(_normalize_url(console.input("Video URL: ")))),
        ("YouTube: Extract Video Keywords & Meta Tags", lambda: (lambda u: console.print(re.findall(r'<meta\s+name="keywords"\s+content="([^"]+)"', requests.get(u, headers={"User-Agent": USER_AGENT}, timeout=8).text)))(_normalize_url(console.input("Video URL: ")))),
        ("YouTube: Video Publish Date & Category Extractor", lambda: (lambda u: (lambda h: console.print({"datePublished": re.findall(r'itemprop="datePublished"\s+content="([^"]+)"', h), "genre": re.findall(r'itemprop="genre"\s+content="([^"]+)"', h)}))(requests.get(u, headers={"User-Agent": USER_AGENT}, timeout=8).text))(_normalize_url(console.input("Video URL: ")))),
        ("YouTube: Shorts URL to Standard Watch Converter", lambda: (lambda u: console.print(f"https://www.youtube.com/watch?v={re.search(r'shorts/([\w-]{11})', u).group(1)}"))(console.input("Shorts URL: ").strip())),
        ("YouTube: Playlist RSS Feed Generator", lambda: console.print(f"https://www.youtube.com/feeds/videos.xml?playlist_id={console.input('Playlist ID (PL...): ').strip()}")),
        ("YouTube: External Social Links on Channel Page", lambda: (lambda h: console.print(sorted(set(re.findall(r'q=(https%3A%2F%2F[^&"]+)', requests.get(f"https://www.youtube.com/@{h}", headers={"User-Agent": USER_AGENT}, timeout=8).text)))))(console.input("Handle: ").strip().lstrip("@"))),

        ("Phone: Full Telecom & Region Intelligence", phone_osint),
        ("Phone: WhatsApp Direct Link & Public Dorks", deep_whatsapp_osint),
        ("Phone: Telegram Public Link & Dork Builder", lambda: (lambda p: console.print({"t_me": f"https://t.me/{p}", "dork": f"https://www.google.com/search?q={quote(f'\"{p}\" site:t.me OR telegram')}"} ))(phonenumbers.format_number(phonenumbers.parse(console.input("Phone (+91...): ").strip(), None), phonenumbers.PhoneNumberFormat.E164))),
        ("Phone: Truecaller / Sync.me Public Web Dorks", lambda: (lambda p: console.print([f"https://www.google.com/search?q={quote(f'\"{p}\" site:truecaller.com')}", f"https://www.google.com/search?q={quote(f'\"{p}\" site:sync.me')}"]))(phonenumbers.format_number(phonenumbers.parse(console.input("Phone (+91...): ").strip(), None), phonenumbers.PhoneNumberFormat.E164))),
        ("Phone: E.164 / RFC3966 / International Formatter", lambda: (lambda n: console.print({"E164": phonenumbers.format_number(n, phonenumbers.PhoneNumberFormat.E164), "INTL": phonenumbers.format_number(n, phonenumbers.PhoneNumberFormat.INTERNATIONAL), "NATL": phonenumbers.format_number(n, phonenumbers.PhoneNumberFormat.NATIONAL), "RFC3966": phonenumbers.format_number(n, phonenumbers.PhoneNumberFormat.RFC3966)}))(phonenumbers.parse(console.input("Phone (+91...): ").strip(), None))),
        ("Phone: Multi-Format Web Mention Dork Generator", lambda: (lambda n: (lambda e, i, nat: console.print(f"https://www.google.com/search?q={quote(f'\"{e}\" OR \"{i}\" OR \"{nat}\"')}")) (phonenumbers.format_number(n, phonenumbers.PhoneNumberFormat.E164), phonenumbers.format_number(n, phonenumbers.PhoneNumberFormat.INTERNATIONAL), phonenumbers.format_number(n, phonenumbers.PhoneNumberFormat.NATIONAL)))(phonenumbers.parse(console.input("Phone (+91...): ").strip(), None))),
        ("Phone: Country Calling Code & Region Lookup", lambda: (lambda cc: console.print({"country_code": cc, "regions": list(phonenumbers.region_codes_for_country_code(int(cc)))}))(console.input("Country Code (e.g., 91, 1, 44): ").strip().lstrip("+"))),
        ("Phone: Timezone & Geographic Circle Lookup", lambda: (lambda n: console.print({"region": geocoder.description_for_number(n, "en"), "timezones": list(timezone.time_zones_for_number(n))}))(phonenumbers.parse(console.input("Phone (+91...): ").strip(), None))),
        ("Phone: Line Type Classifier (Mobile/VoIP/Fixed)", lambda: (lambda n: console.print({"line_type": get_number_type_label(n), "valid": phonenumbers.is_valid_number(n)}))(phonenumbers.parse(console.input("Phone (+91...): ").strip(), None))),
        ("Phone: Social & Classifieds Dork (OLX/Justdial)", lambda: (lambda p: console.print(f"https://www.google.com/search?q={quote(f'\"{p}\" (site:justdial.com OR site:indiamart.com OR site:olx.in)')}"))(re.sub(r"\D", "", console.input("Phone (+91...): ").strip()))),

        ("Forensics: Complete File & Image Deep Report", file_forensics),
        ("Forensics: Magic Bytes & True File Type Check", lambda: console.print({k: inspect_file_deep(console.input("File path: ").strip().strip('"')).get(k) for k in ("file", "size_bytes", "header_hex", "detected_magic_type")})),
        ("Forensics: File Shannon Entropy (Packed/Encrypted Check)", lambda: console.print(f"Shannon Entropy: {inspect_file_deep(console.input('File path: ').strip().strip('\"')).get('shannon_entropy')} / 8.0")),
        ("Forensics: Image EXIF Metadata Extractor", lambda: console.print(json.dumps(inspect_file_deep(console.input("Image path: ").strip().strip('"')).get("exif", {}), indent=2))),
        ("Forensics: Image Dimensions, Format & Color Mode", lambda: console.print(inspect_file_deep(console.input("Image path: ").strip().strip('"')).get("image_dimensions"))),
        ("Forensics: Strip EXIF & Save Clean Copy of Image", lambda: (lambda p: (lambda img: (img.save(p + "_clean.png"), console.print(f"[green][+] Clean image saved: {p}_clean.png[/green]")))(Image.open(p)))(console.input("Image path: ").strip().strip('"'))),
        ("Forensics: Extract Embedded URLs from Binary/File", lambda: console.print(inspect_file_deep(console.input("File path: ").strip().strip('"')).get("embedded_urls"))),
        ("Forensics: Extract Embedded Emails from Binary/File", lambda: console.print(inspect_file_deep(console.input("File path: ").strip().strip('"')).get("embedded_emails"))),
        ("Forensics: ASCII Printable Strings Extractor", lambda: console.print("\n".join(inspect_file_deep(console.input("File path: ").strip().strip('"')).get("sample_strings", [])))),
        ("Forensics: File Checksums (MD5 / SHA1 / SHA256)", lambda: console.print({k: inspect_file_deep(console.input("File path: ").strip().strip('"')).get(k) for k in ("md5", "sha1", "sha256")})),
        ("Forensics: Compare Two Files by SHA256 Hash", lambda: (lambda f1, f2: console.print("MATCH (Identical)" if inspect_file_deep(f1).get("sha256") == inspect_file_deep(f2).get("sha256") else "DIFFERENT"))(console.input("File 1: ").strip().strip('"'), console.input("File 2: ").strip().strip('"'))),
        ("Forensics: ZIP / APK / DOCX Internal File List", lambda: (lambda p: (lambda zf: console.print(zf.namelist()[:50]))(__import__("zipfile").ZipFile(p)))(console.input("Archive/DOCX/APK path: ").strip().strip('"'))),
        ("Forensics: PDF Metadata & Page Count Inspector", lambda: (lambda p: (lambda raw: console.print({"pdf_header": raw[:16], "urls": re.findall(rb"https?://[^\s\)<>]+", raw)[:20]}))(open(p, "rb").read()))(console.input("PDF path: ").strip().strip('"'))),
        ("Forensics: Hex Dump First 256 Bytes of File", lambda: (lambda p: console.print(open(p, "rb").read(256).hex(" ")))(console.input("File path: ").strip().strip('"'))),
        ("Forensics: IPv4 Addresses Extractor from Local File", lambda: (lambda p: console.print(sorted(set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", open(p, "rb").read().decode("latin1"))))))(console.input("File path: ").strip().strip('"'))),
        ("Forensics: Base64 Blobs Finder inside Local File", lambda: (lambda p: console.print(re.findall(r"[A-Za-z0-9+/]{32,}={0,2}", open(p, "rb").read().decode("latin1"))[:15]))(console.input("File path: ").strip().strip('"'))),
        ("Forensics: JWT Tokens Finder inside Local File", lambda: (lambda p: console.print(re.findall(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", open(p, "rb").read().decode("latin1"))))(console.input("File path: ").strip().strip('"'))),
        ("Forensics: File Timestamps (Created/Modified/Accessed)", lambda: (lambda st: console.print({"modified": datetime.fromtimestamp(st.st_mtime).isoformat(), "accessed": datetime.fromtimestamp(st.st_atime).isoformat(), "changed": datetime.fromtimestamp(st.st_ctime).isoformat()}))(os.stat(console.input("File path: ").strip().strip('"')))) ,
        ("Forensics: Directory Recursive Extension Counter", lambda: (lambda d: (lambda exts: console.print({e: exts.count(e) for e in sorted(set(exts))}))([os.path.splitext(f)[1].lower() or "no_ext" for _, _, fs in os.walk(d) for f in fs]))(console.input("Directory path: ").strip().strip('"'))),
        ("Forensics: Reverse Image Search URL Helper", lambda: console.print({"Google Lens": "https://lens.google.com/", "TinEye": "https://tineye.com/", "Yandex Images": "https://yandex.com/images/"})),

        ("Crypto: JWT Header, Payload & UTC Expiry Decoder", jwt_decoder_tool),
        ("Crypto: Multi-Hash Generator (MD5/SHA1/256/512)", hash_tool),
        ("Crypto: SHA3-256 & BLAKE2b Hash Generator", lambda: (lambda b: console.print({"sha3_256": hashlib.sha3_256(b).hexdigest(), "blake2b": hashlib.blake2b(b).hexdigest()}))(console.input("Text: ").encode())),
        ("Codec: Base64 Encode / Decode", codec_utility),
        ("Codec: Base32 Encode / Decode", lambda: (lambda m, t: console.print(base64.b32encode(t.encode()).decode() if m == "e" else base64.b32decode(t.encode()).decode()))(console.input("(e)ncode/(d)ecode: ").strip().lower(), console.input("Text: ").strip())),
        ("Codec: Hexadecimal Encode / Decode", lambda: (lambda m, t: console.print(t.encode().hex() if m == "e" else bytes.fromhex(t).decode("utf-8", errors="replace")))(console.input("(e)ncode/(d)ecode: ").strip().lower(), console.input("Text/Hex: ").strip())),
        ("Codec: ROT13 Cipher Transform", lambda: console.print(codecs.encode(console.input("Text: "), "rot_13"))),
        ("Codec: Binary (8-bit ASCII) Encoder", lambda: console.print(" ".join(format(ord(c), "08b") for c in console.input("Text: ")))),
        ("Codec: Unix Epoch Timestamp to UTC / Local Date", lambda: (lambda ts: console.print({"utc": datetime.fromtimestamp(float(ts), tz=dt_timezone.utc).isoformat(), "local": datetime.fromtimestamp(float(ts)).isoformat()}))(console.input("Unix Timestamp: ").strip())),
        ("Email OSINT: Domain MX, SPF & DMARC Audit", lambda: (lambda em: (lambda dom: console.print({"domain": dom, "mx": _doh_query(dom, "MX"), "txt": _doh_query(dom, "TXT"), "dmarc": _doh_query(f"_dmarc.{dom}", "TXT")}))(em.split("@")[-1]))(console.input("Email address: ").strip())),
        ("Email OSINT: Gravatar Profile Hash & URL Check", lambda: (lambda h: console.print({"md5": h, "avatar": f"https://www.gravatar.com/avatar/{h}?d=404", "profile": f"https://en.gravatar.com/{h}.json"}))(hashlib.md5(console.input("Email: ").strip().lower().encode()).hexdigest())),
        ("Email OSINT: Public Paste & Breach Mention Dorks", lambda: (lambda em: console.print([f"https://www.google.com/search?q={quote(f'\"{em}\"')}", f"https://www.google.com/search?q={quote(f'\"{em}\" site:pastebin.com OR site:github.com')}"]))(console.input("Email: ").strip())),
        ("OSINT: GitHub User Public API Metadata", lambda: console.print(json.dumps({k: v for k, v in requests.get(f"https://api.github.com/users/{quote(console.input('GitHub username: ').strip())}", timeout=6).json().items() if k in ("login", "id", "name", "company", "blog", "location", "email", "bio", "public_repos", "followers", "following", "created_at", "updated_at")}, indent=2))),
        ("OSINT: GitHub User Public Events / Activity", lambda: console.print([{"type": e.get("type"), "repo": e.get("repo", {}).get("name"), "at": e.get("created_at")} for e in requests.get(f"https://api.github.com/users/{quote(console.input('GitHub username: ').strip())}/events/public", timeout=6).json()[:10]])),
        ("OSINT: Reddit User Public About JSON", lambda: console.print(json.dumps(requests.get(f"https://www.reddit.com/user/{quote(console.input('Reddit username: ').strip())}/about.json", headers={"User-Agent": USER_AGENT}, timeout=6).json().get("data", {}), indent=2)[:1500])),
        ("OSINT: PyPI Maintainer Packages Lookup", lambda: console.print(f"https://pypi.org/user/{quote(console.input('PyPI username: ').strip())}/")),
        ("OSINT: MAC Address Vendor (OUI) Lookup", lambda: console.print(requests.get(f"https://api.macvendors.com/{quote(console.input('MAC Address (e.g., 00:1A:2B:3C:4D:5E): ').strip())}", timeout=6).text)),
        ("OSINT: CVE Vulnerability Details (CIRCL API)", lambda: console.print(json.dumps({k: v for k, v in requests.get(f"https://cve.circl.lu/api/cve/{quote(console.input('CVE ID (e.g., CVE-2021-44228): ').strip().upper())}", timeout=8).json().items() if k in ("id", "cvss", "summary", "Published", "Modified")}, indent=2))),
        ("OSINT: Wikipedia Summary Lookup", lambda: console.print(requests.get(f"https://en.wikipedia.org/api/rest_v1/page/summary/{quote(console.input('Topic: ').strip())}", headers={"User-Agent": USER_AGENT}, timeout=6).json().get("extract", "Not found"))),
        ("OSINT: All-in-One Dork Query Builder", google_dork_builder),
    ]


def _build_500_registry() -> dict:
    registry = {}

    for idx, (name, tpl, markers) in enumerate(PLATFORMS_200[:200], 1):
        registry[f"{idx:03d}"] = (
            f"Platform OSINT: {name}",
            lambda n=name, t=tpl, m=markers: _check_single_platform(n, t, m),
        )

    for offset, ep in enumerate(WEB_ENDPOINTS_120[:120]):
        idx = 201 + offset
        registry[f"{idx:03d}"] = (
            f"Web Endpoint: /{ep}",
            lambda path=ep: _check_single_endpoint(path),
        )

    for offset, (label, fn) in enumerate(_build_domain_60()[:60]):
        idx = 321 + offset
        registry[f"{idx:03d}"] = (label, fn)

    for offset, (label, fn) in enumerate(_build_ip_60()[:60]):
        idx = 381 + offset
        registry[f"{idx:03d}"] = (label, fn)

    for offset, (label, fn) in enumerate(_build_deep_60()[:60]):
        idx = 441 + offset
        registry[f"{idx:03d}"] = (label, fn)

    return registry


def registry_500_explorer():
    console.print("\n[bold yellow][15] 500-Option Unique Operational Registry Explorer[/bold yellow]")
    registry = _build_500_registry()
    keys = sorted(registry.keys())
    page = 1
    page_size = 25
    total_pages = (len(keys) + page_size - 1) // page_size

    while True:
        start = (page - 1) * page_size
        end = start + page_size
        console.print(f"\n[bold cyan]Options {start + 1}–{min(end, len(keys))} of {len(keys)} (Page {page}/{total_pages})[/bold cyan]")
        for k in keys[start:end]:
            console.print(f"[{k}] {registry[k][0]}")
        console.print("[ n ] Next | [ p ] Prev | [ g ] Jump # (1-500) | [ f ] Filter Keyword | [ b ] Back to Main Menu")

        cmd = console.input("\n[bold cyan]Select option (001-500) or command (n/p/g/f/b): [/bold cyan]").strip().lower()
        if cmd == "b":
            break
        elif cmd == "n":
            page = min(total_pages, page + 1)
        elif cmd == "p":
            page = max(1, page - 1)
        elif cmd == "f":
            kw = console.input("Enter keyword (e.g., youtube, phone, dns, port, exif, github): ").strip().lower()
            hits = [k for k in keys if kw in registry[k][0].lower()]
            console.print(f"[cyan][*] Found {len(hits)} matching options:[/cyan]")
            for k in hits[:40]:
                console.print(f"    [{k}] {registry[k][0]}")
        elif cmd == "g":
            num = console.input("Enter option number (1-500): ").strip()
            if num.isdigit() and 1 <= int(num) <= len(registry):
                key = f"{int(num):03d}"
                console.print(f"\n[bold yellow][{key}] {registry[key][0]}[/bold yellow]")
                try:
                    registry[key][1]()
                except Exception as e:
                    console.print(f"[red][-] Error: {e}[/red]")
                console.input("\n[dim]Press Enter to continue...[/dim]")
            else:
                console.print("[red][-] Invalid number.[/red]")
        else:
            key = f"{int(cmd):03d}" if cmd.isdigit() else cmd
            if key in registry:
                console.print(f"\n[bold yellow][{key}] {registry[key][0]}[/bold yellow]")
                try:
                    registry[key][1]()
                except Exception as e:
                    console.print(f"[red][-] Error: {e}[/red]")
                console.input("\n[dim]Press Enter to continue...[/dim]")
            else:
                console.print("[red][-] Unknown option.[/red]")


MENU = {
    "1": ("Phone Number OSINT Intelligence", phone_osint),
    "2": ("Multi-Platform Username OSINT (Top 30 Platforms)", username_batch_osint),
    "3": ("Deep Domain Recon (DNS, SSL, RDAP, crt.sh, Wayback)", domain_deep_osint),
    "4": ("Web Public Endpoints Audit (Top 25 Files)", web_paths_audit),
    "5": ("IP Address Intelligence Lookup", ip_lookup),
    "6": ("YouTube Channel Metadata, Avatar & RSS OSINT", youtube_channel_osint),
    "7": ("Local File Forensics (Magic Bytes, Entropy, EXIF, Strings)", file_forensics),
    "8": ("JWT Header, Payload & UTC Expiry Decoder", jwt_decoder_tool),
    "9": ("Cryptographic Hash Generator", hash_tool),
    "10": ("Targeted OSINT Search Query Builder", google_dork_builder),
    "11": ("Fast Multi-Threaded Username OSINT (60 Platforms)", fast_username_osint),
    "12": ("HTTP Security Headers & WAF / CDN Detector", headers_and_waf_audit),
    "13": ("Deep WhatsApp Public Link & Dork Helper", deep_whatsapp_osint),
    "14": ("Base64 & URL Encoder / Decoder", codec_utility),
    "15": ("500-Option Unique Operational Registry Explorer", registry_500_explorer),
}


def main():
    while True:
        banner()
        for k in sorted(MENU.keys(), key=int):
            console.print(f"[{k:>2}] {MENU[k][0]}")
        console.print("[ 0] Exit")

        choice = console.input("\n[bold cyan]Select option: [/bold cyan]").strip()
        if choice == "0":
            console.print("[bold red]Exiting ELVORIX-OSINT. Stay ethical![/bold red]")
            sys.exit(0)
        elif choice in MENU:
            MENU[choice][1]()
        else:
            console.print("[red][-] Invalid option.[/red]")

        console.input("\n[dim]Press Enter to return to menu...[/dim]")


if __name__ == "__main__":
    main()
