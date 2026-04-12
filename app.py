"""
CyberScan Sentinel — v2.4 "Wayback Edition"
Changes from v2.3:
  • Replaced paid Screenshot API with Wayback Machine (archive.org) for free,
    zero-interaction safe previews — no API key required
  • capture_safe_preview() now queries the Wayback Availability API, extracts
    the closest archived snapshot URL, and optionally attempts a Save Page Now
    submission when no snapshot exists
  • Removed SCREENSHOT_API_KEY dependency entirely
  • UI renders archive snapshot in a sandboxed <iframe> with a direct archive link
"""

import os
import re
import time
import requests
from urllib.parse import urlparse, urljoin, quote_plus
from flask import Flask, request, jsonify, render_template
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False

VIRUSTOTAL_API_KEY  = os.getenv("VIRUSTOTAL_API_KEY", "")
REQUEST_TIMEOUT     = int(os.getenv("REQUEST_TIMEOUT", "10"))
MAX_REDIRECT_HOPS   = int(os.getenv("MAX_REDIRECT_HOPS", "5"))

VT_SCAN_ENDPOINT    = "https://www.virustotal.com/api/v3/urls"

# Wayback Machine endpoints — no authentication required
WAYBACK_AVAILABILITY_API = "https://archive.org/wayback/available"
WAYBACK_SAVE_API         = "https://web.archive.org/save/"

# ──────────────────────────────────────────────
# URL Shortener Registry
# If the submitted URL's apex domain is in this set, we flag it as a
# shortener, still scan it, but score the FINAL DESTINATION — not the hop.
# ──────────────────────────────────────────────
URL_SHORTENERS = {
    "bit.ly", "bitly.com",
    "t.co", "tinyurl.com",
    "goo.gl", "ow.ly",
    "buff.ly", "rebrand.ly",
    "short.io", "bl.ink",
    "cutt.ly", "is.gd",
    "tiny.cc", "shrtco.de",
    "lnkd.in", "rb.gy",
    "shorte.st", "adf.ly",
    "bc.vc", "clk.sh",
    "hyperurl.co", "url.ie",
}

# ──────────────────────────────────────────────
# Trusted-Domain Whitelist + Logo Map
# Logo URLs are stable CDN-hosted SVG/PNG marks — no hotlinking risk.
# ──────────────────────────────────────────────
TRUSTED_DOMAIN_LOGOS = {
    "google.com":         "https://www.google.com/favicon.ico",
    "googleapis.com":     "https://www.google.com/favicon.ico",
    "gstatic.com":        "https://www.google.com/favicon.ico",
    "googletagmanager.com": "https://www.google.com/favicon.ico",
    "youtube.com":        "https://www.youtube.com/favicon.ico",
    "microsoft.com":      "https://www.microsoft.com/favicon.ico",
    "azure.com":          "https://www.microsoft.com/favicon.ico",
    "live.com":           "https://www.microsoft.com/favicon.ico",
    "office.com":         "https://www.microsoft.com/favicon.ico",
    "microsoftonline.com":"https://www.microsoft.com/favicon.ico",
    "apple.com":          "https://www.apple.com/favicon.ico",
    "icloud.com":         "https://www.apple.com/favicon.ico",
    "github.com":         "https://github.com/favicon.ico",
    "githubusercontent.com": "https://github.com/favicon.ico",
    "github.io":          "https://github.com/favicon.ico",
    "npmjs.com":          "https://www.npmjs.com/favicon.ico",
    "cloudflare.com":     "https://www.cloudflare.com/favicon.ico",
    "cloudflare.net":     "https://www.cloudflare.com/favicon.ico",
    "stripe.com":         "https://stripe.com/favicon.ico",
    "amazonaws.com":      "https://aws.amazon.com/favicon.ico",
    "awsstatic.com":      "https://aws.amazon.com/favicon.ico",
    "fastly.net":         "https://www.fastly.com/favicon.ico",
    "akamaihd.net":       "https://www.akamai.com/favicon.ico",
    "jquery.com":         "https://jquery.com/favicon.ico",
    "jsdelivr.net":       "https://www.jsdelivr.com/favicon.ico",
    "unpkg.com":          "https://www.unpkg.com/favicon.ico",
}

TRUSTED_DOMAINS = set(TRUSTED_DOMAIN_LOGOS.keys()) | {
    "bootstrapcdn.com", "cdnjs.cloudflare.com",
    "twilio.com", "sendgrid.com", "salesforce.com",
    "googlevideo.com", "bing.com", "msn.com",
}

# ──────────────────────────────────────────────
# Header Metadata
# ──────────────────────────────────────────────
HEADER_METADATA = {
    "Strict-Transport-Security": {
        "why": "Prevents protocol-downgrade attacks and cookie hijacking by forcing HTTPS communication.",
        "recommended": "max-age=31536000; includeSubDomains; preload",
        "tier": "CRITICAL",
    },
    "Content-Security-Policy": {
        "why": "Mitigates XSS and data-injection by whitelisting approved content sources.",
        "recommended": "default-src 'self'; script-src 'self'; object-src 'none';",
        "tier": "CRITICAL",
    },
    "X-Frame-Options": {
        "why": "Blocks embedding in foreign iframes, preventing clickjacking attacks.",
        "recommended": "DENY",
        "tier": "CRITICAL",
    },
    "X-Content-Type-Options": {
        "why": "Prevents MIME-sniffing, blocking drive-by-download vectors.",
        "recommended": "nosniff",
        "tier": "IMPORTANT",
    },
    "Referrer-Policy": {
        "why": "Controls referrer leakage to third-party domains.",
        "recommended": "strict-origin-when-cross-origin",
        "tier": "IMPORTANT",
    },
    "Permissions-Policy": {
        "why": "Restricts browser feature access (camera, mic, geolocation) from embedded contexts.",
        "recommended": "geolocation=(), microphone=(), camera=()",
        "tier": "OPTIONAL",
    },
}

OBFUSCATION_PATTERNS = [
    (r"eval\s*\(",                 "eval() dynamic execution",           "HIGH"),
    (r"document\.write\s*\(",      "document.write() DOM injection",      "HIGH"),
    (r"unescape\s*\(",             "unescape() string obfuscation",       "HIGH"),
    (r"String\.fromCharCode\s*\(", "CharCode-based string construction",  "MEDIUM"),
    (r"atob\s*\(",                 "Base64 decode (atob) pattern",        "MEDIUM"),
    (r"\\x[0-9a-fA-F]{2}",        "Hex-encoded string literals",         "LOW"),
    (r"\\u[0-9a-fA-F]{4}",        "Unicode escape sequences",            "LOW"),
    (r"setTimeout\s*\(\s*['\"]",   "setTimeout string-eval payload",      "HIGH"),
    (r"setInterval\s*\(\s*['\"]",  "setInterval string-eval payload",     "HIGH"),
]

MINIFIED_SAFE_PATTERNS = {
    r"\\x[0-9a-fA-F]{2}",
    r"\\u[0-9a-fA-F]{4}",
    r"String\.fromCharCode\s*\(",
    r"atob\s*\(",
}


# ──────────────────────────────────────────────
# Utilities
# ──────────────────────────────────────────────

def normalize_url(raw: str) -> str:
    raw = raw.strip()
    if not raw.startswith(("http://", "https://")):
        raw = "https://" + raw
    return raw

def is_valid_url(url: str) -> bool:
    try:
        r = urlparse(url)
        return all([r.scheme in ("http", "https"), r.netloc])
    except Exception:
        return False

def get_apex_domain(url: str) -> str:
    try:
        host = urlparse(url).netloc.lower().split(":")[0]
        parts = host.split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else host
    except Exception:
        return ""

def is_trusted(url: str) -> bool:
    return get_apex_domain(url) in TRUSTED_DOMAINS

def is_shortener(url: str) -> bool:
    return get_apex_domain(url) in URL_SHORTENERS

def get_trust_logo(url: str) -> str | None:
    return TRUSTED_DOMAIN_LOGOS.get(get_apex_domain(url))

def is_minified_source(source: str) -> bool:
    if not source:
        return False
    lines = source.splitlines()
    if not lines:
        return False
    return (len(lines) / max(len(source), 1) < 0.001) or (len(source) / max(len(lines), 1) > 500)


# ──────────────────────────────────────────────
# Module 1 — Redirect Chain (cap-aware, shortener-aware)
# ──────────────────────────────────────────────

def trace_redirect_chain(url: str) -> dict:
    """
    Follow hops manually. If chain hits MAX_REDIRECT_HOPS exactly (cap reached),
    `cap_hit` is True — this escalates the redirect component score significantly.

    Shortener detection: if origin is a known shortener, `via_shortener` is True
    and the report clearly states the score targets the final destination.
    """
    chain         = []
    current_url   = url
    origin_apex   = get_apex_domain(url)
    via_shortener = is_shortener(url)
    session       = requests.Session()
    ua = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    )

    for hop_num in range(MAX_REDIRECT_HOPS):
        t0  = time.monotonic()
        hop = {
            "hop":          hop_num + 1,
            "url":          current_url,
            "status_code":  None,
            "server":       None,
            "latency_ms":   None,
            "cross_domain": get_apex_domain(current_url) != origin_apex,
            "shortener":    is_shortener(current_url),
            "error":        None,
        }

        try:
            resp = session.get(
                current_url,
                headers={"User-Agent": ua},
                allow_redirects=False,
                timeout=REQUEST_TIMEOUT,
                verify=True,
            )
            hop["status_code"] = resp.status_code
            hop["server"]      = resp.headers.get("Server")
            hop["latency_ms"]  = round((time.monotonic() - t0) * 1000)
            chain.append(hop)

            if resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("Location", "").strip()
                if not location:
                    break
                current_url = urljoin(current_url, location)
            else:
                break

        except requests.exceptions.SSLError as exc:
            hop["error"] = f"SSL/TLS failure: {str(exc)[:120]}"
            chain.append(hop)
            break
        except requests.exceptions.ConnectionError as exc:
            hop["error"] = f"Connection failure: {str(exc)[:120]}"
            chain.append(hop)
            break
        except requests.exceptions.Timeout:
            hop["error"] = "Request timed out."
            chain.append(hop)
            break

    final_url            = chain[-1]["url"] if chain else url
    cross_domain_final   = get_apex_domain(url) != get_apex_domain(final_url)
    suspicious_hop_count = sum(1 for h in chain if h.get("cross_domain") and h["hop"] > 1)
    # Cap hit = we consumed ALL available hops without reaching a terminal response
    cap_hit = (len(chain) == MAX_REDIRECT_HOPS and
               chain[-1].get("status_code") in (301, 302, 303, 307, 308, None))

    return {
        "chain":                chain,
        "hop_count":            len(chain),
        "final_url":            final_url,
        "cross_domain_redirect": cross_domain_final,
        "suspicious_hop_count": suspicious_hop_count,
        "cap_hit":              cap_hit,
        "via_shortener":        via_shortener,
    }


# ──────────────────────────────────────────────
# Module 2 — HTTP Header Audit
# ──────────────────────────────────────────────

def audit_response_headers(url: str) -> dict:
    findings      = []
    raw_headers   = {}
    server_info   = None
    https_enforced = url.startswith("https://")

    try:
        resp = requests.head(
            url, timeout=REQUEST_TIMEOUT, allow_redirects=True,
            headers={"User-Agent": "CyberScan-Sentinel/2.3"}, verify=True,
        )
        raw_headers   = dict(resp.headers)
        server_info   = resp.headers.get("Server", "Not Disclosed")
        present_lower = {k.lower() for k in resp.headers}

        for header, meta in HEADER_METADATA.items():
            absent = header.lower() not in present_lower
            findings.append({
                "header":            header,
                "tier":              meta["tier"],
                "status":            "ABSENT" if absent else "PRESENT",
                "severity":          "MEDIUM" if absent else "INFO",
                "current_value":     None if absent else resp.headers.get(header, ""),
                "why_it_matters":    meta["why"],
                "recommended_value": meta["recommended"],
            })

        if server_info and server_info != "Not Disclosed":
            findings.append({
                "header":            "Server",
                "tier":              "OPTIONAL",
                "status":            "DISCLOSURE",
                "severity":          "LOW",
                "current_value":     server_info,
                "why_it_matters":    "Disclosing server software gives attackers a precise CVE target.",
                "recommended_value": "Remove or suppress the Server header.",
            })

        if not https_enforced:
            findings.append({
                "header":            "Transport",
                "tier":              "CRITICAL",
                "status":            "INSECURE",
                "severity":          "HIGH",
                "current_value":     "http://",
                "why_it_matters":    "HTTP transmits all data in plaintext, enabling trivial MITM interception.",
                "recommended_value": "Migrate to HTTPS and 301-redirect all HTTP traffic.",
            })

    except requests.exceptions.RequestException as exc:
        findings.append({
            "header": "N/A", "tier": "CRITICAL", "status": "ERROR",
            "severity": "HIGH", "current_value": None,
            "why_it_matters":    "Audit could not complete due to a network-level failure.",
            "recommended_value": str(exc)[:200],
        })

    absent_count = sum(1 for f in findings if f["status"] == "ABSENT")
    # Weight critical-tier absences more heavily
    critical_absent = sum(
        1 for f in findings if f["status"] == "ABSENT" and f.get("tier") == "CRITICAL"
    )
    risk_level = "LOW" if absent_count < 2 else ("MEDIUM" if absent_count < 4 else "HIGH")
    if critical_absent >= 2:
        risk_level = "HIGH"

    return {
        "findings":        findings,
        "server":          server_info,
        "https_enforced":  https_enforced,
        "missing_headers": absent_count,
        "critical_absent": critical_absent,
        "risk_level":      risk_level,
        "raw_headers":     raw_headers,
    }


# ──────────────────────────────────────────────
# Module 3 — Static HTML Payload Analysis
# ──────────────────────────────────────────────

def analyze_html_payload(url: str, trusted: bool = False) -> dict:
    detections          = []
    iframe_count        = 0
    hidden_iframe_count = 0
    auto_download       = False
    raw_size_bytes      = 0
    minified            = False

    SEVERITY_DOWNSHIFT = {"CRITICAL":"HIGH","HIGH":"MEDIUM","MEDIUM":"LOW","LOW":"INFO"}

    try:
        resp = requests.get(
            url, timeout=REQUEST_TIMEOUT, allow_redirects=True,
            headers={"User-Agent": "CyberScan-Sentinel/2.3"},
            verify=True, stream=True,
        )
        chunks, downloaded = [], 0
        for chunk in resp.iter_content(chunk_size=8192):
            chunks.append(chunk)
            downloaded += len(chunk)
            if downloaded > 2 * 1024 * 1024:
                break

        raw_bytes      = b"".join(chunks)
        raw_size_bytes = len(raw_bytes)
        source         = raw_bytes.decode("utf-8", errors="replace")
        minified       = is_minified_source(source)

        for pattern, label, base_sev in OBFUSCATION_PATTERNS:
            matches = re.findall(pattern, source)
            if not matches:
                continue
            eff_sev = base_sev
            note    = None
            if minified and pattern in MINIFIED_SAFE_PATTERNS:
                eff_sev = "LOW"
                note = ("Detected inside a large minified bundle. "
                        "Common in jQuery/React — classify as optimized code unless VT corroborates.")
            if trusted:
                eff_sev = SEVERITY_DOWNSHIFT.get(eff_sev, eff_sev)
                note = (note or "") + " [Whitelist reduction applied — trusted domain.]"
            detections.append({
                "type": "OBFUSCATED_JS", "severity": eff_sev,
                "label": label, "occurrences": len(matches), "context_note": note,
            })

        iframe_tags  = re.findall(r"<iframe[^>]*>", source, re.IGNORECASE)
        iframe_count = len(iframe_tags)
        for tag in iframe_tags:
            tl = tag.lower()
            if any(s in tl for s in [
                "display:none","display: none","visibility:hidden","visibility: hidden",
                'width="0"','height="0"',"width:0","height:0",'width="1"','height="1"',
            ]):
                hidden_iframe_count += 1
                detections.append({
                    "type": "HIDDEN_IFRAME",
                    "severity": "MEDIUM" if trusted else "CRITICAL",
                    "label": "Concealed iframe — potential clickjacking or drive-by vector",
                    "occurrences": 1,
                    "context_note": "[Whitelist reduction applied.]" if trusted else None,
                })

        if re.search(r'content-disposition\s*:\s*attachment', source, re.IGNORECASE):
            auto_download = True
            detections.append({
                "type":"AUTO_DOWNLOAD","severity":"HIGH",
                "label":"Content-Disposition: attachment in inline markup",
                "occurrences":1,"context_note":None,
            })

        if re.search(r'<meta[^>]+http-equiv=["\']?refresh', source, re.IGNORECASE):
            detections.append({
                "type":"META_REFRESH","severity":"LOW" if trusted else "MEDIUM",
                "label":"Meta-refresh redirect tag","occurrences":1,
                "context_note":"[Whitelist reduction applied.]" if trusted else None,
            })

    except requests.exceptions.RequestException as exc:
        detections.append({
            "type":"FETCH_ERROR","severity":"HIGH",
            "label":f"HTML retrieval failure: {str(exc)[:200]}",
            "occurrences":0,"context_note":None,
        })

    critical = sum(1 for d in detections if d["severity"] == "CRITICAL")
    high     = sum(1 for d in detections if d["severity"] == "HIGH")
    medium   = sum(1 for d in detections if d["severity"] == "MEDIUM")
    raw_score = min(100, critical*35 + high*20 + medium*8 + len(detections)*2)
    threat_score = round(raw_score * 0.5) if trusted else raw_score

    return {
        "detections":          detections,
        "iframe_count":        iframe_count,
        "hidden_iframe_count": hidden_iframe_count,
        "auto_download":       auto_download,
        "raw_size_bytes":      raw_size_bytes,
        "minified_source":     minified,
        "trusted_domain":      trusted,
        "threat_score":        threat_score,
        "detection_count":     len(detections),
    }


# ──────────────────────────────────────────────
# Module 4 — VirusTotal V3
# ──────────────────────────────────────────────

def query_virustotal(url: str) -> dict:
    _stub = {"malicious": 0, "suspicious": 0}

    if not VIRUSTOTAL_API_KEY:
        return {**_stub, "error": "VIRUSTOTAL_API_KEY not configured.", "available": False}

    vt_headers = {
        "x-apikey": VIRUSTOTAL_API_KEY,
        "Content-Type": "application/x-www-form-urlencoded",
    }

    try:
        sub = requests.post(
            VT_SCAN_ENDPOINT, headers=vt_headers,
            data={"url": url}, timeout=REQUEST_TIMEOUT,
        )
        if sub.status_code == 429:
            return {**_stub, "error": "VT rate limit. Retry in 60 s.", "available": True}
        if sub.status_code not in (200, 201):
            return {**_stub, "error": f"VT HTTP {sub.status_code}.", "available": True}

        analysis_id = sub.json().get("data", {}).get("id", "")
        if not analysis_id:
            return {**_stub, "error": "VT returned no analysis ID.", "available": True}

        analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        result_data  = {}
        for attempt in range(3):
            time.sleep(4 + attempt * 3)
            r = requests.get(
                analysis_url, headers={"x-apikey": VIRUSTOTAL_API_KEY},
                timeout=REQUEST_TIMEOUT,
            )
            if r.status_code == 200:
                result_data = r.json()
                if result_data.get("data",{}).get("attributes",{}).get("status") == "completed":
                    break

        attrs   = result_data.get("data", {}).get("attributes", {})
        stats   = attrs.get("stats", {})
        results = attrs.get("results", {})

        malicious  = stats.get("malicious",  0)
        suspicious = stats.get("suspicious", 0)
        harmless   = stats.get("harmless",   0)
        undetected = stats.get("undetected", 0)
        total      = malicious + suspicious + harmless + undetected

        flagged = [
            {"engine": e, "category": d.get("category"), "result": d.get("result")}
            for e, d in results.items()
            if d.get("category") in ("malicious", "suspicious")
        ]

        verdict = "CLEAN"
        if malicious > 3:
            verdict = "MALICIOUS"
        elif malicious > 0 or suspicious > 2:
            verdict = "SUSPICIOUS"

        return {
            "available":      True,
            "verdict":        verdict,
            "malicious":      malicious,
            "suspicious":     suspicious,
            "harmless":       harmless,
            "undetected":     undetected,
            "total_engines":  total,
            "flagged_engines": flagged[:12],
            "analysis_id":    analysis_id,
        }

    except requests.exceptions.Timeout:
        return {**_stub, "error": "VT request timed out.", "available": True}
    except requests.exceptions.RequestException as exc:
        return {**_stub, "error": f"VT connectivity failure: {str(exc)[:200]}", "available": True}


# ──────────────────────────────────────────────
# Module 5 — Wayback Machine Safe Preview
# ──────────────────────────────────────────────

def capture_safe_preview(url: str, trusted_logo: str | None = None) -> dict:
    """
    Query the Wayback Machine Availability API for the closest archived snapshot
    of the target URL. Zero cost, zero API key, zero direct browser contact.

    Flow:
      1. GET https://archive.org/wayback/available?url={url}
      2. If archived_snapshots.closest exists → return the snapshot URL for iframe display
      3. If no snapshot → attempt a background Save Page Now (SPN) submission
         so the page will be archived for future scans (best-effort, not awaited)
      4. All failure modes degrade gracefully to NO_SNAPSHOT placeholder

    Returns:
      {
        "mode":          "ARCHIVED" | "NO_SNAPSHOT" | "ARCHIVE_ERROR",
        "archive_url":   str | None,   ← Wayback viewer URL for the iframe
        "snapshot_ts":   str | None,   ← e.g. "20240315142233"
        "trust_logo_url": str | None,  ← for trusted-domain logo placeholder
        "available":     bool,
        "error":         str | None,
      }
    """
    _base = {
        "available":      False,
        "mode":           "ARCHIVE_ERROR",
        "archive_url":    None,
        "snapshot_ts":    None,
        "trust_logo_url": trusted_logo,
        "error":          None,
    }

    # ── Step 1: Query availability ──────────────────────────────────────
    try:
        avail_resp = requests.get(
            WAYBACK_AVAILABILITY_API,
            params={"url": url},
            timeout=REQUEST_TIMEOUT,
            headers={"User-Agent": "CyberScan-Sentinel/2.4"},
        )
    except requests.exceptions.Timeout:
        return {**_base, "error": "Wayback Machine availability check timed out."}
    except requests.exceptions.RequestException as exc:
        return {**_base, "error": f"Wayback Machine unreachable: {str(exc)[:200]}"}

    if avail_resp.status_code != 200:
        return {
            **_base,
            "error": f"Wayback API returned HTTP {avail_resp.status_code}.",
        }

    # ── Step 2: Parse the availability response ──────────────────────────
    try:
        data      = avail_resp.json()
        snapshots = data.get("archived_snapshots", {})
        closest   = snapshots.get("closest", {})
    except ValueError:
        return {**_base, "error": "Wayback API response was not valid JSON."}

    # ── Step 3a: Snapshot found ──────────────────────────────────────────
    if closest.get("available") and closest.get("url"):
        raw_archive_url = closest["url"]
        timestamp       = closest.get("timestamp", "")
        status_code     = closest.get("status", "")

        # Force HTTPS on the archive URL — archive.org serves both
        archive_url = raw_archive_url.replace("http://web.archive.org", "https://web.archive.org", 1)

        # Annotate if the snapshot is stale (older than 180 days)
        stale = False
        staleness_note = None
        if timestamp and len(timestamp) >= 8:
            try:
                snap_time  = time.strptime(timestamp[:8], "%Y%m%d")
                age_days   = (time.time() - time.mktime(snap_time)) / 86400
                if age_days > 180:
                    stale = True
                    staleness_note = (
                        f"Snapshot is {int(age_days)} days old — "
                        "page content may have changed since archival."
                    )
            except Exception:
                pass

        # Human-readable timestamp: "20240315142233" → "2024-03-15 14:22:33 UTC"
        readable_ts = timestamp
        if len(timestamp) >= 14:
            readable_ts = (
                f"{timestamp[:4]}-{timestamp[4:6]}-{timestamp[6:8]} "
                f"{timestamp[8:10]}:{timestamp[10:12]}:{timestamp[12:14]} UTC"
            )

        return {
            "available":      True,
            "mode":           "ARCHIVED",
            "archive_url":    archive_url,
            "snapshot_ts":    readable_ts,
            "snapshot_status": status_code,
            "stale":          stale,
            "staleness_note": staleness_note,
            "trust_logo_url": None,  # logo placeholder not needed when we have a real preview
            "error":          None,
        }

    # ── Step 3b: No snapshot — attempt Save Page Now (fire-and-forget) ───
    # SPN is best-effort: we submit the request but do NOT wait for it to complete,
    # as it can take 10–60 s. We just inform the user that archival was triggered.
    spn_triggered = False
    try:
        # SPN endpoint: POST or GET to https://web.archive.org/save/{url}
        # Use a short timeout — we don't need the response body
        spn_resp = requests.get(
            f"{WAYBACK_SAVE_API}{url}",
            timeout=5,
            headers={"User-Agent": "CyberScan-Sentinel/2.4"},
            allow_redirects=False,
        )
        # A 200, 302, or 523 all indicate the request was received by SPN
        if spn_resp.status_code in (200, 302, 302, 523):
            spn_triggered = True
    except Exception:
        # SPN failure is silent — it's supplementary, not blocking
        pass

    return {
        "available":      True,
        "mode":           "NO_SNAPSHOT",
        "archive_url":    None,
        "snapshot_ts":    None,
        "trust_logo_url": trusted_logo,
        "spn_triggered":  spn_triggered,
        "error": (
            "No archived snapshot found for this URL. "
            + ("A Save Page Now request was submitted — check back later."
               if spn_triggered else
               "Save Page Now submission also failed or was skipped.")
        ),
    }


# ──────────────────────────────────────────────
# Composite Risk Scoring v2.3
# ──────────────────────────────────────────────

def compute_composite_risk(
    vt: dict,
    headers: dict,
    html_analysis: dict,
    redirect: dict,
    trusted: bool,
) -> dict:
    """
    Weighted 70/30 model with three escalation rules:

      Rule A — VT Clean Cap:   VT 0 detections → total capped at 15
      Rule B — Trusted Cap:    Trusted domain   → total capped at 20
      Rule C — Redirect Cap:   Chain hit 5-hop limit → redirect component forced
                               to 15 pts (from max 5), floor of 60 if no VT data
                               A 5-hop chain is almost never legitimate.

    Scoring for the bit.ly question:
      We ALWAYS score the FINAL DESTINATION URL (after redirect resolution).
      The shortener itself is flagged as a routing annotation in redirect_chain,
      but it does not inflate the VT or HTML score — those run against final_url.
    """

    # ── VT (0–70) ────────────────────────────────────────────────────────
    vt_pts   = 0.0
    vt_clean = False
    if vt.get("available") and not vt.get("error"):
        mal = vt.get("malicious",  0)
        sus = vt.get("suspicious", 0)
        if mal == 0 and sus == 0:
            vt_clean = True
        vt_pts = min(70.0, mal * 7.0 + sus * 3.0)

    # ── Header (0–10) ────────────────────────────────────────────────────
    missing       = headers.get("missing_headers", 0)
    crit_absent   = headers.get("critical_absent", 0)
    header_pts    = min(10.0, missing * 1.5 + crit_absent * 1.0)

    # ── HTML (0–15) — already trust/minified-adjusted ───────────────────
    html_pts = min(15.0, html_analysis.get("threat_score", 0) * 0.15)

    # ── Redirect (0–5, or 15 if cap hit) ────────────────────────────────
    redirect_pts = 0.0
    cap_hit      = redirect.get("cap_hit", False)
    if cap_hit:
        # 5-hop cap reached: this is a severe routing anomaly — force max redirect pts
        redirect_pts = 15.0
    elif redirect.get("cross_domain_redirect"):
        redirect_pts = min(5.0, redirect.get("suspicious_hop_count", 0) * 1.5 + 1.0)

    total = vt_pts + header_pts + html_pts + redirect_pts

    # Hard caps
    if vt_clean:
        total = min(15.0, total)
    if trusted:
        total = min(20.0, total)

    # Cap-hit floor: if chain hit 5 hops and no VT data to override, floor at 60
    if cap_hit and not vt_clean and vt_pts == 0 and not vt.get("available"):
        total = max(total, 60.0)

    score = round(min(100.0, total))

    if score >= 70:
        severity       = "CRITICAL"
        recommendation = "Do not proceed. Isolate and report this URL. Initiate IOC extraction immediately."
    elif score >= 45:
        severity       = "HIGH"
        recommendation = "Treat as hostile until proven otherwise. Forensic investigation required."
    elif score >= 20:
        severity       = "MEDIUM"
        recommendation = "Elevated indicators present. Corroborate with additional OSINT before any interaction."
    else:
        severity       = "LOW"
        recommendation = "No significant threat indicators detected. Routine monitoring recommended."

    # Human-readable verdict label (the "SHIELD: VERIFIED" / "BREACH LIKELY" concept)
    verdict_labels = {
        "CRITICAL": "BREACH LIKELY",
        "HIGH":     "THREAT DETECTED",
        "MEDIUM":   "ELEVATED RISK",
        "LOW":      "SHIELD: VERIFIED",
    }
    verdict_label = verdict_labels[severity]

    return {
        "composite_score":  score,
        "severity":         severity,
        "verdict_label":    verdict_label,
        "recommendation":   recommendation,
        "score_breakdown": {
            "virustotal_pts":             round(vt_pts, 1),
            "header_pts":                 round(header_pts, 1),
            "html_pts":                   round(html_pts, 1),
            "redirect_pts":               round(redirect_pts, 1),
            "vt_clean_cap_applied":       vt_clean,
            "trusted_domain_cap_applied": trusted,
            "redirect_cap_hit":           cap_hit,
        },
    }


# ──────────────────────────────────────────────
# Routes
# ──────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/scan", methods=["POST"])
def scan():
    body    = request.get_json(silent=True) or {}
    raw_url = body.get("url", "").strip()

    if not raw_url:
        return jsonify({"error": "No URL submitted for analysis."}), 400

    url = normalize_url(raw_url)
    if not is_valid_url(url):
        return jsonify({"error": "Malformed URL. Provide a valid HTTP/HTTPS target."}), 400

    # Pre-classify before any network calls
    trusted       = is_trusted(url)
    via_shortener = is_shortener(url)

    # Always resolve the chain first — the rest of analysis targets FINAL_URL
    redirect_data = trace_redirect_chain(url)
    final_url     = redirect_data["final_url"]

    # Re-evaluate trust against resolved destination (bit.ly → drive.google.com case)
    trusted_final = trusted or is_trusted(final_url)
    trust_logo    = get_trust_logo(final_url) or get_trust_logo(url)

    # All intelligence modules run against the FINAL destination, not the shortener
    header_data = audit_response_headers(final_url)
    html_data   = analyze_html_payload(final_url, trusted=trusted_final)
    vt_data     = query_virustotal(final_url)          # ← final_url, not url
    screenshot  = capture_safe_preview(final_url, trusted_logo=trust_logo)
    risk        = compute_composite_risk(
        vt_data, header_data, html_data, redirect_data, trusted=trusted_final
    )

    return jsonify({
        "target_url":     url,
        "final_url":      final_url,
        "trusted_domain": trusted_final,
        "via_shortener":  via_shortener,
        "risk":           risk,
        "virustotal":     vt_data,
        "redirect_chain": redirect_data,
        "header_audit":   header_data,
        "html_analysis":  html_data,
        "safe_preview":   screenshot,
        "scan_timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }), 200


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({
        "status":                "operational",
        "version":               "2.4",
        "virustotal_configured": bool(VIRUSTOTAL_API_KEY),
        "wayback_preview":       True,   # always available — no API key required
    }), 200


if __name__ == "__main__":
    port  = int(os.getenv("PORT", 5000))
    debug = os.getenv("FLASK_ENV", "production") == "development"
    app.run(host="0.0.0.0", port=port, debug=debug)
