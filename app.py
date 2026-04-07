"""
CyberScan Sentinel — Refined Production Backend (v2.2)
Improvements over v2.1:
  • Weighted 70/30 VT-anchored composite scoring with whitelist cap
  • Context-aware HTML analysis (minified-library heuristics)
  • Screenshot API URL-encoding bug fixed + graceful SAFE_MODE fallback
  • Enriched header audit with 'why_it_matters' + 'recommended_value'
  • Recursive redirect chain capped at 5 hops with latency + cross-domain tagging
"""

import os
import re
import time
import requests
from urllib.parse import urlparse, urljoin, quote_plus
from flask import Flask, request, jsonify, render_template
from dotenv import load_dotenv

# ──────────────────────────────────────────────
# Bootstrap
# ──────────────────────────────────────────────
load_dotenv()

app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False

VIRUSTOTAL_API_KEY  = os.getenv("VIRUSTOTAL_API_KEY", "")
SCREENSHOT_API_KEY  = os.getenv("SCREENSHOT_API_KEY", "")
REQUEST_TIMEOUT     = int(os.getenv("REQUEST_TIMEOUT", "10"))
MAX_REDIRECT_HOPS   = int(os.getenv("MAX_REDIRECT_HOPS", "5"))  # capped at 5

VT_SCAN_ENDPOINT    = "https://www.virustotal.com/api/v3/urls"
SCREENSHOT_ENDPOINT = "https://shot.screenshotapi.net/screenshot"

# ──────────────────────────────────────────────
# Trusted-Domain Whitelist
# URLs whose apex domain matches an entry receive a reduced static-analysis
# weight and a composite score ceiling to suppress CDN/minified-JS false positives.
# ──────────────────────────────────────────────
TRUSTED_DOMAINS = {
    # Google
    "google.com", "googleapis.com", "gstatic.com", "googletagmanager.com",
    "googleanalytics.com", "youtube.com", "googlevideo.com",
    # Microsoft
    "microsoft.com", "azure.com", "live.com", "office.com",
    "microsoftonline.com", "bing.com", "msn.com",
    # Apple
    "apple.com", "icloud.com",
    # GitHub / dev tooling
    "github.com", "githubusercontent.com", "github.io", "npmjs.com",
    # CDN infrastructure
    "cloudflare.com", "cloudflare.net", "fastly.net", "akamaihd.net",
    "jquery.com", "bootstrapcdn.com", "unpkg.com", "jsdelivr.net",
    "cdnjs.cloudflare.com",
    # Major SaaS
    "stripe.com", "twilio.com", "sendgrid.com", "salesforce.com",
    "amazonaws.com", "awsstatic.com",
}

# ──────────────────────────────────────────────
# Header Metadata — analyst-grade enrichment
# ──────────────────────────────────────────────
HEADER_METADATA = {
    "Strict-Transport-Security": {
        "why": (
            "Prevents protocol-downgrade attacks and cookie hijacking by instructing "
            "browsers to communicate exclusively over HTTPS."
        ),
        "recommended": "max-age=31536000; includeSubDomains; preload",
    },
    "Content-Security-Policy": {
        "why": (
            "Mitigates XSS and data-injection attacks by whitelisting approved "
            "content sources for scripts, styles, and media."
        ),
        "recommended": "default-src 'self'; script-src 'self'; object-src 'none';",
    },
    "X-Frame-Options": {
        "why": (
            "Blocks the page from being embedded inside an iframe on a foreign domain, "
            "preventing clickjacking attacks."
        ),
        "recommended": "DENY",
    },
    "X-Content-Type-Options": {
        "why": (
            "Prevents browsers from MIME-sniffing a response away from its declared "
            "content-type, blocking drive-by-download vectors."
        ),
        "recommended": "nosniff",
    },
    "Referrer-Policy": {
        "why": (
            "Controls referrer information sent with outbound requests, limiting "
            "intelligence leakage to third-party domains."
        ),
        "recommended": "strict-origin-when-cross-origin",
    },
    "Permissions-Policy": {
        "why": (
            "Restricts which browser features (camera, mic, geolocation) the page "
            "may access, reducing attack surface from embedded iframes."
        ),
        "recommended": "geolocation=(), microphone=(), camera=()",
    },
}

# ──────────────────────────────────────────────
# Obfuscation Pattern Registry
# Each tuple: (regex, human_label, base_severity)
# ──────────────────────────────────────────────
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

# These patterns commonly appear in legitimate minified bundles; down-graded
# to LOW when a minified source is detected.
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
    """
    Extract the apex (eTLD+1) domain.
    'https://cdn.googleapis.com/...' → 'googleapis.com'
    """
    try:
        host = urlparse(url).netloc.lower().split(":")[0]
        parts = host.split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else host
    except Exception:
        return ""


def is_trusted(url: str) -> bool:
    return get_apex_domain(url) in TRUSTED_DOMAINS


def is_minified_source(source: str) -> bool:
    """
    Heuristically identify minified/bundled JavaScript.
    Signals: very few newlines relative to total length, or very long average line.
    """
    if not source:
        return False
    lines = source.splitlines()
    if not lines:
        return False
    newline_ratio = len(lines) / max(len(source), 1)
    avg_line_len  = len(source) / max(len(lines), 1)
    return newline_ratio < 0.001 or avg_line_len > 500


# ──────────────────────────────────────────────
# Module 1 — Redirect Chain Analysis (max 5 hops)
# ──────────────────────────────────────────────

def trace_redirect_chain(url: str) -> dict:
    """
    Manually follow HTTP 3xx redirects hop-by-hop (up to MAX_REDIRECT_HOPS = 5).
    Records: URL, HTTP status, server header, round-trip latency, cross-domain flag.
    """
    chain = []
    current_url  = url
    origin_apex  = get_apex_domain(url)
    session      = requests.Session()
    ua = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    )

    for hop_num in range(MAX_REDIRECT_HOPS):
        t0 = time.monotonic()
        hop = {
            "hop": hop_num + 1,
            "url": current_url,
            "status_code": None,
            "server": None,
            "latency_ms": None,
            "cross_domain": get_apex_domain(current_url) != origin_apex,
            "error": None,
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

    return {
        "chain":               chain,
        "hop_count":           len(chain),
        "final_url":           final_url,
        "cross_domain_redirect": cross_domain_final,
        "suspicious_hop_count":  suspicious_hop_count,
    }


# ──────────────────────────────────────────────
# Module 2 — HTTP Header Security Audit (enriched)
# ──────────────────────────────────────────────

def audit_response_headers(url: str) -> dict:
    """
    HEAD request + security header evaluation.
    Each finding now carries 'why_it_matters' and 'recommended_value'
    for analyst-grade remediation guidance.
    """
    findings       = []
    raw_headers    = {}
    server_info    = None
    https_enforced = url.startswith("https://")

    try:
        resp = requests.head(
            url,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True,
            headers={"User-Agent": "CyberScan-Sentinel/2.2"},
            verify=True,
        )
        raw_headers    = dict(resp.headers)
        server_info    = resp.headers.get("Server", "Not Disclosed")
        present_lower  = {k.lower() for k in resp.headers}

        for header, meta in HEADER_METADATA.items():
            if header.lower() not in present_lower:
                findings.append({
                    "header":           header,
                    "status":           "ABSENT",
                    "severity":         "MEDIUM",
                    "current_value":    None,
                    "why_it_matters":   meta["why"],
                    "recommended_value": meta["recommended"],
                })
            else:
                findings.append({
                    "header":           header,
                    "status":           "PRESENT",
                    "severity":         "INFO",
                    "current_value":    resp.headers.get(header, ""),
                    "why_it_matters":   meta["why"],
                    "recommended_value": meta["recommended"],
                })

        if server_info and server_info != "Not Disclosed":
            findings.append({
                "header":           "Server",
                "status":           "DISCLOSURE",
                "severity":         "LOW",
                "current_value":    server_info,
                "why_it_matters":   (
                    "Disclosing server software and version gives attackers a precise "
                    "target for known CVE exploitation."
                ),
                "recommended_value": "Remove or suppress the Server header entirely.",
            })

        if not https_enforced:
            findings.append({
                "header":           "Transport",
                "status":           "INSECURE",
                "severity":         "HIGH",
                "current_value":    "http://",
                "why_it_matters":   "HTTP transmits all data in plaintext, enabling trivial MITM interception.",
                "recommended_value": "Migrate to HTTPS and 301-redirect all HTTP traffic.",
            })

    except requests.exceptions.RequestException as exc:
        findings.append({
            "header":           "N/A",
            "status":           "ERROR",
            "severity":         "HIGH",
            "current_value":    None,
            "why_it_matters":   "Audit could not complete due to a network-level failure.",
            "recommended_value": str(exc)[:200],
        })

    absent_count = sum(1 for f in findings if f["status"] == "ABSENT")
    risk_level   = "LOW" if absent_count < 2 else ("MEDIUM" if absent_count < 4 else "HIGH")

    return {
        "findings":        findings,
        "server":          server_info,
        "https_enforced":  https_enforced,
        "missing_headers": absent_count,
        "risk_level":      risk_level,
        "raw_headers":     raw_headers,
    }


# ──────────────────────────────────────────────
# Module 3 — Static HTML Payload Analysis (context-aware)
# ──────────────────────────────────────────────

def analyze_html_payload(url: str, trusted: bool = False) -> dict:
    """
    Fetch and statically analyze HTML source.

    Context-awareness layers:
      1. Minified source → low-signal patterns reclassified to LOW with explanatory note
      2. Trusted domain  → all severities down-shifted one tier; threat_score halved
    """
    detections          = []
    iframe_count        = 0
    hidden_iframe_count = 0
    auto_download       = False
    raw_size_bytes      = 0
    minified            = False

    SEVERITY_DOWNSHIFT = {
        "CRITICAL": "HIGH",
        "HIGH":     "MEDIUM",
        "MEDIUM":   "LOW",
        "LOW":      "INFO",
    }

    try:
        resp = requests.get(
            url,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True,
            headers={"User-Agent": "CyberScan-Sentinel/2.2"},
            verify=True,
            stream=True,
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

        # ── Obfuscation patterns ─────────────────────────────────────────
        for pattern, label, base_sev in OBFUSCATION_PATTERNS:
            matches = re.findall(pattern, source)
            if not matches:
                continue

            eff_sev = base_sev
            note    = None

            # Minification context: low-signal patterns are common in jQuery/React
            if minified and pattern in MINIFIED_SAFE_PATTERNS:
                eff_sev = "LOW"
                note = (
                    "Detected inside a large minified bundle. "
                    "Pattern is common in legitimate library code (jQuery, React, etc.). "
                    "Classify as 'Optimized Code — Low Risk' unless corroborated by VT."
                )

            # Trusted domain: down-shift severity by one tier
            if trusted:
                eff_sev = SEVERITY_DOWNSHIFT.get(eff_sev, eff_sev)
                note = (note or "") + " [Whitelist reduction applied — trusted domain.]"

            detections.append({
                "type":         "OBFUSCATED_JS",
                "severity":     eff_sev,
                "label":        label,
                "occurrences":  len(matches),
                "context_note": note,
            })

        # ── Hidden iframes ───────────────────────────────────────────────
        iframe_tags = re.findall(r"<iframe[^>]*>", source, re.IGNORECASE)
        iframe_count = len(iframe_tags)
        for tag in iframe_tags:
            tl = tag.lower()
            if any(s in tl for s in [
                "display:none", "display: none", "visibility:hidden",
                "visibility: hidden", 'width="0"', 'height="0"',
                "width:0", "height:0", 'width="1"', 'height="1"',
            ]):
                hidden_iframe_count += 1
                sev = "MEDIUM" if trusted else "CRITICAL"
                detections.append({
                    "type":         "HIDDEN_IFRAME",
                    "severity":     sev,
                    "label":        "Concealed iframe — potential clickjacking or drive-by vector",
                    "occurrences":  1,
                    "context_note": "[Whitelist reduction applied.]" if trusted else None,
                })

        # ── Auto-download & meta-refresh ─────────────────────────────────
        if re.search(r'content-disposition\s*:\s*attachment', source, re.IGNORECASE):
            auto_download = True
            detections.append({
                "type":         "AUTO_DOWNLOAD",
                "severity":     "HIGH",
                "label":        "Content-Disposition: attachment in inline markup",
                "occurrences":  1,
                "context_note": None,
            })

        if re.search(r'<meta[^>]+http-equiv=["\']?refresh', source, re.IGNORECASE):
            sev = "LOW" if trusted else "MEDIUM"
            detections.append({
                "type":         "META_REFRESH",
                "severity":     sev,
                "label":        "Meta-refresh redirect tag detected",
                "occurrences":  1,
                "context_note": "[Whitelist reduction applied.]" if trusted else None,
            })

    except requests.exceptions.RequestException as exc:
        detections.append({
            "type":         "FETCH_ERROR",
            "severity":     "HIGH",
            "label":        f"HTML retrieval failure: {str(exc)[:200]}",
            "occurrences":  0,
            "context_note": None,
        })

    critical = sum(1 for d in detections if d["severity"] == "CRITICAL")
    high     = sum(1 for d in detections if d["severity"] == "HIGH")
    medium   = sum(1 for d in detections if d["severity"] == "MEDIUM")
    raw_score = min(100, critical * 35 + high * 20 + medium * 8 + len(detections) * 2)

    # Trusted domains: halve the static score contribution
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
# Module 4 — VirusTotal V3 Threat Intelligence
# ──────────────────────────────────────────────

def query_virustotal(url: str) -> dict:
    """
    Submit URL to VT V3, poll with exponential back-off, return engine verdicts.
    """
    _clean_stub = {"malicious": 0, "suspicious": 0}

    if not VIRUSTOTAL_API_KEY:
        return {**_clean_stub, "error": "VIRUSTOTAL_API_KEY not configured.", "available": False}

    vt_headers = {
        "x-apikey": VIRUSTOTAL_API_KEY,
        "Content-Type": "application/x-www-form-urlencoded",
    }

    try:
        sub = requests.post(VT_SCAN_ENDPOINT, headers=vt_headers, data={"url": url}, timeout=REQUEST_TIMEOUT)

        if sub.status_code == 429:
            return {**_clean_stub, "error": "VT rate limit exceeded. Retry in 60 s.", "available": True}
        if sub.status_code not in (200, 201):
            return {**_clean_stub, "error": f"VT submission HTTP {sub.status_code}.", "available": True}

        analysis_id = sub.json().get("data", {}).get("id", "")
        if not analysis_id:
            return {**_clean_stub, "error": "VT returned no analysis ID.", "available": True}

        analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        result_data  = {}
        for attempt in range(3):
            time.sleep(4 + attempt * 3)
            r = requests.get(analysis_url, headers={"x-apikey": VIRUSTOTAL_API_KEY}, timeout=REQUEST_TIMEOUT)
            if r.status_code == 200:
                result_data = r.json()
                if result_data.get("data", {}).get("attributes", {}).get("status") == "completed":
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
        return {**_clean_stub, "error": "VT request timed out.", "available": True}
    except requests.exceptions.RequestException as exc:
        return {**_clean_stub, "error": f"VT connectivity failure: {str(exc)[:200]}", "available": True}


# ──────────────────────────────────────────────
# Module 5 — Safe-View Screenshot Sandbox (v2.2 fixed)
# ──────────────────────────────────────────────

def capture_safe_preview(url: str) -> dict:
    """
    Delegate rendering to ScreenshotAPI.net.

    Fixes vs v2.1:
      • Target URL is percent-encoded via quote_plus before injection into query string
      • All non-200 responses degrade gracefully to SAFE_MODE placeholder
      • JSON parse failures caught explicitly
    """
    if not SCREENSHOT_API_KEY:
        return {"available": False, "mode": "UNCONFIGURED", "screenshot_url": None,
                "error": "SCREENSHOT_API_KEY not configured."}

    encoded_target = quote_plus(url)
    request_url = (
        f"{SCREENSHOT_ENDPOINT}"
        f"?token={SCREENSHOT_API_KEY}"
        f"&url={encoded_target}"
        f"&output=json&width=1280&height=800"
        f"&full_page=false&fresh=true&block_ads=true&no_cookie_banners=true&delay=2"
    )

    REASON_MAP = {
        400: "Malformed request — target URL may contain unsupported characters.",
        401: "Authentication failure — verify SCREENSHOT_API_KEY is valid.",
        403: "Access denied by Screenshot API.",
        404: "Screenshot API endpoint not found. Verify API documentation.",
        429: "Screenshot API rate limit reached.",
        500: "Screenshot API internal server error.",
        503: "Screenshot API temporarily unavailable.",
    }

    try:
        resp = requests.get(request_url, timeout=30)

        if resp.status_code == 200:
            try:
                data = resp.json()
                ss_url = data.get("screenshot") or data.get("url")
                if ss_url:
                    return {"available": True, "mode": "LIVE", "screenshot_url": ss_url, "error": None}
                return {"available": True, "mode": "SAFE_MODE", "screenshot_url": None,
                        "error": "API returned 200 but payload contained no screenshot URL."}
            except ValueError:
                return {"available": True, "mode": "SAFE_MODE", "screenshot_url": None,
                        "error": "API response was not valid JSON."}

        reason = REASON_MAP.get(resp.status_code, f"Unexpected HTTP {resp.status_code}.")
        return {"available": True, "mode": "SAFE_MODE", "screenshot_url": None, "error": reason}

    except requests.exceptions.Timeout:
        return {"available": True, "mode": "SAFE_MODE", "screenshot_url": None,
                "error": "Screenshot API request timed out (>30 s)."}
    except requests.exceptions.RequestException as exc:
        return {"available": True, "mode": "SAFE_MODE", "screenshot_url": None,
                "error": f"Network error: {str(exc)[:200]}"}


# ──────────────────────────────────────────────
# Composite Risk Scoring — Weighted 70 / 30
# ──────────────────────────────────────────────

def compute_composite_risk(
    vt: dict,
    headers: dict,
    html_analysis: dict,
    redirect: dict,
    trusted: bool,
) -> dict:
    """
    Weighted scoring model — designed to behave like a security analyst:

      VirusTotal   → 70 pts  (crowdsourced engine verdicts; authoritative)
      Header audit → 10 pts  (misconfiguration signal)
      HTML heuristics → 15 pts  (already trust/minified-adjusted by module 3)
      Redirect chain  →  5 pts  (supplementary routing signal)

      Hard caps:
        • VT returns 0 malicious + 0 suspicious → composite CAPPED at 15
          (suppresses false positives from static-analysis noise on clean CDN pages)
        • Trusted domain → composite CAPPED at 20 even with minor VT detections
    """

    # ── VT component (0–70) ──────────────────────────────────────────────
    vt_pts  = 0.0
    vt_clean = False
    if vt.get("available") and not vt.get("error"):
        mal = vt.get("malicious",  0)
        sus = vt.get("suspicious", 0)
        if mal == 0 and sus == 0:
            vt_clean = True
        vt_pts = min(70.0, mal * 7.0 + sus * 3.0)

    # ── Header component (0–10) ──────────────────────────────────────────
    header_pts = min(10.0, headers.get("missing_headers", 0) * 1.8)

    # ── HTML component (0–15) — threat_score is already 0–100 adjusted ──
    html_pts = min(15.0, html_analysis.get("threat_score", 0) * 0.15)

    # ── Redirect component (0–5) ─────────────────────────────────────────
    redirect_pts = 0.0
    if redirect.get("cross_domain_redirect"):
        redirect_pts = min(5.0, redirect.get("suspicious_hop_count", 0) * 1.5 + 1.0)

    total = vt_pts + header_pts + html_pts + redirect_pts

    # Hard caps
    if vt_clean:
        total = min(15.0, total)
    if trusted:
        total = min(20.0, total)

    score = round(min(100.0, total))

    if score >= 70:
        severity       = "CRITICAL"
        recommendation = "Do not proceed. Isolate and report this URL. Initiate IOC extraction immediately."
    elif score >= 45:
        severity       = "HIGH"
        recommendation = "Treat as hostile until proven otherwise. Forensic investigation required."
    elif score >= 20:
        severity       = "MEDIUM"
        recommendation = "Elevated indicators present. Corroborate with additional OSINT before any user interaction."
    else:
        severity       = "LOW"
        recommendation = "No significant threat indicators detected at this time. Routine monitoring recommended."

    return {
        "composite_score": score,
        "severity":        severity,
        "recommendation":  recommendation,
        "score_breakdown": {
            "virustotal_pts":              round(vt_pts, 1),
            "header_pts":                  round(header_pts, 1),
            "html_pts":                    round(html_pts, 1),
            "redirect_pts":                round(redirect_pts, 1),
            "vt_clean_cap_applied":        vt_clean,
            "trusted_domain_cap_applied":  trusted,
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

    trusted = is_trusted(url)

    redirect_data = trace_redirect_chain(url)
    final_url     = redirect_data["final_url"]
    trusted_final = trusted or is_trusted(final_url)

    header_data = audit_response_headers(final_url)
    html_data   = analyze_html_payload(final_url, trusted=trusted_final)
    vt_data     = query_virustotal(url)
    screenshot  = capture_safe_preview(final_url)
    risk        = compute_composite_risk(vt_data, header_data, html_data, redirect_data, trusted=trusted_final)

    return jsonify({
        "target_url":     url,
        "final_url":      final_url,
        "trusted_domain": trusted_final,
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
        "status":                  "operational",
        "version":                 "2.2",
        "virustotal_configured":   bool(VIRUSTOTAL_API_KEY),
        "screenshot_configured":   bool(SCREENSHOT_API_KEY),
    }), 200


# ──────────────────────────────────────────────
# Entrypoint
# ──────────────────────────────────────────────

if __name__ == "__main__":
    port  = int(os.getenv("PORT", 5000))
    debug = os.getenv("FLASK_ENV", "production") == "development"
    app.run(host="0.0.0.0", port=port, debug=debug)
