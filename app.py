"""
CyberScan Sentinel — Production-Grade URL Security Scanner
Flask backend with VirusTotal V3, redirect chain analysis,
heuristic header inspection, and static HTML payload detection.
"""

import os
import re
import time
import html
import json
import requests
from urllib.parse import urlparse, urljoin
from flask import Flask, request, jsonify, render_template
from dotenv import load_dotenv

# ──────────────────────────────────────────────
# Bootstrap
# ──────────────────────────────────────────────
load_dotenv()

app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False

VIRUSTOTAL_API_KEY    = os.getenv("VIRUSTOTAL_API_KEY", "")
SCREENSHOT_API_KEY    = os.getenv("SCREENSHOT_API_KEY", "")
REQUEST_TIMEOUT       = int(os.getenv("REQUEST_TIMEOUT", "10"))
MAX_REDIRECT_HOPS     = int(os.getenv("MAX_REDIRECT_HOPS", "10"))

VT_SCAN_ENDPOINT      = "https://www.virustotal.com/api/v3/urls"
SCREENSHOT_ENDPOINT   = "https://shot.screenshotapi.net/screenshot"

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]

OBFUSCATION_PATTERNS = [
    (r"eval\s*\(", "eval() execution detected"),
    (r"document\.write\s*\(", "document.write() injection risk"),
    (r"unescape\s*\(", "unescape() obfuscation pattern"),
    (r"String\.fromCharCode\s*\(", "CharCode-based string obfuscation"),
    (r"atob\s*\(", "Base64 decode pattern (atob)"),
    (r"\\x[0-9a-fA-F]{2}", "Hex-encoded string literals"),
    (r"\\u[0-9a-fA-F]{4}", "Unicode escape obfuscation"),
    (r"setTimeout\s*\(\s*['\"]", "setTimeout string-eval payload"),
    (r"setInterval\s*\(\s*['\"]", "setInterval string-eval payload"),
]


# ──────────────────────────────────────────────
# Utilities
# ──────────────────────────────────────────────

def normalize_url(raw: str) -> str:
    """Ensure the URL carries an explicit scheme."""
    raw = raw.strip()
    if not raw.startswith(("http://", "https://")):
        raw = "https://" + raw
    return raw


def is_valid_url(url: str) -> bool:
    """Basic structural validation of a URL."""
    try:
        result = urlparse(url)
        return all([result.scheme in ("http", "https"), result.netloc])
    except Exception:
        return False


# ──────────────────────────────────────────────
# Module 1 — Redirect Chain Analysis
# ──────────────────────────────────────────────

def trace_redirect_chain(url: str) -> dict:
    """
    Follow HTTP redirects manually to record every hop,
    status code, and the final resolved destination.
    """
    chain = []
    current_url = url
    session = requests.Session()
    session.max_redirects = 0  # Disable auto-follow; we handle it manually

    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        )
    }

    for hop in range(MAX_REDIRECT_HOPS):
        try:
            resp = session.get(
                current_url,
                headers=headers,
                allow_redirects=False,
                timeout=REQUEST_TIMEOUT,
                verify=True,
            )
        except requests.exceptions.SSLError as exc:
            chain.append({
                "hop": hop + 1,
                "url": current_url,
                "status_code": None,
                "error": f"SSL/TLS handshake failure: {str(exc)[:120]}",
            })
            break
        except requests.exceptions.ConnectionError as exc:
            chain.append({
                "hop": hop + 1,
                "url": current_url,
                "status_code": None,
                "error": f"Connection refused or DNS resolution failure: {str(exc)[:120]}",
            })
            break
        except requests.exceptions.Timeout:
            chain.append({
                "hop": hop + 1,
                "url": current_url,
                "status_code": None,
                "error": "Request timed out.",
            })
            break

        chain.append({
            "hop": hop + 1,
            "url": current_url,
            "status_code": resp.status_code,
            "error": None,
        })

        if resp.status_code in (301, 302, 303, 307, 308):
            location = resp.headers.get("Location", "").strip()
            if not location:
                break
            # Resolve relative redirects
            current_url = urljoin(current_url, location)
        else:
            break  # Final destination reached

    final_url = chain[-1]["url"] if chain else url
    cross_domain = urlparse(url).netloc != urlparse(final_url).netloc

    return {
        "chain": chain,
        "hop_count": len(chain),
        "final_url": final_url,
        "cross_domain_redirect": cross_domain,
    }


# ──────────────────────────────────────────────
# Module 2 — HTTP Header Security Audit
# ──────────────────────────────────────────────

def audit_response_headers(url: str) -> dict:
    """
    Perform a HEAD request to the target and evaluate
    the presence and configuration of security-critical headers.
    """
    findings = []
    raw_headers = {}
    server_info = None
    https_enforced = url.startswith("https://")

    try:
        resp = requests.head(
            url,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True,
            headers={"User-Agent": "CyberScan-Sentinel/1.0"},
            verify=True,
        )
        raw_headers = dict(resp.headers)
        server_info = resp.headers.get("Server", "Not Disclosed")

        for header in SECURITY_HEADERS:
            if header.lower() not in {k.lower() for k in resp.headers}:
                findings.append({
                    "header": header,
                    "status": "ABSENT",
                    "severity": "MEDIUM",
                    "description": f"Security header '{header}' is not present.",
                })
            else:
                findings.append({
                    "header": header,
                    "status": "PRESENT",
                    "severity": "INFO",
                    "description": f"Header value: {resp.headers.get(header, '')}",
                })

        # Flag verbose server disclosure
        if server_info and server_info != "Not Disclosed":
            findings.append({
                "header": "Server",
                "status": "DISCLOSURE",
                "severity": "LOW",
                "description": f"Server software version disclosed: {server_info}",
            })

    except requests.exceptions.RequestException as exc:
        findings.append({
            "header": "N/A",
            "status": "ERROR",
            "severity": "HIGH",
            "description": f"Header retrieval failed: {str(exc)[:200]}",
        })

    absent_count = sum(1 for f in findings if f["status"] == "ABSENT")
    risk_level = "LOW"
    if absent_count >= 4:
        risk_level = "HIGH"
    elif absent_count >= 2:
        risk_level = "MEDIUM"

    return {
        "findings": findings,
        "server": server_info,
        "https_enforced": https_enforced,
        "missing_headers": absent_count,
        "risk_level": risk_level,
        "raw_headers": raw_headers,
    }


# ──────────────────────────────────────────────
# Module 3 — Static HTML Payload Analysis
# ──────────────────────────────────────────────

def analyze_html_payload(url: str) -> dict:
    """
    Fetch and statically analyze the target's HTML source for
    obfuscated JavaScript, hidden iframes, and drive-by download vectors.
    """
    detections = []
    iframe_count = 0
    hidden_iframe_count = 0
    auto_download_detected = False
    raw_size_bytes = 0

    try:
        resp = requests.get(
            url,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True,
            headers={"User-Agent": "CyberScan-Sentinel/1.0"},
            verify=True,
            stream=True,
        )
        # Cap download at 2 MB to prevent memory exhaustion
        content_chunks = []
        downloaded = 0
        for chunk in resp.iter_content(chunk_size=8192):
            content_chunks.append(chunk)
            downloaded += len(chunk)
            if downloaded > 2 * 1024 * 1024:
                break

        raw_bytes = b"".join(content_chunks)
        raw_size_bytes = len(raw_bytes)

        try:
            source = raw_bytes.decode("utf-8", errors="replace")
        except Exception:
            source = raw_bytes.decode("latin-1", errors="replace")

        # Obfuscated JS pattern matching
        for pattern, label in OBFUSCATION_PATTERNS:
            matches = re.findall(pattern, source)
            if matches:
                detections.append({
                    "type": "OBFUSCATED_JS",
                    "severity": "HIGH",
                    "label": label,
                    "occurrences": len(matches),
                })

        # Hidden iframe detection
        iframe_matches = re.findall(
            r"<iframe[^>]*>",
            source,
            re.IGNORECASE,
        )
        iframe_count = len(iframe_matches)
        for tag in iframe_matches:
            tag_lower = tag.lower()
            if any(s in tag_lower for s in [
                "display:none", "display: none",
                "visibility:hidden", "visibility: hidden",
                'width="0"', 'height="0"',
                "width:0", "height:0",
            ]):
                hidden_iframe_count += 1
                detections.append({
                    "type": "HIDDEN_IFRAME",
                    "severity": "CRITICAL",
                    "label": "Concealed iframe — possible clickjacking or drive-by payload",
                    "occurrences": 1,
                })

        # Auto-download vectors
        if re.search(r'content-disposition\s*:\s*attachment', source, re.IGNORECASE):
            auto_download_detected = True
            detections.append({
                "type": "AUTO_DOWNLOAD",
                "severity": "HIGH",
                "label": "Content-Disposition: attachment detected in inline markup",
                "occurrences": 1,
            })
        if re.search(r'<meta[^>]+http-equiv=["\']?refresh', source, re.IGNORECASE):
            detections.append({
                "type": "META_REFRESH",
                "severity": "MEDIUM",
                "label": "Meta-refresh redirect tag detected",
                "occurrences": 1,
            })

    except requests.exceptions.RequestException as exc:
        detections.append({
            "type": "FETCH_ERROR",
            "severity": "HIGH",
            "label": f"HTML retrieval failed: {str(exc)[:200]}",
            "occurrences": 0,
        })

    critical = sum(1 for d in detections if d["severity"] == "CRITICAL")
    high = sum(1 for d in detections if d["severity"] == "HIGH")
    threat_score = min(100, critical * 35 + high * 20 + len(detections) * 5)

    return {
        "detections": detections,
        "iframe_count": iframe_count,
        "hidden_iframe_count": hidden_iframe_count,
        "auto_download_detected": auto_download_detected,
        "raw_size_bytes": raw_size_bytes,
        "threat_score": threat_score,
        "detection_count": len(detections),
    }


# ──────────────────────────────────────────────
# Module 4 — VirusTotal V3 Threat Intelligence
# ──────────────────────────────────────────────

def query_virustotal(url: str) -> dict:
    """
    Submit the target URL to VirusTotal V3 and retrieve
    the full engine verdict report.
    """
    if not VIRUSTOTAL_API_KEY:
        return {
            "error": "VIRUSTOTAL_API_KEY environment variable is not configured.",
            "available": False,
        }

    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY,
        "Content-Type": "application/x-www-form-urlencoded",
    }

    try:
        # Step 1: Submit URL for analysis
        submit_resp = requests.post(
            VT_SCAN_ENDPOINT,
            headers=headers,
            data={"url": url},
            timeout=REQUEST_TIMEOUT,
        )

        if submit_resp.status_code == 429:
            return {
                "error": "VirusTotal API rate limit exceeded. Retry after 60 seconds.",
                "available": True,
            }
        if submit_resp.status_code not in (200, 201):
            return {
                "error": f"VirusTotal submission failed: HTTP {submit_resp.status_code}",
                "available": True,
            }

        analysis_id = submit_resp.json().get("data", {}).get("id", "")
        if not analysis_id:
            return {"error": "VirusTotal returned no analysis ID.", "available": True}

        # Step 2: Poll for results (max 3 attempts with backoff)
        analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        result_data = {}
        for attempt in range(3):
            time.sleep(3 + attempt * 2)
            result_resp = requests.get(
                analysis_url,
                headers={"x-apikey": VIRUSTOTAL_API_KEY},
                timeout=REQUEST_TIMEOUT,
            )
            if result_resp.status_code == 200:
                result_data = result_resp.json()
                status = result_data.get("data", {}).get("attributes", {}).get("status", "")
                if status == "completed":
                    break

        attributes = result_data.get("data", {}).get("attributes", {})
        stats = attributes.get("stats", {})
        results = attributes.get("results", {})

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        total_engines = malicious + suspicious + harmless + undetected

        # Collect flagging engines
        flagged_engines = [
            {"engine": engine, "category": data.get("category"), "result": data.get("result")}
            for engine, data in results.items()
            if data.get("category") in ("malicious", "suspicious")
        ]

        verdict = "CLEAN"
        if malicious > 3:
            verdict = "MALICIOUS"
        elif malicious > 0 or suspicious > 2:
            verdict = "SUSPICIOUS"

        return {
            "available": True,
            "verdict": verdict,
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected,
            "total_engines": total_engines,
            "flagged_engines": flagged_engines[:10],  # Cap for response size
            "analysis_id": analysis_id,
        }

    except requests.exceptions.Timeout:
        return {"error": "VirusTotal API request timed out.", "available": True}
    except requests.exceptions.RequestException as exc:
        return {"error": f"VirusTotal connectivity failure: {str(exc)[:200]}", "available": True}


# ──────────────────────────────────────────────
# Module 5 — Safe-View Screenshot Sandbox
# ──────────────────────────────────────────────

def capture_safe_preview(url: str) -> dict:
    """
    Delegate rendering to a third-party Screenshot API,
    ensuring zero direct browser contact with the target URL.
    """
    if not SCREENSHOT_API_KEY:
        return {
            "available": False,
            "error": "SCREENSHOT_API_KEY environment variable is not configured.",
        }

    try:
        params = {
            "token": SCREENSHOT_API_KEY,
            "url": url,
            "output": "json",
            "width": "1280",
            "height": "800",
            "full_page": "false",
            "fresh": "true",
            "block_ads": "true",
            "no_cookie_banners": "true",
            "delay": "2",
        }

        resp = requests.get(
            SCREENSHOT_ENDPOINT,
            params=params,
            timeout=30,
        )

        if resp.status_code == 200:
            data = resp.json()
            screenshot_url = data.get("screenshot")
            return {
                "available": True,
                "screenshot_url": screenshot_url,
                "error": None,
            }
        else:
            return {
                "available": True,
                "screenshot_url": None,
                "error": f"Screenshot API returned HTTP {resp.status_code}",
            }

    except requests.exceptions.Timeout:
        return {
            "available": True,
            "screenshot_url": None,
            "error": "Screenshot API request timed out.",
        }
    except requests.exceptions.RequestException as exc:
        return {
            "available": True,
            "screenshot_url": None,
            "error": f"Screenshot API connectivity failure: {str(exc)[:200]}",
        }


# ──────────────────────────────────────────────
# Composite Risk Scoring
# ──────────────────────────────────────────────

def compute_composite_risk(vt: dict, headers: dict, html_analysis: dict, redirect: dict) -> dict:
    """
    Aggregate sub-module findings into a single threat severity rating.
    """
    score = 0

    # VirusTotal contribution (0–40 pts)
    if vt.get("available") and not vt.get("error"):
        malicious = vt.get("malicious", 0)
        suspicious = vt.get("suspicious", 0)
        score += min(40, malicious * 8 + suspicious * 4)

    # Header audit contribution (0–20 pts)
    missing = headers.get("missing_headers", 0)
    score += min(20, missing * 4)

    # HTML payload contribution (0–30 pts)
    score += min(30, html_analysis.get("threat_score", 0) * 0.3)

    # Redirect chain contribution (0–10 pts)
    hops = redirect.get("hop_count", 1)
    if redirect.get("cross_domain_redirect"):
        score += min(10, hops * 2)

    score = round(min(100, score))

    if score >= 70:
        severity = "CRITICAL"
        recommendation = "Do not proceed. Isolate and report this URL immediately."
    elif score >= 45:
        severity = "HIGH"
        recommendation = "Treat as hostile. Further forensic investigation required."
    elif score >= 20:
        severity = "MEDIUM"
        recommendation = "Exercise caution. Corroborate findings with additional OSINT."
    else:
        severity = "LOW"
        recommendation = "No significant threat indicators detected at this time."

    return {
        "composite_score": score,
        "severity": severity,
        "recommendation": recommendation,
    }


# ──────────────────────────────────────────────
# Routes
# ──────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/scan", methods=["POST"])
def scan():
    """
    Primary scan endpoint. Accepts JSON { "url": "..." } and
    returns a comprehensive threat intelligence report.
    """
    body = request.get_json(silent=True) or {}
    raw_url = body.get("url", "").strip()

    if not raw_url:
        return jsonify({"error": "No URL submitted for analysis."}), 400

    url = normalize_url(raw_url)

    if not is_valid_url(url):
        return jsonify({"error": "Malformed URL. Provide a valid HTTP/HTTPS target."}), 400

    # Execute all analysis modules
    redirect_data  = trace_redirect_chain(url)
    header_data    = audit_response_headers(redirect_data["final_url"])
    html_data      = analyze_html_payload(redirect_data["final_url"])
    vt_data        = query_virustotal(url)
    screenshot     = capture_safe_preview(redirect_data["final_url"])
    risk           = compute_composite_risk(vt_data, header_data, html_data, redirect_data)

    report = {
        "target_url": url,
        "final_url": redirect_data["final_url"],
        "risk": risk,
        "virustotal": vt_data,
        "redirect_chain": redirect_data,
        "header_audit": header_data,
        "html_analysis": html_data,
        "safe_preview": screenshot,
        "scan_timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }

    return jsonify(report), 200


@app.route("/api/health", methods=["GET"])
def health():
    """Liveness probe for Render health checks."""
    return jsonify({
        "status": "operational",
        "virustotal_configured": bool(VIRUSTOTAL_API_KEY),
        "screenshot_configured": bool(SCREENSHOT_API_KEY),
    }), 200


# ──────────────────────────────────────────────
# Entrypoint
# ──────────────────────────────────────────────

if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    debug = os.getenv("FLASK_ENV", "production") == "development"
    app.run(host="0.0.0.0", port=port, debug=debug)
