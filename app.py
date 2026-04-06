"""
CyberScan Sentinel – Advanced URL Intelligence & Automated Sandbox
A professional security analysis platform for URL threat detection.
"""

import os
import json
import requests
import re
from urllib.parse import urlparse, urljoin
from functools import lru_cache
from datetime import datetime

from flask import Flask, render_template, request, jsonify
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.config['JSON_SORT_KEYS'] = False

# ============================================================================
# CONFIGURATION & CONSTANTS
# ============================================================================

VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')
SCREENSHOT_API_KEY = os.getenv('SCREENSHOT_API_KEY')
SECRET_KEY = os.getenv('SECRET_KEY', 'dev-key-change-in-production')

VIRUSTOTAL_URL_ENDPOINT = "https://www.virustotal.com/api/v3/urls"
MAX_REDIRECTS = 10
REQUEST_TIMEOUT = 10
SCREENSHOT_TIMEOUT = 15

# Suspicious pattern signatures for static analysis
SUSPICIOUS_PATTERNS = {
    'obfuscated_js': [
        r'eval\s*\(',
        r'Function\s*\(',
        r'atob\s*\(',
        r'\[[\s\S]{0,20}\]\.\w+\(',
    ],
    'hidden_iframes': [
        r'<iframe[^>]*\s+hidden',
        r'<iframe[^>]*style="display:none"',
        r'<iframe[^>]*width=["\']*0',
    ],
    'auto_download': [
        r'<a[^>]*download\s*=',
        r'window\.location\s*=\s*["\']data:',
    ],
    'suspicious_scripts': [
        r'<script[^>]*src=["\']([^"\']*)?eval',
        r'document\.write\s*\(',
    ],
}

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def is_valid_url(url: str) -> tuple[bool, str]:
    """
    Validate URL format and protocol.
    Returns: (is_valid, normalized_url)
    """
    if not url or not isinstance(url, str):
        return False, ""
    
    url = url.strip()
    
    # Add protocol if missing
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    try:
        result = urlparse(url)
        if result.scheme not in ('http', 'https'):
            return False, ""
        if not result.netloc:
            return False, ""
        return True, url
    except Exception:
        return False, ""


def track_redirection_chain(url: str) -> dict:
    """
    Follow HTTP redirects and log the chain.
    Returns: {
        'chain': [...],
        'final_url': str,
        'status_code': int,
        'error': str or None
    }
    """
    chain = []
    current_url = url
    
    try:
        for hop in range(MAX_REDIRECTS):
            try:
                response = requests.head(
                    current_url,
                    allow_redirects=False,
                    timeout=REQUEST_TIMEOUT,
                    headers={
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                    }
                )
                
                chain.append({
                    'hop': hop + 1,
                    'url': current_url,
                    'status_code': response.status_code,
                    'timestamp': datetime.utcnow().isoformat()
                })
                
                # Check for redirects
                if response.status_code in (301, 302, 303, 307, 308):
                    location = response.headers.get('Location')
                    if location:
                        current_url = urljoin(current_url, location)
                    else:
                        break
                else:
                    break
                    
            except requests.exceptions.Timeout:
                return {
                    'chain': chain,
                    'final_url': current_url,
                    'status_code': None,
                    'error': f'Timeout at hop {hop + 1}'
                }
            except requests.exceptions.ConnectionError:
                return {
                    'chain': chain,
                    'final_url': current_url,
                    'status_code': None,
                    'error': f'Connection error at hop {hop + 1}'
                }
        
        return {
            'chain': chain,
            'final_url': current_url,
            'status_code': chain[-1]['status_code'] if chain else None,
            'error': None
        }
        
    except Exception as e:
        return {
            'chain': chain,
            'final_url': current_url,
            'status_code': None,
            'error': str(e)
        }


def analyze_html_for_threats(url: str) -> dict:
    """
    Perform static analysis on target HTML for malicious patterns.
    """
    findings = {
        'obfuscated_code': [],
        'hidden_iframes': [],
        'auto_download': [],
        'suspicious_scripts': [],
        'risk_score': 0,
        'error': None
    }
    
    try:
        response = requests.get(
            url,
            timeout=REQUEST_TIMEOUT,
            headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
        )
        response.raise_for_status()
        html_source = response.text.lower()
        
        # Scan for obfuscated JavaScript
        for pattern in SUSPICIOUS_PATTERNS['obfuscated_js']:
            matches = re.findall(pattern, html_source, re.IGNORECASE)
            if matches:
                findings['obfuscated_code'].extend(matches[:3])
                findings['risk_score'] += 15
        
        # Scan for hidden iframes
        for pattern in SUSPICIOUS_PATTERNS['hidden_iframes']:
            if re.search(pattern, html_source, re.IGNORECASE):
                findings['hidden_iframes'].append(pattern)
                findings['risk_score'] += 20
        
        # Scan for auto-download behaviors
        for pattern in SUSPICIOUS_PATTERNS['auto_download']:
            matches = re.findall(pattern, html_source, re.IGNORECASE)
            if matches:
                findings['auto_download'].extend(matches[:2])
                findings['risk_score'] += 25
        
        # Scan for suspicious scripts
        for pattern in SUSPICIOUS_PATTERNS['suspicious_scripts']:
            matches = re.findall(pattern, html_source, re.IGNORECASE)
            if matches:
                findings['suspicious_scripts'].extend(matches[:3])
                findings['risk_score'] += 10
        
        findings['risk_score'] = min(findings['risk_score'], 100)
        
    except requests.exceptions.Timeout:
        findings['error'] = 'HTML analysis timeout exceeded'
    except requests.exceptions.ConnectionError:
        findings['error'] = 'Unable to reach target URL for static analysis'
    except Exception as e:
        findings['error'] = f'Static analysis error: {str(e)}'
    
    return findings


def query_virustotal(url: str) -> dict:
    """
    Query VirusTotal API V3 for URL threat intelligence.
    """
    if not VIRUSTOTAL_API_KEY:
        return {
            'error': 'VirusTotal API key not configured',
            'vendors_checked': 0,
            'malicious': 0,
            'suspicious': 0,
            'harmless': 0,
            'undetected': 0
        }
    
    try:
        # Encode URL for VirusTotal
        from urllib.parse import quote
        encoded_url = quote(url, safe='')
        
        headers = {
            'x-apikey': VIRUSTOTAL_API_KEY,
            'User-Agent': 'CyberScan-Sentinel/1.0'
        }
        
        # First, submit the URL for scanning
        response = requests.post(
            VIRUSTOTAL_URL_ENDPOINT,
            headers=headers,
            data={'url': url},
            timeout=REQUEST_TIMEOUT
        )
        
        if response.status_code not in (200, 201):
            return {
                'error': f'VirusTotal API error: {response.status_code}',
                'vendors_checked': 0,
                'malicious': 0,
                'suspicious': 0,
                'harmless': 0,
                'undetected': 0
            }
        
        data = response.json()
        url_id = data['data']['id']
        
        # Retrieve analysis results
        analysis_url = f"{VIRUSTOTAL_URL_ENDPOINT}/{url_id}"
        analysis_response = requests.get(
            analysis_url,
            headers=headers,
            timeout=REQUEST_TIMEOUT
        )
        
        if analysis_response.status_code != 200:
            return {
                'error': 'Unable to retrieve VirusTotal analysis',
                'vendors_checked': 0,
                'malicious': 0,
                'suspicious': 0,
                'harmless': 0,
                'undetected': 0
            }
        
        stats = analysis_response.json()['data']['attributes']['last_analysis_stats']
        
        return {
            'error': None,
            'vendors_checked': sum(stats.values()),
            'malicious': stats.get('malicious', 0),
            'suspicious': stats.get('suspicious', 0),
            'harmless': stats.get('harmless', 0),
            'undetected': stats.get('undetected', 0)
        }
        
    except requests.exceptions.Timeout:
        return {
            'error': 'VirusTotal API timeout',
            'vendors_checked': 0,
            'malicious': 0,
            'suspicious': 0,
            'harmless': 0,
            'undetected': 0
        }
    except Exception as e:
        return {
            'error': f'VirusTotal query error: {str(e)}',
            'vendors_checked': 0,
            'malicious': 0,
            'suspicious': 0,
            'harmless': 0,
            'undetected': 0
        }


def generate_screenshot(url: str) -> dict:
    """
    Generate a sandbox screenshot using ScreenshotAPI.net
    """
    if not SCREENSHOT_API_KEY:
        return {
            'success': False,
            'error': 'Screenshot API key not configured',
            'screenshot_url': None
        }
    
    try:
        # ScreenshotAPI.net endpoint
        api_url = "https://api.screenshotapi.net/capture"
        
        params = {
            'apikey': SCREENSHOT_API_KEY,
            'url': url,
            'format': 'png',
            'width': 1366,
            'height': 768
        }
        
        response = requests.get(
            api_url,
            params=params,
            timeout=SCREENSHOT_TIMEOUT
        )
        
        if response.status_code == 200:
            screenshot_data = response.json()
            if screenshot_data.get('success'):
                return {
                    'success': True,
                    'error': None,
                    'screenshot_url': screenshot_data.get('screenshot')
                }
            else:
                return {
                    'success': False,
                    'error': screenshot_data.get('error', 'Unknown error'),
                    'screenshot_url': None
                }
        else:
            return {
                'success': False,
                'error': f'API returned status {response.status_code}',
                'screenshot_url': None
            }
            
    except requests.exceptions.Timeout:
        return {
            'success': False,
            'error': 'Screenshot generation timeout',
            'screenshot_url': None
        }
    except Exception as e:
        return {
            'success': False,
            'error': f'Screenshot error: {str(e)}',
            'screenshot_url': None
        }


def calculate_threat_level(vt_data: dict, static_analysis: dict) -> str:
    """
    Determine threat level based on analysis results.
    Returns: 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'CLEAN'
    """
    malicious_count = vt_data.get('malicious', 0)
    suspicious_count = vt_data.get('suspicious', 0)
    static_risk = static_analysis.get('risk_score', 0)
    
    threat_score = (malicious_count * 10) + (suspicious_count * 5) + static_risk
    
    if threat_score >= 80:
        return 'CRITICAL'
    elif threat_score >= 60:
        return 'HIGH'
    elif threat_score >= 40:
        return 'MEDIUM'
    elif threat_score >= 20:
        return 'LOW'
    else:
        return 'CLEAN'


# ============================================================================
# ROUTES
# ============================================================================

@app.route('/')
def index():
    """Serve the main dashboard."""
    return render_template('index.html')


@app.route('/api/analyze', methods=['POST'])
def analyze():
    """
    Main analysis endpoint.
    Request: { "url": "https://example.com" }
    Response: { intelligence report }
    """
    try:
        data = request.get_json()
        target_url = data.get('url', '').strip()
        
        # Validate input
        is_valid, normalized_url = is_valid_url(target_url)
        if not is_valid:
            return jsonify({
                'success': False,
                'error': 'Invalid URL format or unsupported protocol. Please provide a valid HTTP/HTTPS URL.',
                'error_type': 'INVALID_URL'
            }), 400
        
        # Initialize response
        intelligence_report = {
            'url_analyzed': normalized_url,
            'timestamp': datetime.utcnow().isoformat(),
            'redirection_chain': None,
            'virustotal_analysis': None,
            'static_analysis': None,
            'screenshot': None,
            'threat_level': None,
            'summary': None
        }
        
        # Step 1: Track redirections
        intelligence_report['redirection_chain'] = track_redirection_chain(normalized_url)
        
        final_url = intelligence_report['redirection_chain']['final_url']
        
        # Step 2: VirusTotal analysis
        intelligence_report['virustotal_analysis'] = query_virustotal(final_url)
        
        # Step 3: Static HTML analysis
        intelligence_report['static_analysis'] = analyze_html_for_threats(final_url)
        
        # Step 4: Generate screenshot
        intelligence_report['screenshot'] = generate_screenshot(final_url)
        
        # Step 5: Calculate threat level
        intelligence_report['threat_level'] = calculate_threat_level(
            intelligence_report['virustotal_analysis'],
            intelligence_report['static_analysis']
        )
        
        # Step 6: Generate summary
        intelligence_report['summary'] = {
            'total_hops': len(intelligence_report['redirection_chain']['chain']),
            'vendors_checked': intelligence_report['virustotal_analysis'].get('vendors_checked', 0),
            'malicious_detections': intelligence_report['virustotal_analysis'].get('malicious', 0),
            'static_risk_score': intelligence_report['static_analysis'].get('risk_score', 0)
        }
        
        return jsonify({
            'success': True,
            'intelligence_report': intelligence_report
        }), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Unexpected error during analysis: {str(e)}',
            'error_type': 'ANALYSIS_ERROR'
        }), 500


@app.route('/api/health', methods=['GET'])
def health():
    """Health check endpoint for deployment verification."""
    return jsonify({
        'status': 'operational',
        'service': 'CyberScan Sentinel',
        'timestamp': datetime.utcnow().isoformat()
    }), 200


@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors."""
    return jsonify({
        'success': False,
        'error': 'Endpoint not found',
        'error_type': 'NOT_FOUND'
    }), 404


@app.errorhandler(500)
def server_error(error):
    """Handle 500 errors."""
    return jsonify({
        'success': False,
        'error': 'Internal server error',
        'error_type': 'SERVER_ERROR'
    }), 500


# ============================================================================
# APPLICATION ENTRY POINT
# ============================================================================

if __name__ == '__main__':
    debug_mode = os.getenv('FLASK_ENV', 'production') == 'development'
    app.run(
        host='0.0.0.0',
        port=int(os.getenv('PORT', 5000)),
        debug=debug_mode
    )
