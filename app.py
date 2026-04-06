from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
import requests
import base64
from urllib.parse import urlparse
import os
from dotenv import load_dotenv
import re
import ssl
import socket
from datetime import datetime

load_dotenv()

app = Flask(__name__)
CORS(app)

VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')
VT_API_URL = "https://www.virustotal.com/api/v3"

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    url = request.json.get('url')
    
    if not url:
        return jsonify({'error': 'URL is required'}), 400
    
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    # جمع جميع البيانات
    virustotal_data = check_virustotal(url)
    redirects_data = detect_redirects(url)
    ssl_data = check_ssl(url)
    patterns_data = detect_malicious_patterns(url)
    injection_data = detect_injection_threats(url)
    screenshot_data = get_screenshot_safe(url)
    
    # AI Analysis - تحليل ذكي للبيانات
    ai_analysis = perform_ai_analysis(
        url=url,
        virustotal=virustotal_data,
        redirects=redirects_data,
        ssl=ssl_data,
        patterns=patterns_data,
        injection=injection_data
    )
    
    results = {
        'url': url,
        'virustotal': virustotal_data,
        'redirects': redirects_data,
        'ssl_check': ssl_data,
        'malicious_patterns': patterns_data,
        'injection_check': injection_data,
        'screenshot': screenshot_data,
        'ai_analysis': ai_analysis,
        'overall_risk': ai_analysis['risk_level'],
        'risk_score': ai_analysis['risk_score'],
        'timestamp': datetime.now().isoformat()
    }
    
    return jsonify(results)

def perform_ai_analysis(url, virustotal, redirects, ssl, patterns, injection):
    """تحليل ذكي للرابط"""
    
    risk_factors = []
    risk_score = 0
    
    # 1. VirusTotal Analysis
    if virustotal['malicious'] > 0:
        risk_score += virustotal['malicious'] * 20
        risk_factors.append({
            'type': 'malware_detected',
            'severity': 'critical',
            'message': f"Malware detected by {virustotal['malicious']} vendors",
            'confidence': 95
        })
    
    if virustotal['suspicious'] > 0:
        risk_score += virustotal['suspicious'] * 10
        risk_factors.append({
            'type': 'suspicious_activity',
            'severity': 'high',
            'message': f"Suspicious behavior detected by {virustotal['suspicious']} vendors",
            'confidence': 75
        })
    
    # 2. SSL Certificate Analysis
    if not ssl['valid']:
        risk_score += 15
        risk_factors.append({
            'type': 'invalid_ssl',
            'severity': 'high',
            'message': 'Invalid or missing SSL certificate',
            'confidence': 90
        })
    
    # 3. Redirect Analysis
    if redirects['suspicious']:
        risk_score += 20
        risk_factors.append({
            'type': 'suspicious_redirects',
            'severity': 'high',
            'message': f"Domain changes detected across {len(redirects['redirects'])} redirects",
            'confidence': 85
        })
    
    # 4. URL Pattern Analysis
    if patterns['found']:
        risk_score += patterns['count'] * 8
        risk_factors.append({
            'type': 'malicious_patterns',
            'severity': 'medium',
            'message': f"{patterns['count']} suspicious patterns detected in URL",
            'confidence': 70
        })
    
    # 5. Injection Threat Analysis
    if injection['found']:
        risk_score += injection['count'] * 5
        risk_factors.append({
            'type': 'code_injection',
            'severity': 'high',
            'message': f"Potential code injection vectors detected",
            'confidence': 80
        })
    
    # 6. Domain Age & Reputation (AI Logic)
    domain = urlparse(url).netloc
    domain_risk = analyze_domain_reputation(domain)
    if domain_risk['risk_level'] > 0:
        risk_score += domain_risk['risk_level']
        risk_factors.append(domain_risk['factor'])
    
    # 7. URL Structure Analysis (AI Logic)
    structure_risk = analyze_url_structure(url)
    if structure_risk['risk_level'] > 0:
        risk_score += structure_risk['risk_level']
        risk_factors.append(structure_risk['factor'])
    
    # Cap risk score at 100
    risk_score = min(int(risk_score), 100)
    
    # Determine risk level
    if risk_score >= 70:
        risk_level = 'DANGEROUS'
        recommendation = 'Do not access this URL. High probability of malware or phishing.'
    elif risk_score >= 40:
        risk_level = 'SUSPICIOUS'
        recommendation = 'Proceed with caution. Consider avoiding data entry on this site.'
    else:
        risk_level = 'SAFE'
        recommendation = 'URL appears to be safe. Normal precautions recommended.'
    
    # Generate AI confidence score
    confidence = calculate_ai_confidence(risk_factors)
    
    return {
        'risk_level': risk_level,
        'risk_score': risk_score,
        'confidence': confidence,
        'recommendation': recommendation,
        'risk_factors': risk_factors,
        'analysis_timestamp': datetime.now().isoformat()
    }

def analyze_domain_reputation(domain):
    """تحليل سمعة النطاق"""
    risk_level = 0
    factor = None
    
    # Check for newly registered domains (suspicious)
    if len(domain.split('.')) == 2:  # Simple domain
        # Check for suspicious TLDs
        tld = domain.split('.')[-1]
        suspicious_tlds = ['tk', 'ml', 'ga', 'cf', 'top', 'work', 'stream']
        
        if tld in suspicious_tlds:
            risk_level = 12
            factor = {
                'type': 'suspicious_tld',
                'severity': 'medium',
                'message': f'Suspicious TLD (.{tld}) commonly used for malicious sites',
                'confidence': 65
            }
    
    # Check for homograph attacks (visually similar domains)
    suspicious_domains = [
        'qoogle.com', 'goog1e.com', 'g00gle.com',
        'facebook.com', 'facebookk.com',
        'amazon.com', 'amaz0n.com'
    ]
    
    if domain in suspicious_domains or contains_lookalike(domain):
        risk_level = 25
        factor = {
            'type': 'homograph_attack',
            'severity': 'critical',
            'message': 'Domain appears to mimic a well-known legitimate site',
            'confidence': 88
        }
    
    return {
        'risk_level': risk_level,
        'factor': factor
    }

def analyze_url_structure(url):
    """تحليل هيكل الرابط"""
    risk_level = 0
    factor = None
    
    # Check for overly long URLs (common in phishing)
    if len(url) > 100:
        risk_level = 5
        factor = {
            'type': 'long_url',
            'severity': 'low',
            'message': 'Unusually long URL, commonly used in phishing attacks',
            'confidence': 60
        }
    
    # Check for suspicious parameters
    if '?' in url:
        params = url.split('?')[1]
        if 'redirect' in params.lower() or 'forward' in params.lower():
            risk_level = 15
            factor = {
                'type': 'redirect_parameter',
                'severity': 'medium',
                'message': 'URL contains redirect parameters',
                'confidence': 72
            }
    
    # Check for nested subdomains
    domain_parts = url.split('/')[2].split('.')
    if len(domain_parts) > 3:
        risk_level = 8
        factor = {
            'type': 'suspicious_subdomains',
            'severity': 'low',
            'message': 'Multiple nested subdomains detected',
            'confidence': 58
        }
    
    return {
        'risk_level': risk_level,
        'factor': factor
    }

def contains_lookalike(domain):
    """Check for homograph attacks"""
    lookalikes = {
        'google': ['g00gle', 'qoogle', 'g0ogle'],
        'facebook': ['facebookk', 'faceb00k'],
        'amazon': ['amaz0n', 'amtzon'],
        'paypal': ['paypa1', 'paypla'],
    }
    
    for brand, variants in lookalikes.items():
        if any(variant in domain.lower() for variant in variants):
            return True
    return False

def calculate_ai_confidence(risk_factors):
    """حساب مستوى ثقة التحليل"""
    if not risk_factors:
        return 100
    
    # Average confidence of all factors
    total_confidence = sum(factor.get('confidence', 0) for factor in risk_factors)
    return min(int(total_confidence / len(risk_factors)), 100)

def check_virustotal(url):
    try:
        if not VIRUSTOTAL_API_KEY:
            return {
                'malicious': 0,
                'suspicious': 0,
                'undetected': 0,
                'harmless': 0,
                'total_vendors': 0
            }
        
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        
        response = requests.get(
            f"{VT_API_URL}/urls/{url_id}",
            headers=headers,
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            stats = data['data']['attributes']['last_analysis_stats']
            
            return {
                'malicious': stats.get('malicious', 0),
                'suspicious': stats.get('suspicious', 0),
                'undetected': stats.get('undetected', 0),
                'harmless': stats.get('harmless', 0),
                'total_vendors': sum(stats.values())
            }
        else:
            return {
                'malicious': 0,
                'suspicious': 0,
                'undetected': 0,
                'harmless': 0,
                'total_vendors': 0
            }
    except Exception as e:
        print(f"VirusTotal Error: {e}")
        return {
            'malicious': 0,
            'suspicious': 0,
            'undetected': 0,
            'harmless': 0,
            'total_vendors': 0
        }

def detect_redirects(url):
    try:
        response = requests.head(url, allow_redirects=False, timeout=5, verify=True)
        
        redirects = []
        current_url = url
        redirect_count = 0
        
        while 300 <= response.status_code < 400 and redirect_count < 5:
            redirect_url = response.headers.get('Location', '')
            if not redirect_url:
                break
            
            redirects.append({
                'from': current_url,
                'to': redirect_url
            })
            
            current_url = redirect_url
            response = requests.head(redirect_url, allow_redirects=False, timeout=5, verify=True)
            redirect_count += 1
        
        suspicious = False
        if redirects:
            original_domain = urlparse(url).netloc
            final_domain = urlparse(current_url).netloc
            suspicious = original_domain != final_domain
        
        return {
            'found': len(redirects) > 0,
            'count': len(redirects),
            'redirects': redirects,
            'suspicious': suspicious
        }
    except Exception as e:
        return {
            'found': False,
            'count': 0,
            'redirects': [],
            'suspicious': False
        }

def check_ssl(url):
    try:
        domain = urlparse(url).netloc
        context = ssl.create_default_context()
        
        try:
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    return {
                        'valid': True,
                        'issuer': cert.get('issuer', [{}])[0].get('commonName', 'Unknown'),
                        'subject': cert.get('subject', [{}])[0].get('commonName', domain),
                        'message': 'Valid SSL Certificate'
                    }
        except ssl.SSLError:
            return {
                'valid': False,
                'message': 'Invalid SSL Certificate'
            }
    except Exception as e:
        return {
            'valid': False,
            'message': 'SSL Check Failed'
        }

def detect_malicious_patterns(url):
    suspicious_patterns = []
    
    dangerous_keywords = [
        'bit.ly', 'tinyurl', 'short.link', 'goo.gl',
        'free-download', 'free-software', 'confirm-account',
        'verify-account', 'update-now', 'click-here',
        'limited-time', 'act-now', 'claim-prize'
    ]
    
    url_lower = url.lower()
    for keyword in dangerous_keywords:
        if keyword in url_lower:
            suspicious_patterns.append(f'Suspicious keyword: {keyword}')
    
    if '%' in url and len(url.split('%')) > 4:
        suspicious_patterns.append('Unusual URL encoding')
    
    domain = urlparse(url).netloc
    if re.match(r'^\d+\.\d+\.\d+\.\d+', domain):
        suspicious_patterns.append('IP address instead of domain')
    
    return {
        'found': len(suspicious_patterns) > 0,
        'patterns': suspicious_patterns,
        'count': len(suspicious_patterns)
    }

def detect_injection_threats(url):
    threats = []
    
    try:
        response = requests.get(url, timeout=10, allow_redirects=True)
        html_content = response.text.lower()
        
        if '<script' in html_content:
            threats.append('JavaScript code detected')
        
        if 'eval(' in html_content:
            threats.append('Eval function detected')
        
        if '<iframe' in html_content:
            if 'display:none' in html_content or 'visibility:hidden' in html_content:
                threats.append('Hidden iframe detected')
        
        return {
            'found': len(threats) > 0,
            'threats': threats,
            'count': len(threats)
        }
    except:
        return {
            'found': False,
            'threats': [],
            'count': 0
        }

def get_screenshot_safe(url):
    try:
        response = requests.get(
            f"https://urlscreenshot.com/generate?url={url}&format=png",
            timeout=15,
            headers={'User-Agent': 'Mozilla/5.0'}
        )
        
        if response.status_code == 200 and len(response.content) > 100:
            return base64.b64encode(response.content).decode()
    except:
        pass
    
    return None

if __name__ == '__main__':
    app.run(debug=True, port=5000)
  
