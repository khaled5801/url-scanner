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
    
    results = {
        'url': url,
        'virustotal': check_virustotal(url),
        'redirects': detect_redirects(url),
        'ssl_check': check_ssl(url),
        'malicious_patterns': detect_malicious_patterns(url),
        'injection_check': detect_injection_threats(url),
        'screenshot': get_screenshot_safe(url),
        'overall_risk': 'SAFE'
    }
    
    risk_score = calculate_risk(results)
    results['risk_score'] = risk_score
    
    if risk_score >= 70:
        results['overall_risk'] = 'DANGEROUS'
    elif risk_score >= 40:
        results['overall_risk'] = 'SUSPICIOUS'
    else:
        results['overall_risk'] = 'SAFE'
    
    return jsonify(results)

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
        print(f"Redirect detection error: {e}")
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
        except ssl.SSLError as e:
            return {
                'valid': False,
                'error': str(e),
                'message': 'Invalid SSL Certificate'
            }
    except Exception as e:
        return {
            'valid': False,
            'error': str(e),
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
            suspicious_patterns.append(f'Suspicious keyword detected: {keyword}')
    
    if '%' in url and len(url.split('%')) > 4:
        suspicious_patterns.append('Unusual URL encoding detected')
    
    domains = url.split('/')[-1].split('.')
    if len(domains) > 3:
        suspicious_patterns.append('Complex domain structure detected')
    
    domain = urlparse(url).netloc
    if re.match(r'^\d+\.\d+\.\d+\.\d+', domain):
        suspicious_patterns.append('IP address used instead of domain')
    
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
            threats.append('Dangerous eval() function detected')
        
        if 'document.write' in html_content:
            threats.append('DOM manipulation detected')
        
        if '<iframe' in html_content:
            if 'display:none' in html_content or 'visibility:hidden' in html_content:
                threats.append('Hidden iframe detected')
        
        return {
            'found': len(threats) > 0,
            'threats': threats,
            'count': len(threats)
        }
    except Exception as e:
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
        else:
            return None
    except Exception as e:
        return None

def calculate_risk(results):
    risk_score = 0
    
    vt = results['virustotal']
    if vt['malicious'] > 0:
        risk_score += min(vt['malicious'] * 15, 35)
    elif vt['suspicious'] > 0:
        risk_score += min(vt['suspicious'] * 7, 25)
    
    if not results['ssl_check'].get('valid', False):
        risk_score += 15
    
    if results['redirects']['suspicious']:
        risk_score += 20
    
    if results['malicious_patterns']['found']:
        risk_score += min(results['malicious_patterns']['count'] * 7, 20)
    
    if results['injection_check']['found']:
        risk_score += min(results['injection_check']['count'] * 3, 10)
    
    return min(int(risk_score), 100)

if __name__ == '__main__':
    # جلب المنفذ من إعدادات السيرفر، وإذا لم يوجد يستخدم 5000 كاحتياط
    port = int(os.environ.get("PORT", 5000))
    # تشغيل التطبيق على 0.0.0.0 ليقبل الاتصالات الخارجية
    app.run(host='0.0.0.0', port=port)
  
