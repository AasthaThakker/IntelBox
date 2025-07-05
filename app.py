import os
import logging
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
# Import custom modules for security analysis
from GeoIPlocator import GeoIPLocator
from URLscanner import MaliciousURLScanner
from headeranalysis import EmailHeaderAnalyzer
from phishing_detector import PhishingDetector # NEW: Import PhishingDetector
from dns_whois import DNSWHOISIntelligence # NEW: Import DNSWHOISIntelligence
from dotenv import load_dotenv

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)

# --- Initialize Security Analysis Components ---
email_analyzer = EmailHeaderAnalyzer()
locator = GeoIPLocator()

load_dotenv()
vt_api_key = os.getenv("VIRUSTOTAL_API_KEY")

if not vt_api_key:
    logger.warning("VirusTotal API key not found in environment variables. URL scanning and IP analysis may be limited or fail.")

url_scanner = MaliciousURLScanner(virustotal_api_key=vt_api_key)
phishing_detector = PhishingDetector() # NEW: Initialize PhishingDetector
dns_whois_analyzer = DNSWHOISIntelligence() # NEW: Initialize DNSWHOISIntelligence

# --- Route Definitions ---

@app.route('/')
def home():
    return render_template('UI.html')

@app.route('/analyze_ip', methods=['POST'])
def analyze_ip():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No JSON data provided'}), 400
            
        ip = data.get('ip', '').strip()

        if not ip:
            return jsonify({'error': 'No IP provided'}), 400

        if not _is_valid_ip_format(ip):
            return jsonify({'error': 'Invalid IP format'}), 400

        result = locator.locate_ip(ip)
        if not result:
            return jsonify({'error': 'Unable to analyze IP'}), 500

        return jsonify({
            'ip': result.ip,
            'country': result.country,
            'city': result.city,
            'region': result.region,
            'timezone': result.timezone,
            'isp': result.isp,
            'organization': result.organization,
            'asn': result.asn,
            'latitude': result.latitude,
            'longitude': result.longitude,
            'is_proxy': result.is_proxy,
            'is_tor': result.is_tor,
            'threat_level': result.threat_level
        })

    except Exception as e:
        logger.error(f"Exception in analyze_ip: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/analyze_url', methods=['POST'])
def analyze_url():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No JSON data provided'}), 400
            
        url = data.get('url', '').strip()
        
        if not url:
            return jsonify({'error': 'No URL provided'}), 400

        if len(url) > 2048:
            return jsonify({'error': 'URL too long'}), 400

        result = url_scanner.analyze_url(url)

        return jsonify({
            'url': result.url,
            'is_malicious': result.is_malicious,
            'risk_score': result.risk_score,
            'categories': result.categories,
            'detections': result.detections,
            'scan_date': result.scan_date,
            'additional_info': result.additional_info 
        })

    except ValueError as e:
        logger.error(f"ValueError in analyze_url: {e}")
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        logger.error(f"Exception in analyze_url: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/analyze_headers', methods=['POST']) # Renamed from /analyze_email for header analysis
def analyze_headers():
    """
    API endpoint to analyze email headers for security indicators.
    This endpoint specifically requires full email content with headers.
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No JSON data provided'}), 400
            
        email_content = data.get('email', '').strip()

        if not email_content:
            return jsonify({'error': 'No email content provided'}), 400

        if len(email_content) > 1024 * 1024:  # 1MB limit
            return jsonify({'error': 'Email content too large'}), 400

        # Perform header analysis
        header_analysis = email_analyzer.analyze_headers(email_content)
        if not header_analysis:
            # If header analysis fails, it means the input was likely not a full email with headers
            return jsonify({'error': 'Failed to analyze email headers. Please provide full raw email content including headers.'}), 400

        # Return only header analysis results for this endpoint
        return jsonify({
            'sender_info': header_analysis.sender_info,
            'routing_path': header_analysis.routing_path,
            'authentication': {
                'spf_result': header_analysis.authentication.spf_result,
                'dkim_result': header_analysis.authentication.dkim_result,
                'dmarc_result': header_analysis.authentication.dmarc_result,
                'authentication_status': header_analysis.authentication.authentication_status
            },
            'security_indicators': header_analysis.security_indicators,
            'risk_assessment': header_analysis.risk_assessment,
            'summary': header_analysis.analysis_summary
        })

    except Exception as e:
        logger.error(f"Exception in analyze_headers: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/detect_phishing', methods=['POST'])
def detect_phishing(): # Changed back to synchronous function
    """
    API endpoint to perform AI-based phishing detection.
    This endpoint can handle just email body or full raw email content.
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No JSON data provided'}), 400
            
        email_content = data.get('email', '').strip()

        if not email_content:
            return jsonify({'error': 'No email content provided'}), 400

        if len(email_content) > 1024 * 1024:  # 1MB limit
            return jsonify({'error': 'Email content too large'}), 400

        # Perform AI-based phishing detection using the raw email content
        # The phishing_detector now handles its own parsing
        # Removed 'await' as classify_email is now synchronous
        phishing_result = phishing_detector.classify_email(email_content)

        # Return only phishing detection results for this endpoint
        return jsonify({
            'classification': phishing_result.classification,
            'confidence': phishing_result.confidence,
            'indicators': phishing_result.indicators,
            'risk_score': phishing_result.risk_score,
            'summary': phishing_result.summary
        })

    except Exception as e:
        logger.error(f"Exception in detect_phishing: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/analyze_domain', methods=['POST']) # NEW: New endpoint for DNS/WHOIS
def analyze_domain():
    """
    API endpoint to analyze a domain's DNS records and WHOIS information.
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No JSON data provided'}), 400
            
        domain = data.get('domain', '').strip()

        if not domain:
            return jsonify({'error': 'No domain provided'}), 400

        result = dns_whois_analyzer.analyze_domain(domain)
        
        return jsonify({
            'domain': result.domain,
            'a_records': result.a_records,
            'mx_records': result.mx_records,
            'spf_record': result.spf_record,
            'ns_records': result.ns_records,
            'whois_info': result.whois_info,
            'is_newly_registered': result.is_newly_registered,
            'is_short_lifecycle': result.is_short_lifecycle,
            'risk_score': result.risk_score,
            'summary': result.summary
        })

    except ValueError as e:
        logger.error(f"ValueError in analyze_domain: {e}")
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        logger.error(f"Exception in analyze_domain: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'healthy', 'scanner': 'ready'})

def _is_valid_ip_format(ip: str) -> bool:
    import re
    ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    ipv6_pattern = r'^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$'
    return bool(re.match(ipv4_pattern, ip) or re.match(ipv6_pattern, ip))

# --- Error Handlers ---
@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal server error: {error}")
    return jsonify({'error': 'Internal server error'}), 500

# --- Application Entry Point ---
if __name__ == '__main__':
    print("Starting Multi-Tool Security Analysis Backend...")
    print("Backend will be available at http://127.0.0.1:5000")
    app.run(debug=True, host='127.0.0.1', port=5000)
