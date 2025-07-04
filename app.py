import os
import logging
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
# Import custom modules for security analysis
from GeoIPlocator import GeoIPLocator
from URLscanner import MaliciousURLScanner
from headeranalysis import EmailHeaderAnalyzer
from dotenv import load_dotenv # Used to load environment variables from a .env file

# Configure logging for the application
# Sets up basic logging to display INFO level messages and above.
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__) # Creates a logger instance for this module

# Initialize the Flask application
app = Flask(__name__)
# Enable Cross-Origin Resource Sharing (CORS) for all routes.
# This allows web pages from different domains to make requests to this API.
CORS(app)

# --- Initialize Security Analysis Components ---
# Initializes the EmailHeaderAnalyzer for parsing email headers.
email_analyzer = EmailHeaderAnalyzer()
# Initializes the GeoIPLocator for IP address geolocation.
locator = GeoIPLocator()

# Load environment variables from a .env file (if present).
# This is crucial for securely managing sensitive information like API keys.
load_dotenv()
# Retrieve the VirusTotal API key from environment variables.
# Using environment variables is a best practice for security, preventing API keys
# from being hardcoded directly into the source code.
vt_api_key = os.getenv("VIRUSTOTAL_API_KEY")

# Check if the VirusTotal API key was loaded successfully.
# Logs a warning if the API key is not found, indicating a potential issue.
if not vt_api_key:
    logger.warning("VirusTotal API key not found in environment variables. URL scanning may be limited or fail.")

# Initializes the MaliciousURLScanner with the retrieved VirusTotal API key.
url_scanner = MaliciousURLScanner(virustotal_api_key=vt_api_key)

# --- Route Definitions ---

@app.route('/')
def home():
    """
    Renders the main HTML page for the application.
    This is typically the entry point for the web interface.
    """
    return render_template('UI.html')

@app.route('/analyze_ip', methods=['POST'])
def analyze_ip():
    """
    API endpoint to analyze an IP address.
    Expects a POST request with JSON data containing an 'ip' field.
    Returns geolocation and threat intelligence information for the given IP.
    """
    try:
        data = request.get_json() # Get JSON data from the request body
        if not data:
            # Return a 400 Bad Request error if no JSON data is provided.
            return jsonify({'error': 'No JSON data provided'}), 400
            
        ip = data.get('ip', '').strip() # Extract and clean the 'ip' field

        if not ip:
            # Return a 400 Bad Request error if the IP field is empty.
            return jsonify({'error': 'No IP provided'}), 400

        # Basic IP format validation using a helper function.
        if not _is_valid_ip_format(ip):
            # Return a 400 Bad Request error if the IP format is invalid.
            return jsonify({'error': 'Invalid IP format'}), 400

        # Call the GeoIPLocator to get IP details.
        result = locator.locate_ip(ip)
        if not result:
            # Return a 500 Internal Server Error if IP analysis fails.
            return jsonify({'error': 'Unable to analyze IP'}), 500

        # Return the analysis results as a JSON response.
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
        # Log any unexpected exceptions during IP analysis.
        logger.error(f"Exception in analyze_ip: {e}")
        # Return a generic 500 Internal Server Error for unhandled exceptions.
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/analyze_url', methods=['POST'])
def analyze_url():
    """
    API endpoint to analyze a URL for malicious content.
    Expects a POST request with JSON data containing a 'url' field.
    Returns scan results including malicious status, risk score, and detections.
    """
    try:
        data = request.get_json() # Get JSON data from the request body
        if not data:
            # Return a 400 Bad Request error if no JSON data is provided.
            return jsonify({'error': 'No JSON data provided'}), 400
            
        url = data.get('url', '').strip() # Extract and clean the 'url' field
        
        if not url:
            # Return a 400 Bad Request error if the URL field is empty.
            return jsonify({'error': 'No URL provided'}), 400

        # Validate URL length to prevent excessively long inputs.
        if len(url) > 2048:
            # Return a 400 Bad Request error if the URL is too long.
            return jsonify({'error': 'URL too long'}), 400

        # Call the MaliciousURLScanner to analyze the URL.
        result = url_scanner.analyze_url(url)

        # Return the analysis results as a JSON response.
        # Includes all fields from the scanner result, including additional_info.
        return jsonify({
            'url': result.url,
            'is_malicious': result.is_malicious,
            'risk_score': result.risk_score,
            'categories': result.categories,
            'detections': result.detections,
            'scan_date': result.scan_date,
            # 'additional_info' contains more detailed data, like heuristic indicators.
            'additional_info': result.additional_info 
        })

    except ValueError as e:
        # Catch specific ValueError exceptions, often raised by the scanner for invalid input.
        logger.error(f"ValueError in analyze_url: {e}")
        # Return a 400 Bad Request with the specific error message.
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        # Log any unexpected exceptions during URL analysis.
        logger.error(f"Exception in analyze_url: {e}")
        # Return a generic 500 Internal Server Error for unhandled exceptions.
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/analyze_email', methods=['POST'])
def analyze_email():
    """
    API endpoint to analyze email headers for security indicators.
    Expects a POST request with JSON data containing an 'email' field
    (which should contain the raw email content/headers).
    Returns a structured analysis of sender info, routing, authentication, and risk.
    """
    try:
        data = request.get_json() # Get JSON data from the request body
        if not data:
            # Return a 400 Bad Request error if no JSON data is provided.
            return jsonify({'error': 'No JSON data provided'}), 400
            
        email_content = data.get('email', '').strip() # Extract and clean the 'email' field

        if not email_content:
            # Return a 400 Bad Request error if the email content is empty.
            return jsonify({'error': 'No email content provided'}), 400

        # Validate email content length to prevent excessively large inputs.
        if len(email_content) > 1024 * 1024:  # 1MB limit
            # Return a 400 Bad Request error if the email content is too large.
            return jsonify({'error': 'Email content too large'}), 400

        # Call the EmailHeaderAnalyzer to process the email content.
        analysis = email_analyzer.analyze_headers(email_content)
        if not analysis:
            # Return a 500 Internal Server Error if email analysis fails.
            return jsonify({'error': 'Failed to analyze email headers'}), 500

        # Return the structured email analysis results as a JSON response.
        return jsonify({
            'sender_info': analysis.sender_info,
            'routing_path': analysis.routing_path,
            'authentication': {
                'spf_result': analysis.authentication.spf_result,
                'dkim_result': analysis.authentication.dkim_result,
                'dmarc_result': analysis.authentication.dmarc_result,
                'authentication_status': analysis.authentication.authentication_status
            },
            'security_indicators': analysis.security_indicators,
            'risk_assessment': analysis.risk_assessment,
            'summary': analysis.analysis_summary
        })

    except Exception as e:
        # Log any unexpected exceptions during email analysis.
        logger.error(f"Exception in analyze_email: {e}")
        # Return a generic 500 Internal Server Error for unhandled exceptions.
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/health', methods=['GET'])
def health_check():
    """
    API endpoint for health checks.
    Returns a simple JSON response indicating the application's status.
    Useful for monitoring and deployment systems.
    """
    # Simply returns a status message.
    return jsonify({'status': 'healthy', 'scanner': 'ready'})

def _is_valid_ip_format(ip: str) -> bool:
    """
    Helper function to perform basic validation of IP address format.
    Supports both IPv4 and IPv6 patterns.
    """
    import re # Import regular expression module
    # Regex pattern for IPv4 addresses (e.g., 192.168.1.1)
    ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    # Regex pattern for IPv6 addresses (e.g., 2001:0db8:85a3:0000:0000:8a2e:0370:7334)
    ipv6_pattern = r'^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$'
    
    # Check if the IP matches either IPv4 or IPv6 pattern.
    return bool(re.match(ipv4_pattern, ip) or re.match(ipv6_pattern, ip))

# --- Error Handlers ---

@app.errorhandler(404)
def not_found(error):
    """
    Custom error handler for 404 Not Found errors.
    Returns a JSON response for unhandled routes.
    """
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    """
    Custom error handler for 500 Internal Server Errors.
    Logs the error and returns a generic JSON response.
    """
    logger.error(f"Internal server error: {error}")
    return jsonify({'error': 'Internal server error'}), 500

# --- Application Entry Point ---

if __name__ == '__main__':
    # This block runs when the script is executed directly (not imported as a module).
    print("Starting Multi-Tool Security Analysis Backend...")
    print("Backend will be available at http://127.0.0.1:5000")
    # Run the Flask application.
    # debug=True: Enables debug mode (auto-reloads on code changes, provides debugger).
    # host='127.0.0.1': Binds the server to the localhost interface.
    # port=5000: Runs the server on port 5000.
    app.run(debug=True, host='127.0.0.1', port=5000)

