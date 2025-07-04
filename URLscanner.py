import time
import requests
import urllib.parse
import re
import hashlib
import base64
import logging
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass

logger = logging.getLogger(__name__)

@dataclass
class URLScanResult:
    url: str
    is_malicious: bool
    risk_score: int
    categories: List[str]
    detections: Dict[str, str]
    scan_date: str
    additional_info: Dict

class MaliciousURLScanner:
    def __init__(self, virustotal_api_key: str = None):
        self.vt_api_key = virustotal_api_key
        self.vt_base_url = "https://www.virustotal.com/api/v3/urls"
        self.session = requests.Session()
        self.session.timeout = 30

    def _validate_url(self, url: str) -> str:
        """Validate and normalize URL"""
        if not url:
            raise ValueError("URL cannot be empty")
        
        # Remove whitespace
        url = url.strip()
        
        # Add protocol if missing
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        # Validate URL format
        try:
            parsed = urllib.parse.urlparse(url)
            if not parsed.netloc:
                raise ValueError("Invalid URL format")
        except Exception as e:
            raise ValueError(f"Invalid URL format: {e}")
        
        return url

    def get_vt_report(self, url: str) -> Optional[Dict]:
        """Get VirusTotal report for URL"""
        if not self.vt_api_key:
            logger.warning("VirusTotal API key not set")
            return None

        try:
            headers = {"x-apikey": self.vt_api_key}
            
            # Create URL ID for VirusTotal (base64 encode without padding)
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            
            # First, try to get existing report
            report_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
            
            try:
                report_resp = self.session.get(report_url, headers=headers, timeout=15)
                if report_resp.status_code == 200:
                    logger.info("Using existing VirusTotal report")
                    return report_resp.json()
                elif report_resp.status_code == 404:
                    logger.info("No existing report found, submitting new scan")
                else:
                    logger.warning(f"VT Report Error {report_resp.status_code}: {report_resp.text}")
            except requests.exceptions.RequestException as e:
                logger.error(f"Error fetching VT report: {e}")
            
            # Submit new scan
            logger.info("Submitting new URL scan to VirusTotal")
            submit_data = {"url": url}
            submit_resp = self.session.post(
                self.vt_base_url, 
                headers=headers, 
                data=submit_data,  # Changed from json to data
                timeout=15
            )
            
            if submit_resp.status_code != 200:
                logger.error(f"VT Submit Error {submit_resp.status_code}: {submit_resp.text}")
                return None

            analysis_id = submit_resp.json().get('data', {}).get('id')
            if not analysis_id:
                logger.error("No analysis ID received from VirusTotal")
                return None
                
            analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"

            # Wait for analysis completion (max 60 seconds)
            max_attempts = 12
            for attempt in range(max_attempts):
                time.sleep(5)
                try:
                    analysis_resp = self.session.get(analysis_url, headers=headers, timeout=15)
                    if analysis_resp.status_code != 200:
                        logger.warning(f"Analysis check failed: {analysis_resp.status_code}")
                        continue

                    analysis = analysis_resp.json()
                    status = analysis.get('data', {}).get('attributes', {}).get('status', '')
                    
                    if status == "completed":
                        logger.info("VirusTotal analysis completed")
                        # Get the final URL report
                        final_report = self.session.get(report_url, headers=headers, timeout=15)
                        if final_report.status_code == 200:
                            return final_report.json()
                        else:
                            return analysis
                    elif status in ["error", "failed"]:
                        logger.error("VirusTotal analysis failed")
                        return None
                        
                except requests.exceptions.RequestException as e:
                    logger.error(f"Request error during VT analysis: {e}")
                    
            logger.warning("VirusTotal analysis didn't complete in time")
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Network error with VirusTotal: {e}")
        except Exception as e:
            logger.error(f"Unexpected error with VirusTotal: {e}")
            
        return None

    def heuristic_analysis(self, url: str) -> Tuple[int, List[str]]:
        """Perform heuristic analysis of URL"""
        risk_score = 0
        indicators = []
        
        try:
            parsed = urllib.parse.urlparse(url)
            domain = parsed.netloc.lower()
            path = parsed.path.lower()
            full_url = url.lower()
        except Exception as e:
            logger.error(f"Error parsing URL for heuristic analysis: {e}")
            return 5, ["URL parsing error"]

        # Enhanced suspicious patterns with better scoring
        suspicious_patterns = [
            (r'bit\.ly|tinyurl|goo\.gl|t\.co|short\.link|rb\.gy|is\.gd', 2, "URL shortener detected"),
            (r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', 4, "IP address as domain"),
            (r'[a-z0-9]+-[a-z0-9]+-[a-z0-9]+\.', 2, "Suspicious domain pattern"),
            (r'[a-z]{25,}\.com', 2, "Very long domain name"),
            (r'[0-9]{10,}', 2, "Long numeric sequence"),
            (r'\.exe|\.scr|\.bat|\.pif|\.com$', 3, "Executable file extension"),
            (r'free|prize|winner|lottery|click.*here|urgent|act.*now', 1, "Suspicious promotional content"),
        ]

        # Expanded suspicious TLDs
        suspicious_tlds = [
            '.tk', '.ml', '.ga', '.cf', '.top', '.click', '.download',
            '.link', '.loan', '.men', '.work', '.date', '.review', '.stream',
            '.win', '.bid', '.racing', '.party', '.science', '.faith'
        ]

        # Enhanced phishing keywords
        phishing_keywords = [
            'login', 'signin', 'account', 'verify', 'secure', 'bank',
            'paypal', 'amazon', 'microsoft', 'google', 'facebook',
            'update', 'confirm', 'suspended', 'locked', 'expired',
            'validation', 'authentication', 'security', 'alert'
        ]

        # Check patterns
        for pattern, score, desc in suspicious_patterns:
            if re.search(pattern, full_url, re.IGNORECASE):
                risk_score += score
                indicators.append(desc)

        # Check TLDs
        for tld in suspicious_tlds:
            if domain.endswith(tld):
                risk_score += 3
                indicators.append(f"Suspicious TLD: {tld}")
                break  # Only count once

        # Check for phishing keywords
        keyword_count = 0
        for keyword in phishing_keywords:
            if keyword in domain or keyword in path:
                keyword_count += 1
                if keyword_count <= 3:  # Limit to avoid over-scoring
                    risk_score += 1
                    indicators.append(f"Phishing keyword: {keyword}")

        # URL length check
        if len(url) > 200:
            risk_score += 3
            indicators.append("Extremely long URL")
        elif len(url) > 100:
            risk_score += 1
            indicators.append("Long URL")

        # Subdomain check
        subdomain_count = domain.count('.') - 1
        if subdomain_count > 3:
            risk_score += 3
            indicators.append("Excessive subdomains")
        elif subdomain_count > 2:
            risk_score += 1
            indicators.append("Multiple subdomains")

        # Suspicious parameters
        if '?' in url:
            suspicious_params = ['redirect', 'url', 'link', 'goto', 'target', 'next', 'continue']
            try:
                query = urllib.parse.parse_qs(parsed.query)
                for param in suspicious_params:
                    if param in query:
                        risk_score += 2
                        indicators.append(f"Suspicious parameter: {param}")
            except Exception:
                pass

        # Check for suspicious characters (IDN homograph attacks)
        if re.search(r'[а-я]', domain):  # Cyrillic characters
            risk_score += 3
            indicators.append("Non-Latin characters in domain")

        # Check for homograph attacks
        if re.search(r'[0oO1lI]', domain):
            # Only flag if there are multiple suspicious characters
            suspicious_count = len(re.findall(r'[0oO1lI]', domain))
            if suspicious_count > 2:
                risk_score += 2
                indicators.append("Potential homograph attack")

        # Check for domain squatting patterns
        popular_domains = ['google', 'facebook', 'amazon', 'microsoft', 'apple', 'paypal', 'netflix']
        for pop_domain in popular_domains:
            if pop_domain in domain and not domain.endswith(f'{pop_domain}.com'):
                risk_score += 3
                indicators.append(f"Potential {pop_domain} domain squatting")

        # Check for suspicious port numbers
        if ':' in parsed.netloc:
            try:
                port = int(parsed.netloc.split(':')[1])
                if port not in [80, 443, 8080, 8443]:
                    risk_score += 2
                    indicators.append(f"Suspicious port: {port}")
            except (ValueError, IndexError):
                pass

        return risk_score, indicators

    def analyze_url(self, url: str) -> URLScanResult:
        """Analyze URL for maliciousness"""
        try:
            # Validate and normalize URL
            url = self._validate_url(url)
            
            # Perform heuristic analysis
            heuristic_score, indicators = self.heuristic_analysis(url)
            
            # Get VirusTotal data
            vt_data = self.get_vt_report(url)

            total_score = heuristic_score
            detections = {}
            categories = []
            additional_info = {"heuristic_indicators": indicators}

            # Process VirusTotal results
            if vt_data:
                try:
                    # Handle both analysis response and URL report response
                    if 'data' in vt_data and 'attributes' in vt_data['data']:
                        attrs = vt_data['data']['attributes']
                        
                        # For URL reports
                        if 'last_analysis_stats' in attrs:
                            stats = attrs['last_analysis_stats']
                            malicious = stats.get('malicious', 0)
                            suspicious = stats.get('suspicious', 0)
                            harmless = stats.get('harmless', 0)
                            undetected = stats.get('undetected', 0)
                            
                            # Adjust scoring based on VT results
                            vt_score = malicious * 4 + suspicious * 2
                            total_score += vt_score

                            if malicious > 0:
                                detections['VirusTotal'] = f"{malicious} engines flagged as malicious"
                                categories.append("Malicious")
                            elif suspicious > 0:
                                detections['VirusTotal'] = f"{suspicious} engines flagged as suspicious"
                                categories.append("Suspicious")

                            additional_info['virustotal'] = {
                                'malicious': malicious,
                                'suspicious': suspicious,
                                'harmless': harmless,
                                'undetected': undetected,
                                'total_scans': malicious + suspicious + harmless + undetected
                            }
                        
                        # For analysis responses
                        elif 'stats' in attrs:
                            stats = attrs['stats']
                            malicious = stats.get('malicious', 0)
                            suspicious = stats.get('suspicious', 0)
                            harmless = stats.get('harmless', 0)
                            
                            vt_score = malicious * 4 + suspicious * 2
                            total_score += vt_score

                            if malicious > 0:
                                detections['VirusTotal'] = f"{malicious} engines flagged as malicious"
                                categories.append("Malicious")
                            elif suspicious > 0:
                                detections['VirusTotal'] = f"{suspicious} engines flagged as suspicious"
                                categories.append("Suspicious")

                            additional_info['virustotal'] = {
                                'malicious': malicious,
                                'suspicious': suspicious,
                                'harmless': harmless,
                                'total_scans': malicious + suspicious + harmless
                            }
                            
                except Exception as e:
                    logger.error(f"Error processing VirusTotal data: {e}")
                    additional_info['vt_error'] = str(e)

            # Add heuristic detections
            if indicators:
                detections['Heuristic'] = f"{len(indicators)} suspicious indicators found"

            # Determine if URL is malicious (lowered threshold)
            is_malicious = total_score >= 4

            # Add risk level category
            if total_score >= 10:
                categories.append("High Risk")
            elif total_score >= 4:
                categories.append("Medium Risk")
            elif total_score >= 2:
                categories.append("Low Risk")
            else:
                categories.append("Clean")

            # Cap the risk score at 10
            total_score = min(total_score, 10)

            return URLScanResult(
                url=url,
                is_malicious=is_malicious,
                risk_score=total_score,
                categories=categories,
                detections=detections,
                scan_date=time.strftime('%Y-%m-%d %H:%M:%S'),
                additional_info=additional_info
            )
            
        except ValueError as e:
            # Re-raise validation errors
            raise e
        except Exception as e:
            logger.error(f"Error analyzing URL: {e}")
            raise ValueError(f"Failed to analyze URL: {e}")

    def __del__(self):
        """Cleanup session on object destruction"""
        if hasattr(self, 'session'):
            self.session.close()