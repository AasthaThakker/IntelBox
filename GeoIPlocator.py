import requests
import ipaddress
from typing import Dict, List, Optional
from dataclasses import dataclass
from requests.exceptions import RequestException
import time

@dataclass
class GeoIPResult:
    ip: str
    country: str
    country_code: str
    city: str
    region: str
    postal_code: str
    latitude: float
    longitude: float
    timezone: str
    isp: str
    organization: str
    asn: str
    is_proxy: bool
    is_tor: bool
    threat_level: str

class GeoIPLocator:
    def __init__(self, vt_api_key: str = None):
        self.headers = {'User-Agent': 'GeoIPLocator/1.0'}
        
        # Use provided API key or default (replace with your actual key)
        self.vt_api_key = vt_api_key or "929089e0d7421406a3ebfee0fc2d1542b9626373bef163f9f94874ea20c2c24b"
        
        # Primary APIs (free tier)
        self.apis = {
            'ipapi': 'http://ip-api.com/json/{ip}?fields=status,message,continent,continentCode,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query',
            'ipinfo': 'https://ipinfo.io/{ip}/json',
            'ipwhois': 'http://ipwho.is/{ip}'  # Backup API
        }
        
        # Initialize threat feeds
        self.threat_indicators = {
            'tor_exit_nodes': [],
            'known_malicious_ips': [],
            'proxy_ranges': []
        }
        self._load_threat_feeds()

    def _load_threat_feeds(self):
        """Load threat intelligence feeds with error handling"""
        print("[INFO] Loading threat intelligence feeds...")
        
        # Load Tor exit nodes
        try:
            tor_nodes = self._fetch_tor_exit_nodes()
            if tor_nodes:
                self.threat_indicators['tor_exit_nodes'] = tor_nodes
                print(f"[INFO] Loaded {len(tor_nodes)} Tor exit nodes")
        except Exception as e:
            print(f"[WARNING] Failed to load Tor exit nodes: {e}")
        
        # Load malicious IPs (simplified for demo)
        self.threat_indicators['known_malicious_ips'] = [
            '185.220.101.1',  # Known malicious IP for testing
            '198.51.100.1',   # RFC 5737 test IP
            '203.0.113.1'     # RFC 5737 test IP
        ]
        
        # Load proxy ranges (simplified)
        self.threat_indicators['proxy_ranges'] = [
            '10.0.0.0/8',
            '172.16.0.0/12',
            '192.168.0.0/16'
        ]

    def _fetch_tor_exit_nodes(self) -> List[str]:
        """Fetch Tor exit nodes list"""
        url = "https://check.torproject.org/torbulkexitlist"
        try:
            response = requests.get(url, headers=self.headers, timeout=10)
            if response.status_code == 200:
                nodes = [line.strip() for line in response.text.splitlines() 
                        if line.strip() and not line.startswith('#')]
                return nodes[:100]  # Limit to first 100 for performance
        except Exception as e:
            print(f"[ERROR] Tor feed error: {e}")
        return []

    def check_virustotal_ip(self, ip: str) -> Optional[str]:
        """Check IP reputation using VirusTotal API"""
        if not self.vt_api_key:
            return None
            
        try:
            headers = {"x-apikey": self.vt_api_key}
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
            
            response = requests.get(url, headers=headers, timeout=15)
            
            if response.status_code == 200:
                data = response.json()
                stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                
                malicious = stats.get('malicious', 0)
                suspicious = stats.get('suspicious', 0)
                
                if malicious > 2:
                    return "HIGH"
                elif malicious > 0 or suspicious > 3:
                    return "MEDIUM"
                else:
                    return "CLEAN"
            elif response.status_code == 404:
                return "UNKNOWN"
            else:
                print(f"[WARNING] VirusTotal API error: {response.status_code}")
                
        except Exception as e:
            print(f"[ERROR] VirusTotal check failed: {e}")
        
        return None

    def check_threat_intelligence(self, ip: str) -> tuple[bool, bool, str]:
        """Analyze IP against threat intelligence sources"""
        is_tor = ip in self.threat_indicators['tor_exit_nodes']
        is_proxy = False
        
        # Check if IP is in proxy ranges
        try:
            for cidr in self.threat_indicators['proxy_ranges']:
                if self._is_ip_in_range(ip, cidr):
                    is_proxy = True
                    break
        except Exception:
            pass
        
        # Check known malicious IPs
        is_malicious_feed = ip in self.threat_indicators['known_malicious_ips']
        
        # Get VirusTotal assessment
        vt_threat = self.check_virustotal_ip(ip)
        
        # Determine overall threat level
        if vt_threat == "HIGH" or is_malicious_feed:
            threat_level = "HIGH"
        elif vt_threat == "MEDIUM" or is_tor:
            threat_level = "MEDIUM"
        elif is_proxy or vt_threat == "UNKNOWN":
            threat_level = "LOW"
        else:
            threat_level = "CLEAN"
        
        return is_proxy, is_tor, threat_level

    def _is_ip_in_range(self, ip: str, cidr: str) -> bool:
        """Check if IP is within CIDR range"""
        try:
            return ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(cidr, strict=False)
        except (ValueError, ipaddress.AddressValueError):
            return False

    def get_ip_info_ipapi(self, ip: str) -> Optional[Dict]:
        """Get IP info from ip-api.com"""
        try:
            url = self.apis['ipapi'].format(ip=ip)
            response = requests.get(url, headers=self.headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    return data
                else:
                    print(f"[ERROR] ip-api error: {data.get('message', 'Unknown error')}")
        except Exception as e:
            print(f"[ERROR] ip-api request failed: {e}")
        return None

    def get_ip_info_ipinfo(self, ip: str) -> Optional[Dict]:
        """Get IP info from ipinfo.io"""
        try:
            url = self.apis['ipinfo'].format(ip=ip)
            response = requests.get(url, headers=self.headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                if 'error' not in data:
                    return data
        except Exception as e:
            print(f"[ERROR] ipinfo request failed: {e}")
        return None

    def get_ip_info_ipwhois(self, ip: str) -> Optional[Dict]:
        """Get IP info from ipwho.is"""
        try:
            url = self.apis['ipwhois'].format(ip=ip)
            response = requests.get(url, headers=self.headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('success', False):
                    return data
        except Exception as e:
            print(f"[ERROR] ipwhois request failed: {e}")
        return None

    def locate_ip(self, ip: str) -> Optional[GeoIPResult]:
        """Main method to locate IP and assess threats"""
        if not ip or not self._is_valid_ip(ip):
            print(f"[ERROR] Invalid IP address: {ip}")
            return None
        
        # Try multiple APIs for geolocation
        data = None
        source = None
        
        # Try ip-api first (most reliable for free tier)
        data = self.get_ip_info_ipapi(ip)
        if data:
            source = 'ipapi'
        else:
            # Fallback to ipinfo
            data = self.get_ip_info_ipinfo(ip)
            if data:
                source = 'ipinfo'
                data = self._convert_ipinfo_format(data)
            else:
                # Final fallback
                data = self.get_ip_info_ipwhois(ip)
                if data:
                    source = 'ipwhois'
                    data = self._convert_ipwhois_format(data)
        
        if not data:
            print(f"[ERROR] Failed to get geolocation data for {ip}")
            return None
        
        # Perform threat intelligence analysis
        is_proxy, is_tor, threat_level = self.check_threat_intelligence(ip)
        
        try:
            # Parse coordinates
            lat, lon = 0.0, 0.0
            if 'lat' in data and 'lon' in data:
                lat = float(data.get('lat', 0))
                lon = float(data.get('lon', 0))
            elif 'loc' in data and ',' in str(data['loc']):
                coords = str(data['loc']).split(',')
                if len(coords) == 2:
                    lat, lon = float(coords[0]), float(coords[1])
            
            return GeoIPResult(
                ip=ip,
                country=data.get('country', 'Unknown'),
                country_code=data.get('countryCode', 'Unknown'),
                city=data.get('city', 'Unknown'),
                region=data.get('regionName', data.get('region', 'Unknown')),
                postal_code=data.get('zip', data.get('postal', 'Unknown')),
                latitude=lat,
                longitude=lon,
                timezone=data.get('timezone', 'Unknown'),
                isp=data.get('isp', 'Unknown'),
                organization=data.get('org', data.get('organization', 'Unknown')),
                asn=data.get('as', data.get('asn', 'Unknown')),
                is_proxy=is_proxy,
                is_tor=is_tor,
                threat_level=threat_level
            )
            
        except Exception as e:
            print(f"[ERROR] Failed to parse IP data: {e}")
            return None

    def _is_valid_ip(self, ip: str) -> bool:
        """Validate IP address format"""
        try:
            ipaddress.IPv4Address(ip)
            return True
        except ipaddress.AddressValueError:
            try:
                ipaddress.IPv6Address(ip)
                return True
            except ipaddress.AddressValueError:
                return False

    def _convert_ipinfo_format(self, data: Dict) -> Dict:
        """Convert ipinfo.io format to standard format"""
        return {
            'country': data.get('country', 'Unknown'),
            'countryCode': data.get('country', 'Unknown'),
            'city': data.get('city', 'Unknown'),
            'regionName': data.get('region', 'Unknown'),
            'zip': data.get('postal', 'Unknown'),
            'timezone': data.get('timezone', 'Unknown'),
            'isp': data.get('org', 'Unknown').split(' ')[0] if data.get('org') else 'Unknown',
            'org': data.get('org', 'Unknown'),
            'as': data.get('org', 'Unknown'),
            'loc': data.get('loc', '0,0'),
            'lat': data.get('loc', '0,0').split(',')[0] if data.get('loc') else '0',
            'lon': data.get('loc', '0,0').split(',')[1] if data.get('loc') and ',' in data.get('loc') else '0'
        }

    def _convert_ipwhois_format(self, data: Dict) -> Dict:
        """Convert ipwho.is format to standard format"""
        return {
            'country': data.get('country', 'Unknown'),
            'countryCode': data.get('country_code', 'Unknown'),
            'city': data.get('city', 'Unknown'),
            'regionName': data.get('region', 'Unknown'),
            'zip': data.get('postal', 'Unknown'),
            'timezone': data.get('timezone', {}).get('id', 'Unknown') if isinstance(data.get('timezone'), dict) else 'Unknown',
            'isp': data.get('connection', {}).get('isp', 'Unknown') if isinstance(data.get('connection'), dict) else 'Unknown',
            'org': data.get('connection', {}).get('org', 'Unknown') if isinstance(data.get('connection'), dict) else 'Unknown',
            'as': data.get('connection', {}).get('asn', 'Unknown') if isinstance(data.get('connection'), dict) else 'Unknown',
            'lat': data.get('latitude', 0),
            'lon': data.get('longitude', 0)
        }

# Test function
def test_geoip_locator():
    """Test the GeoIP locator with sample IPs"""
    locator = GeoIPLocator()
    
    test_ips = [
        "8.8.8.8",          # Google DNS (Clean)
        "1.1.1.1",          # Cloudflare DNS (Clean)
        "185.220.101.1",    # Test malicious IP
        "208.67.222.222"    # OpenDNS
    ]
    
    for ip in test_ips:
        print(f"\n=== Testing IP: {ip} ===")
        result = locator.locate_ip(ip)
        
        if result:
            print(f"Location: {result.city}, {result.country}")
            print(f"ISP: {result.isp}")
            print(f"Threat Level: {result.threat_level}")
            print(f"Is Tor: {result.is_tor}")
            print(f"Is Proxy: {result.is_proxy}")
        else:
            print("❌ Failed to analyze IP")

if __name__ == "__main__":
    test_geoip_locator()