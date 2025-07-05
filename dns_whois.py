import dns.resolver
import whois
import logging
import datetime
from typing import Dict, List, Optional, Union
from dataclasses import dataclass

logger = logging.getLogger(__name__)

@dataclass
class DNSWHOISResult:
    """
    Represents the combined DNS and WHOIS lookup result for a domain.
    """
    domain: str
    a_records: List[str]
    mx_records: List[str]
    spf_record: Optional[str]
    ns_records: List[str]
    whois_info: Dict
    is_newly_registered: bool
    is_short_lifecycle: bool
    risk_score: int
    summary: str

class DNSWHOISIntelligence:
    """
    Provides intelligence by querying DNS records and WHOIS information for domains.
    Helps identify suspicious domain characteristics like new registration or short lifecycles.
    """
    def __init__(self):
        # Configure DNS resolver (optional, uses system defaults if not set)
        # dns.resolver.default_resolver = dns.resolver.Resolver(configure=False)
        # dns.resolver.default_resolver.nameservers = ['8.8.8.8', '8.8.4.4'] # Google DNS

        self.min_domain_age_days_for_suspicion = 90 # Domains younger than this are suspicious
        self.max_domain_lifecycle_days_for_suspicion = 365 # Domains registered for less than this are suspicious

    def _query_dns_records(self, domain: str, record_type: str) -> List[str]:
        """
        Queries DNS records for a given domain and record type.
        """
        records = []
        try:
            answers = dns.resolver.resolve(domain, record_type)
            for rdata in answers:
                records.append(str(rdata))
        except dns.resolver.NoAnswer:
            logger.info(f"No {record_type} record found for {domain}")
        except dns.resolver.NXDOMAIN:
            logger.warning(f"Domain '{domain}' does not exist (NXDOMAIN).")
        except dns.resolver.Timeout:
            logger.error(f"DNS query for {domain} timed out.")
        except Exception as e:
            logger.error(f"Error querying {record_type} for {domain}: {e}")
        return records

    def _query_whois(self, domain: str) -> Dict:
        """
        Queries WHOIS information for a given domain.
        """
        whois_data = {}
        try:
            w = whois.whois(domain)
            if w:
                whois_data = {
                    'domain_name': w.domain_name,
                    'registrar': w.registrar,
                    'creation_date': str(w.creation_date),
                    'expiration_date': str(w.expiration_date),
                    'updated_date': str(w.updated_date),
                    'name_servers': w.name_servers,
                    'emails': w.emails,
                    'org': w.org,
                    'state': w.state,
                    'country': w.country
                }
            else:
                logger.info(f"No WHOIS data found for {domain}")
        except whois.parser.PywhoisError as e:
            logger.warning(f"WHOIS lookup error for {domain}: {e}")
        except Exception as e:
            logger.error(f"Error querying WHOIS for {domain}: {e}")
        return whois_data

    def analyze_domain(self, domain: str) -> DNSWHOISResult:
        """
        Performs comprehensive DNS and WHOIS analysis for a domain.
        """
        if not domain:
            raise ValueError("Domain cannot be empty.")

        a_records = self._query_dns_records(domain, 'A')
        mx_records = self._query_dns_records(domain, 'MX')
        ns_records = self._query_dns_records(domain, 'NS')
        
        spf_record = None
        txt_records = self._query_dns_records(domain, 'TXT')
        for txt in txt_records:
            if 'v=spf' in txt.lower():
                spf_record = txt
                break

        whois_info = self._query_whois(domain)

        is_newly_registered = False
        is_short_lifecycle = False
        risk_score = 0
        indicators = []

        # Check for newly registered domains
        creation_date_str = whois_info.get('creation_date')
        if creation_date_str:
            try:
                # Handle multiple creation dates if WHOIS returns a list
                if isinstance(creation_date_str, list):
                    creation_date_str = creation_date_str[0]
                
                # Attempt to parse common date formats
                creation_date = None
                for fmt in ['%Y-%m-%d %H:%M:%S', '%Y-%m-%d', '%Y%m%d', '%Y.%m.%d', '%d-%b-%Y', '%d-%b-%Y %H:%M:%S']:
                    try:
                        creation_date = datetime.datetime.strptime(creation_date_str, fmt)
                        break
                    except ValueError:
                        continue

                if creation_date:
                    age_days = (datetime.datetime.now() - creation_date).days
                    if age_days < self.min_domain_age_days_for_suspicion:
                        is_newly_registered = True
                        indicators.append(f"Newly registered domain (age: {age_days} days).")
                        risk_score += 5
                else:
                    logger.warning(f"Could not parse creation date: {creation_date_str}")
            except Exception as e:
                logger.error(f"Error processing creation date: {e}")

        # Check for short-lifecycle domains (based on expiration date)
        expiration_date_str = whois_info.get('expiration_date')
        if expiration_date_str:
            try:
                # Handle multiple expiration dates if WHOIS returns a list
                if isinstance(expiration_date_str, list):
                    expiration_date_str = expiration_date_str[0]

                expiration_date = None
                for fmt in ['%Y-%m-%d %H:%M:%S', '%Y-%m-%d', '%Y%m%d', '%Y.%m.%d', '%d-%b-%Y', '%d-%b-%Y %H:%M:%S']:
                    try:
                        expiration_date = datetime.datetime.strptime(expiration_date_str, fmt)
                        break
                    except ValueError:
                        continue
                
                if expiration_date and creation_date: # Need both to calculate lifecycle
                    lifecycle_days = (expiration_date - creation_date).days
                    if lifecycle_days > 0 and lifecycle_days < self.max_domain_lifecycle_days_for_suspicion:
                        is_short_lifecycle = True
                        indicators.append(f"Short domain lifecycle ({lifecycle_days} days).")
                        risk_score += 4
                else:
                    logger.warning(f"Could not parse expiration date: {expiration_date_str}")
            except Exception as e:
                logger.error(f"Error processing expiration date: {e}")

        # Additional risk indicators based on DNS records
        if not a_records:
            indicators.append("No A records found (domain might not resolve).")
            risk_score += 2
        if not mx_records:
            indicators.append("No MX records found (domain cannot receive emails).")
            risk_score += 1
        if not spf_record:
            indicators.append("No SPF record found (email sender authentication weak).")
            risk_score += 2
        if not ns_records:
            indicators.append("No NS records found (domain might be misconfigured).")
            risk_score += 1

        # Check for suspicious registrar (simple example, needs a list of known bad registrars)
        suspicious_registrars = ['namecheap.com', 'godaddy.com'] # Example, not exhaustive
        registrar = whois_info.get('registrar', '').lower()
        if any(sr in registrar for sr in suspicious_registrars):
            indicators.append(f"Registered with a potentially suspicious registrar: {registrar}")
            risk_score += 2

        # Summarize findings
        summary = "Domain analysis completed."
        if risk_score >= 8:
            summary = "HIGH RISK: This domain shows strong signs of being malicious or part of a phishing campaign."
        elif risk_score >= 5:
            summary = "MEDIUM RISK: This domain has several suspicious characteristics. Proceed with caution."
        elif risk_score >= 2:
            summary = "LOW RISK: This domain has minor suspicious characteristics or misconfigurations."
        else:
            summary = "CLEAN: This domain appears legitimate based on DNS and WHOIS data."

        return DNSWHOISResult(
            domain=domain,
            a_records=a_records,
            mx_records=mx_records,
            spf_record=spf_record,
            ns_records=ns_records,
            whois_info=whois_info,
            is_newly_registered=is_newly_registered,
            is_short_lifecycle=is_short_lifecycle,
            risk_score=min(risk_score, 10), # Cap score at 10
            summary=summary
        )

# Example usage (for testing this module directly)
if __name__ == "__main__":
    analyzer = DNSWHOISIntelligence()

    print("\n--- Analyzing google.com ---")
    result_google = analyzer.analyze_domain("google.com")
    print(f"Domain: {result_google.domain}")
    print(f"A Records: {result_google.a_records}")
    print(f"MX Records: {result_google.mx_records}")
    print(f"SPF Record: {result_google.spf_record}")
    print(f"NS Records: {result_google.ns_records}")
    print(f"WHOIS Info (partial): {result_google.whois_info.get('registrar', 'N/A')}, Created: {result_google.whois_info.get('creation_date', 'N/A')}")
    print(f"Newly Registered: {result_google.is_newly_registered}")
    print(f"Short Lifecycle: {result_google.is_short_lifecycle}")
    print(f"Risk Score: {result_google.risk_score}")
    print(f"Summary: {result_google.summary}")

    print("\n--- Analyzing example.tk (likely newly registered/suspicious TLD) ---")
    # This domain is often used for testing and might be newly registered or have short lifecycle
    # The actual results depend on the live WHOIS data at the time of execution.
    result_tk = analyzer.analyze_domain("example.tk")
    print(f"Domain: {result_tk.domain}")
    print(f"A Records: {result_tk.a_records}")
    print(f"MX Records: {result_tk.mx_records}")
    print(f"SPF Record: {result_tk.spf_record}")
    print(f"NS Records: {result_tk.ns_records}")
    print(f"WHOIS Info (partial): {result_tk.whois_info.get('registrar', 'N/A')}, Created: {result_tk.whois_info.get('creation_date', 'N/A')}")
    print(f"Newly Registered: {result_tk.is_newly_registered}")
    print(f"Short Lifecycle: {result_tk.is_short_lifecycle}")
    print(f"Risk Score: {result_tk.risk_score}")
    print(f"Summary: {result_tk.summary}")

    print("\n--- Analyzing a non-existent domain (example.nonexistent) ---")
    result_nonexistent = analyzer.analyze_domain("example.nonexistent")
    print(f"Domain: {result_nonexistent.domain}")
    print(f"A Records: {result_nonexistent.a_records}")
    print(f"MX Records: {result_nonexistent.mx_records}")
    print(f"SPF Record: {result_nonexistent.spf_record}")
    print(f"NS Records: {result_nonexistent.ns_records}")
    print(f"WHOIS Info (partial): {result_nonexistent.whois_info.get('registrar', 'N/A')}")
    print(f"Newly Registered: {result_nonexistent.is_newly_registered}")
    print(f"Short Lifecycle: {result_nonexistent.is_short_lifecycle}")
    print(f"Risk Score: {result_nonexistent.risk_score}")
    print(f"Summary: {result_nonexistent.summary}")