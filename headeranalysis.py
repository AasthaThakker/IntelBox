import re
import email
from email.header import decode_header
from email.utils import parsedate_to_datetime
from email.message import EmailMessage
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
import datetime


@dataclass
class AuthenticationResult:
    spf_result: str
    dkim_result: str
    dmarc_result: str
    authentication_status: str

@dataclass
class EmailHeaderAnalysis:
    sender_info: Dict
    routing_path: List[Dict]
    authentication: AuthenticationResult
    security_indicators: List[str]
    risk_assessment: str
    analysis_summary: str
    # Add full email content for phishing detection
    full_email_content: str 

class EmailHeaderAnalyzer:
    def __init__(self):
        self.suspicious_headers = [
            'x-originating-ip',
            'x-sender-ip',
            'x-remote-ip'
        ]
        self.auth_headers = [
            'authentication-results',
            'received-spf',
            'dkim-signature',
            'arc-authentication-results'
        ]
    
    def parse_email_headers(self, email_content: str) -> Optional[EmailMessage]:
        try:
            if isinstance(email_content, str):
                msg = email.message_from_string(email_content)
            else:
                msg = email.message_from_bytes(email_content)
            return msg
        except Exception as e:
            print(f"Error parsing email: {e}")
            return None

    def extract_sender_info(self, msg: EmailMessage) -> Dict:
        sender_info = {}
        from_header = msg.get('From', '')
        reply_to_header = msg.get('Reply-To', '')

        # Extract full 'From' address
        sender_info['from_address'] = from_header

        # Extract email and domain from 'From' header
        email_match = re.search(r'<(.+?)>', from_header)
        sender_info['email'] = email_match.group(1) if email_match else from_header
        if '@' in sender_info['email']:
            sender_info['domain'] = sender_info['email'].split('@')[1].lower()
        else:
            sender_info['domain'] = '' # Default if no domain found

        # Extract full 'Reply-To' address
        sender_info['reply_to_address'] = reply_to_header
        
        # Check if Reply-To domain differs from From domain
        reply_to_domain = ''
        if '@' in reply_to_header:
            reply_to_domain = reply_to_header.split('@')[1].lower()
        sender_info['reply_to_differs'] = (reply_to_domain != '' and sender_info['domain'] != '' and reply_to_domain != sender_info['domain'])

        sender_info['return_path'] = msg.get('Return-Path', '')
        sender_info['message_id'] = msg.get('Message-ID', '')

        # Extract Subject header
        subject_header = msg.get('Subject', '')
        decoded_subject = ''
        try:
            # Decode potentially encoded subject headers
            decoded_parts = decode_header(subject_header)
            for part, charset in decoded_parts:
                if isinstance(part, bytes):
                    decoded_subject += part.decode(charset or 'utf-8', errors='ignore')
                else:
                    decoded_subject += part
        except Exception as e:
            print(f"Error decoding subject: {e}")
            decoded_subject = subject_header # Fallback to raw subject
        sender_info['subject'] = decoded_subject


        return sender_info

    def analyze_received_headers(self, msg: email.message.EmailMessage) -> List[Dict]:
        received_headers = msg.get_all('Received') or []
        routing_path = []

        for i, received in enumerate(received_headers):
            hop_info = {
                'hop_number': i + 1,
                'raw_header': received,
                'received_from': 'Unknown',
                'by_server': 'Unknown',
                'delay': 'N/A', # Placeholder for delay calculation
                'timestamp': None,
                'protocol': None
            }

            # Extract 'from' and 'by' parts
            from_match = re.search(r'from\s+([^\s]+)', received, re.IGNORECASE)
            if from_match:
                hop_info['received_from'] = from_match.group(1)
            
            by_match = re.search(r'by\s+([^\s]+)', received, re.IGNORECASE)
            if by_match:
                hop_info['by_server'] = by_match.group(1)

            timestamp_match = re.search(r';\s*(.+)', received)
            if timestamp_match:
                try:
                    dt = parsedate_to_datetime(timestamp_match.group(1).strip())
                    hop_info['timestamp'] = dt.isoformat()
                except Exception:
                    hop_info['timestamp'] = timestamp_match.group(1).strip()

            protocol_match = re.search(r'with\s+([^\s]+)', received, re.IGNORECASE)
            if protocol_match:
                hop_info['protocol'] = protocol_match.group(1)

            # Basic delay calculation (requires previous hop's timestamp)
            if i > 0 and routing_path[i-1]['timestamp'] and hop_info['timestamp']:
                try:
                    prev_time = datetime.datetime.fromisoformat(routing_path[i-1]['timestamp'])
                    current_time = datetime.datetime.fromisoformat(hop_info['timestamp'])
                    delay_seconds = (current_time - prev_time).total_seconds()
                    hop_info['delay'] = f"{delay_seconds:.2f}s"
                except Exception:
                    pass


            routing_path.append(hop_info)
        
        return routing_path

    def analyze_authentication(self, msg: email.message.EmailMessage) -> AuthenticationResult:
        auth_results = msg.get('Authentication-Results', '')
        received_spf = msg.get('Received-SPF', '')
        dkim_signature = msg.get('DKIM-Signature', '')

        spf_result = "Not Found"
        dkim_result = "Not Found"
        dmarc_result = "Not Found"

        if received_spf:
            spf_result = self._extract_result(received_spf)

        if auth_results:
            spf_match = re.search(r'spf=(\w+)', auth_results.lower())
            if spf_match:
                spf_result = spf_match.group(1).upper()

            dkim_match = re.search(r'dkim=(\w+)', auth_results.lower())
            if dkim_match:
                dkim_result = dkim_match.group(1).upper()

            dmarc_match = re.search(r'dmarc=(\w+)', auth_results.lower())
            if dmarc_match:
                dmarc_result = dmarc_match.group(1).upper()

        if dkim_signature and dkim_result == "Not Found":
            dkim_result = "PRESENT"

        if spf_result == "PASS" and dkim_result in ["PASS", "PRESENT"] and dmarc_result == "PASS":
            auth_status = "AUTHENTICATED"
        elif spf_result == "FAIL" or dkim_result == "FAIL" or dmarc_result == "FAIL":
            auth_status = "FAILED"
        else:
            auth_status = "PARTIAL"

        return AuthenticationResult(spf_result, dkim_result, dmarc_result, auth_status)

    def _extract_result(self, header_value: str) -> str:
        header_value = header_value.lower()
        for keyword in ['pass', 'fail', 'softfail', 'neutral', 'none']:
            if keyword in header_value:
                return keyword.upper()
        return "UNKNOWN"

    def detect_security_indicators(self, msg: email.message.EmailMessage, 
                                    sender_info: Dict, routing_path: List[Dict],
                                    auth_result: AuthenticationResult) -> Tuple[List[str], str]:
        indicators = []
        risk_level = "LOW"

        if auth_result.spf_result == "FAIL":
            indicators.append("SPF authentication failed")
            risk_level = "HIGH"

        if auth_result.dkim_result == "FAIL":
            indicators.append("DKIM authentication failed")
            risk_level = "HIGH"

        if auth_result.dmarc_result == "FAIL":
            indicators.append("DMARC authentication failed")
            risk_level = "HIGH"

        if auth_result.spf_result == "Not Found" or auth_result.spf_result == "NONE":
            indicators.append("No SPF record found or SPF not evaluated")
            risk_level = "MEDIUM" if risk_level == "LOW" else risk_level

        if auth_result.dkim_result == "Not Found" or auth_result.dkim_result == "NONE":
            indicators.append("No DKIM signature found or DKIM not evaluated")
            risk_level = "MEDIUM" if risk_level == "LOW" else risk_level

        if auth_result.dmarc_result == "Not Found" or auth_result.dmarc_result == "NONE":
            indicators.append("No DMARC record found or DMARC not evaluated")
            risk_level = "MEDIUM" if risk_level == "LOW" else risk_level


        from_domain = sender_info.get('domain', '')
        reply_to_address = sender_info.get('reply_to_address', '')

        if sender_info.get('reply_to_differs', False):
            reply_domain = reply_to_address.split('@')[1].lower() if '@' in reply_to_address else ''
            indicators.append(f"Reply-To domain ({reply_domain}) differs from From domain ({from_domain})")
            risk_level = "MEDIUM" if risk_level == "LOW" else risk_level

        for header_name in self.suspicious_headers:
            if msg.get(header_name):
                indicators.append(f"Suspicious header found: {header_name}")
                risk_level = "MEDIUM" if risk_level == "LOW" else risk_level

        if len(routing_path) > 10:
            indicators.append(f"Unusually long routing path: {len(routing_path)} hops")
            risk_level = "MEDIUM" if risk_level == "LOW" else risk_level
        
        # Check for discrepancies in Received headers (simplified)
        # This is a complex check, but a basic one could be:
        # If the 'from' part of a Received header doesn't match the actual sender IP/domain
        # (This would require IP lookup for each hop, which is beyond simple header analysis here)
        # For now, rely on authentication results for spoofing.

        return indicators, risk_level

    def analyze_headers(self, email_content: str) -> Optional[EmailHeaderAnalysis]:
        msg = self.parse_email_headers(email_content)
        if not msg:
            return None

        sender_info = self.extract_sender_info(msg)
        routing_path = self.analyze_received_headers(msg)
        auth_result = self.analyze_authentication(msg)
        security_indicators, risk_level = self.detect_security_indicators(
            msg, sender_info, routing_path, auth_result
        )
        summary = self.generate_analysis_summary(sender_info, auth_result, risk_level)

        return EmailHeaderAnalysis(
            sender_info=sender_info,
            routing_path=routing_path,
            authentication=auth_result,
            security_indicators=security_indicators,
            risk_assessment=risk_level,
            analysis_summary=summary,
            full_email_content=email_content # Store full content for phishing detector
        )

    def generate_analysis_summary(self, sender_info: Dict, 
                                  auth_result: AuthenticationResult, 
                                  risk_level: str) -> str:
        domain = sender_info.get('domain', 'Unknown')
        if risk_level == "HIGH":
            return f"⚠️ HIGH RISK: Email from {domain} failed authentication checks. Exercise extreme caution."
        elif risk_level == "MEDIUM":
            return f"⚡ MEDIUM RISK: Email from {domain} has some authentication issues. Review carefully."
        else:
            return f"✅ LOW RISK: Email from {domain} appears legitimate with proper authentication."

    def generate_detailed_report(self, analysis: EmailHeaderAnalysis) -> str:
        report = f"""
=== Email Header Analysis Report ===

{analysis.analysis_summary}

SENDER INFORMATION:
From: {analysis.sender_info.get('from_address', 'N/A')}
Email: {analysis.sender_info.get('email', 'N/A')}
Domain: {analysis.sender_info.get('domain', 'N/A')}
Reply-To: {analysis.sender_info.get('reply_to_address', 'N/A')}
Return-Path: {analysis.sender_info.get('return_path', 'N/A')}
Message-ID: {analysis.sender_info.get('message_id', 'N/A')}
Subject: {analysis.sender_info.get('subject', 'N/A')}

AUTHENTICATION RESULTS:
SPF: {analysis.authentication.spf_result}
DKIM: {analysis.authentication.dkim_result}
DMARC: {analysis.authentication.dmarc_result}
Overall Status: {analysis.authentication.authentication_status}

ROUTING PATH:
Total Hops: {len(analysis.routing_path)}
"""
        for hop in analysis.routing_path[:5]:
            report += f"Hop {hop['hop_number']}: From {hop.get('received_from', 'Unknown')} by {hop.get('by_server', 'Unknown')} [{hop.get('protocol', 'Unknown')}] @ {hop.get('timestamp', 'N/A')} (Delay: {hop.get('delay', 'N/A')})\n"

        if len(analysis.routing_path) > 5:
            report += f"... and {len(analysis.routing_path) - 5} more hops\n"

        report += f"\nSECURITY INDICATORS:\n"
        if analysis.security_indicators:
            for indicator in analysis.security_indicators:
                report += f"⚠️ {indicator}\n"
        else:
            report += "✅ No security concerns detected\n"

        report += f"\nRISK ASSESSMENT: {analysis.risk_assessment}\n"
        return report

# Sample usage
def demo_email_analyzer():
    analyzer = EmailHeaderAnalyzer()

    sample_email = """From: security@paypal.com
Reply-To: noreply@suspicious-domain.tk
To: victim@company.com
Subject: Urgent: Verify Your Account
Message-ID: <123456789@suspicious-domain.tk>
Received: from mail.suspicious-domain.tk (mail.suspicious-domain.tk [192.168.1.100])
    by mx.company.com with ESMTP id ABC123
    for <victim@company.com>; Mon, 1 Jan 2024 12:00:00 +0000
Received: from [10.0.0.1] (unknown [203.0.113.1])
    by mail.suspicious-domain.tk with ESMTP id XYZ789; Mon, 1 Jan 2024 11:59:30 +0000
Authentication-Results: mx.company.com;
    spf=fail (sender IP is 203.0.113.1) smtp.mailfrom=suspicious-domain.tk;
    dkim=none;
    dmarc=fail (p=reject dis=none) header.from=paypal.com
Received-SPF: fail (mx.company.com: domain of suspicious-domain.tk does not designate 203.0.113.1 as permitted sender)

This is a test email for header analysis.
Click here to verify your account: http://badlink.example.com/verify
"""
    print("=== Email Header Analysis ===")
    analysis = analyzer.analyze_headers(sample_email)
    if analysis:
        print(analyzer.generate_detailed_report(analysis))
    else:
        print("Failed to analyze email headers")

if __name__ == "__main__":
    demo_email_analyzer()
