import re
import logging
import joblib
import os
import pandas as pd
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from urllib.parse import urlparse
# Removed: import json # No longer needed without LLM API calls
# Removed: import httpx # No longer needed without LLM API calls

logger = logging.getLogger(__name__)

@dataclass
class PhishingDetectionResult:
    """
    Represents the result of a phishing detection analysis.
    """
    classification: str  # e.g., 'Phishing', 'Spam', 'Safe'
    confidence: float    # Confidence score of the classification
    indicators: List[str] # Specific indicators found
    risk_score: int      # Overall risk score (0-10)
    summary: str         # A concise summary of the analysis

class PhishingDetector:
    """
    A class to detect phishing emails using a combination of heuristic rules
    and a trained machine learning model. LLM integration has been removed.
    """
    def __init__(self, model_path: str = 'phishing_model.joblib', vectorizer_path: str = 'phishing_vectorizer.joblib'):
        self.model = None
        self.vectorizer = None
        self.model_path = model_path
        self.vectorizer_path = vectorizer_path

        # Heuristic rules and keywords
        self.phishing_keywords = [
            'verify', 'account', 'update', 'security', 'alert', 'login', 'password',
            'urgent', 'action required', 'suspended', 'locked', 'transaction',
            'invoice', 'payment', 'delivery', 'shipping', 'failed delivery',
            'click here', 'confirm', 'unusual activity', 'compromised', 'suspicious',
            'unauthorized', 'deactivated', 'limited', 'important notice', 'fraud'
        ]
        self.suspicious_tlds = [
            '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.bid', '.win',
            '.loan', '.men', '.work', '.date', '.review', '.stream', '.download',
            '.link', '.click', '.party', '.science', '.faith', '.zip', '.icu', '.club'
        ]
        self.common_email_providers = [
            'gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com', 'aol.com',
            'protonmail.com', 'icloud.com', 'mail.com'
        ]

        # Load model and vectorizer, or train dummy model
        self._load_model_and_vectorizer()

    def _load_model_and_vectorizer(self):
        """
        Loads the pre-trained ML model and TF-IDF vectorizer.
        If not found, it trains a dummy model for demonstration purposes.
        In a real application, these would be trained on a large dataset.
        """
        if os.path.exists(self.model_path) and os.path.exists(self.vectorizer_path):
            try:
                self.model = joblib.load(self.model_path)
                self.vectorizer = joblib.load(self.vectorizer_path)
                logger.info("Loaded existing ML model and vectorizer.")
            except Exception as e:
                logger.warning(f"Error loading model/vectorizer: {e}. Training dummy model.")
                self._train_dummy_model()
        else:
            logger.info("Model or vectorizer not found. Training dummy model.")
            self._train_dummy_model()

    def _train_dummy_model(self):
        """
        Trains a very basic dummy ML model (Logistic Regression) and TF-IDF vectorizer.
        This is for demonstration purposes only. A real phishing detector requires
        extensive training data and feature engineering.
        """
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.linear_model import LogisticRegression
        from sklearn.pipeline import Pipeline

        # Dummy data for training, focusing on email body content
        emails = [
            "Your account has been suspended. Click here to verify immediately.", # Phishing
            "Hello, this is a test email. No action required.",                  # Safe
            "Win a free iPhone! Click now to claim your prize!",                 # Spam
            "Urgent security alert: Your password needs reset to avoid lockout.",# Phishing
            "Meeting reminder for tomorrow morning at 10 AM.",                   # Safe
            "You have won a lottery! Claim your prize by providing your details.",# Spam
            "Please update your billing information immediately to prevent service interruption.", # Phishing
            "Regarding your recent order #12345, it has been shipped.",         # Safe
            "Congratulations, you've been selected for an exclusive offer!",     # Spam
            "Important notice about your bank account. Review suspicious activity.",# Phishing
            "Your Netflix account is on hold. Update your payment details.",     # Phishing
            "Exclusive discount for loyal customers. Limited time offer!",       # Spam
            "Your Amazon order has shipped. Track it here.",                    # Safe
            "We detected unusual sign-in activity on your Microsoft account.",   # Phishing
            "Get rich quick! Invest in this amazing opportunity now!"           # Spam
        ]
        labels = [
            'Phishing', 'Safe', 'Spam', 'Phishing', 'Safe', 'Spam', 'Phishing',
            'Safe', 'Spam', 'Phishing', 'Phishing', 'Spam', 'Safe', 'Phishing', 'Spam'
        ]

        df = pd.DataFrame({'text': emails, 'label': labels})

        self.vectorizer = TfidfVectorizer(stop_words='english', max_features=2000, ngram_range=(1, 2))
        X_text = self.vectorizer.fit_transform(df['text'])

        self.model = LogisticRegression(max_iter=1000, solver='liblinear')
        self.model.fit(X_text, df['label'])

        try:
            joblib.dump(self.model, self.model_path)
            joblib.dump(self.vectorizer, self.vectorizer_path)
            logger.info("Dummy ML model and vectorizer trained and saved.")
        except Exception as e:
            logger.error(f"Failed to save dummy model/vectorizer: {e}")

    def _extract_features(self, email_body: str) -> pd.DataFrame:
        """
        Extracts features from email body for the ML model.
        """
        features = {}
        text_lower = email_body.lower()
        
        features['body_length'] = len(text_lower)
        features['num_links'] = len(re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', text_lower))
        features['phishing_keyword_count'] = sum(1 for kw in self.phishing_keywords if kw in text_lower)

        df_features = pd.DataFrame([features])
        df_features['text'] = email_body # Add original text for vectorizer

        return df_features

    def _apply_heuristics(self, email_body: str) -> Tuple[List[str], int]:
        """
        Applies heuristic rules to identify indicators and assign a risk score.
        LLM analysis integration has been removed.
        """
        indicators = []
        heuristic_score = 0
        text_lower = email_body.lower()
        
        # Heuristic 1: Suspicious keywords in body
        found_keywords = [kw for kw in self.phishing_keywords if kw in text_lower]
        if found_keywords:
            indicators.append(f"Contains suspicious keywords: {', '.join(set(found_keywords[:3]))}...")
            heuristic_score += len(set(found_keywords)) # Add score based on unique keywords

        # Heuristic 2: Suspicious URLs in body
        urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', text_lower)
        for url in urls:
            parsed_url = urlparse(url)
            domain = parsed_url.netloc.lower()
            if not domain:
                continue

            # Check for IP address in domain
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain):
                indicators.append(f"URL uses IP address instead of domain: {domain}")
                heuristic_score += 4
            
            # Check for suspicious TLDs in URLs
            if any(domain.endswith(tld) for tld in self.suspicious_tlds):
                indicators.append(f"URL contains suspicious TLD: {domain}")
                heuristic_score += 3

            # Check for long, obfuscated URLs
            if len(url) > 100 and ('%' in url or 'xn--' in url): # Added punycode check
                indicators.append(f"Long and potentially obfuscated URL: {url[:50]}...")
                heuristic_score += 2
            
            # Check for multiple subdomains (phishing often uses many subdomains to hide true domain)
            subdomain_count = domain.count('.') - 1
            if subdomain_count > 3:
                indicators.append(f"Excessive subdomains in URL: {domain}")
                heuristic_score += 2
        
        # Removed: Heuristic 3: LLM Sentiment and Emotion Analysis
        # All LLM-related sentiment/emotion logic removed from here.

        # Cap the heuristic score at a reasonable maximum
        heuristic_score = min(heuristic_score, 10)

        return indicators, heuristic_score

    def classify_email(self, email_body: str) -> PhishingDetectionResult:
        """
        Classifies an email (body content only) as phishing, spam, or safe.
        Uses ML model prediction with heuristic analysis. LLM integration has been removed.
        """
        if not self.model or not self.vectorizer:
            logger.error("ML model or vectorizer not loaded. Cannot classify email.")
            return PhishingDetectionResult(
                classification="Error",
                confidence=0.0,
                indicators=["ML model not loaded"],
                risk_score=10,
                summary="System error: ML model not ready."
            )

        # Removed: 1. LLM Sentiment and Emotion Analysis
        
        # 1. ML Model Prediction (re-numbered)
        try:
            X_transformed = self.vectorizer.transform([email_body])
            
            prediction_proba = self.model.predict_proba(X_transformed)[0]
            predicted_class_index = prediction_proba.argmax()
            predicted_class = self.model.classes_[predicted_class_index]
            confidence = prediction_proba[predicted_class_index]
        except Exception as e:
            logger.error(f"Error during ML prediction: {e}")
            return PhishingDetectionResult(
                classification="Error",
                confidence=0.0,
                indicators=["ML prediction failed"],
                risk_score=10,
                summary="System error during ML prediction."
            )

        # 2. Heuristic Assessment (re-numbered, now without LLM insights)
        heuristic_indicators, heuristic_score = self._apply_heuristics(email_body)
        
        # Combine ML prediction with heuristic assessment
        final_indicators = list(set(heuristic_indicators)) # Remove duplicates
        
        # Adjust risk score based on ML prediction
        ml_risk_mapping = {
            'Phishing': 8,
            'Spam': 5,
            'Safe': 1
        }
        ml_risk = ml_risk_mapping.get(predicted_class, 0)
        
        # Combine scores: give more weight to ML if confidence is high, or take higher of the two
        combined_risk_score = max(ml_risk, heuristic_score) # Take the higher of the two
        combined_risk_score = min(combined_risk_score, 10) # Cap at 10

        # Determine final classification and summary
        final_classification = predicted_class
        summary = f"ML classified as {predicted_class} with {confidence:.2f} confidence. "
        
        if combined_risk_score >= 8:
            final_classification = "Phishing"
            summary += "HIGH RISK: This email exhibits strong indicators of a phishing attempt."
        elif combined_risk_score >= 5:
            if final_classification == "Safe": # If ML said safe, but heuristics are medium, upgrade to spam
                final_classification = "Spam"
            summary += "MEDIUM RISK: This email has suspicious elements. Exercise caution."
        elif combined_risk_score >= 2:
            if final_classification == "Safe":
                summary += "LOW RISK: This email appears safe but has minor suspicious characteristics."
            else:
                summary += "LOW RISK: This email is likely spam or promotional."
        else:
            final_classification = "Safe"
            summary += "CLEAN: This email appears safe with no significant threats detected."

        return PhishingDetectionResult(
            classification=final_classification,
            confidence=float(f"{confidence:.2f}"), # Ensure float for JSON serialization
            indicators=final_indicators,
            risk_score=combined_risk_score,
            summary=summary
        )

# Example usage (for testing this module directly)
if __name__ == "__main__":
    detector = PhishingDetector()

    # Sample email body (phishing)
    sample_body_phishing = """
    Dear Customer,

    Your PayPal account has been temporarily suspended due to unusual activity.
    Please click on the link below to verify your account immediately:

    http://paypal-verify.security-update.tk/login?id=12345

    Failure to do so will result in permanent account closure.

    Thank you,
    PayPal Security Team
    """

    # Sample email body (spam/promotional)
    sample_body_spam = """
    Congratulations! You've been selected for a once-in-a-lifetime opportunity to win a brand new iPhone 16!
    Simply click this link to claim your prize now:

    http://free-iphone-giveaway.xyz/claim?prize=iphone16

    Don't miss out, this offer is for a limited time only!
    """

    # Sample email body (safe)
    sample_body_safe = """
    Hello John,

    This is a regular update regarding your Google account. No action is needed.
    You can review your security settings at:

    https://myaccount.google.com/security

    Best regards,
    The Google Team
    """
    
    # Another safe email
    sample_body_safe_2 = """
    Hi Team,

    Just a reminder that our weekly project sync meeting is scheduled for tomorrow at 10 AM in Conference Room B.
    Please come prepared to discuss your progress on task #456.

    Thanks,
    Sarah
    """

    print("\n--- Phishing Email (Body Only) ---")
    result = detector.classify_email(sample_body_phishing)
    print(f"Classification: {result.classification}")
    print(f"Confidence: {result.confidence}")
    print(f"Risk Score: {result.risk_score}")
    print(f"Indicators: {result.indicators}")
    print(f"Summary: {result.summary}")

    print("\n--- Spam Email (Body Only) ---")
    result = detector.classify_email(sample_body_spam)
    print(f"Classification: {result.classification}")
    print(f"Confidence: {result.confidence}")
    print(f"Risk Score: {result.risk_score}")
    print(f"Indicators: {result.indicators}")
    print(f"Summary: {result.summary}")

    print("\n--- Safe Email (Body Only) ---")
    result = detector.classify_email(sample_body_safe)
    print(f"Classification: {result.classification}")
    print(f"Confidence: {result.confidence}")
    print(f"Risk Score: {result.risk_score}")
    print(f"Indicators: {result.indicators}")
    print(f"Summary: {result.summary}")

    print("\n--- Safe Email 2 (Body Only) ---")
    result = detector.classify_email(sample_body_safe_2)
    print(f"Classification: {result.classification}")
    print(f"Confidence: {result.confidence}")
    print(f"Risk Score: {result.risk_score}")
    print(f"Indicators: {result.indicators}")
    print(f"Summary: {result.summary}")
