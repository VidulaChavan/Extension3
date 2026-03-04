"""
URL Feature Extraction Module
Enhanced Version with Advanced Phishing Detection Layers
Layer 1: Strong URL Structure Features
Layer 2: Brand Impersonation Detection
Layer 3: Redirect & URL Trick Detection
"""

import re
import math
from urllib.parse import urlparse
import numpy as np

class URLFeatureExtractor:
    def __init__(self):
        # Original suspicious keywords
        self.suspicious_keywords = [
            'login', 'verify', 'update', 'bank', 'secure', 'account'
        ]
        
        # Urgent words from content rules
        self.urgent_words = ['urgent', 'verify', 'suspend', 'limited time', 'click now']
        
        # NEW: Suspicious TLDs
        self.suspicious_tlds = ['xyz', 'top', 'ru', 'tk', 'ml', 'ga', 'cf']
        
        # NEW: Brand keywords commonly impersonated
        self.brand_keywords = [
            'paypal', 'amazon', 'google', 'microsoft',
            'apple', 'netflix', 'bank', 'icici', 'hdfc', 'sbi'
        ]

    def extract_features(self, url, page_text="", links_count=0):
        """
        Extract all features from URL and page context
        Matches both urlFeatures.js and contentScript.js URL detection
        """
        url = str(url).lower().strip()

        # Add protocol if missing
        url_with_protocol = url
        if not url.startswith(('http://', 'https://')):
            url_with_protocol = 'http://' + url

        parsed = urlparse(url_with_protocol)
        hostname = parsed.hostname or ""

        features = {
            # ========================
            # ORIGINAL FEATURES
            # ========================
            'url_length': self._get_url_length(url),
            'has_ip': self._has_ip_address(url),
            'has_at_symbol': self._has_at_symbol(url),
            'subdomain_count': self._count_subdomains(url_with_protocol),
            'is_https': self._is_https(url),
            'special_char_count': self._count_special_chars(url),
            'has_suspicious_keyword': self._has_suspicious_keyword(url),
            
            # From contentScript.js URL rules
            'has_login_verify': self._has_login_verify(url),
            'has_too_many_links': 1 if links_count > 50 else 0,
            'has_urgent_words': self._has_urgent_words(page_text),

            # ========================
            # LAYER 1 - Strong URL Structure
            # ========================
            'url_entropy': self._calculate_entropy(url),
            'digit_count': self._count_digits(url),
            'hyphen_count': self._count_hyphens(url),
            'domain_length': len(hostname),
            'is_suspicious_tld': self._is_suspicious_tld(hostname),

            # ========================
            # LAYER 2 - Brand Impersonation
            # ========================
            'has_brand_name': self._has_brand_name(url, hostname),

            # ========================
            # LAYER 3 - Redirect Tricks
            # ========================
            'has_redirect_pattern': self._has_redirect_pattern(url)
        }

        return features

    def extract_features_array(self, url, page_text="", links_count=0):
        """Extract features as array for model input"""
        features = self.extract_features(url, page_text, links_count)
        return np.array(list(features.values()))

    # ========================
    # ORIGINAL METHODS
    # ========================

    def _get_url_length(self, url):
        return len(url)

    def _has_ip_address(self, url):
        # Check for IPv4 pattern
        ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        return 1 if re.search(ip_pattern, url) else 0

    def _has_at_symbol(self, url):
        return 1 if '@' in url else 0

    def _count_subdomains(self, url):
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname or ''
            parts = hostname.split('.')
            # subdomain count = total parts - 2 (domain + TLD)
            return max(0, len(parts) - 2)
        except:
            return 0

    def _is_https(self, url):
        return 1 if url.startswith('https') else 0

    def _count_special_chars(self, url):
        special_chars = re.findall(r'[-_?=&]', url)
        return len(special_chars)

    def _has_suspicious_keyword(self, url):
        for keyword in self.suspicious_keywords:
            if keyword in url:
                return 1
        return 0

    def _has_login_verify(self, url):
        return 1 if ('login' in url or 'verify' in url) else 0

    def _has_urgent_words(self, text):
        text_lower = text.lower()
        for word in self.urgent_words:
            if word in text_lower:
                return 1
        return 0

    # ========================
    # NEW LAYER 1 METHODS
    # ========================

    def _calculate_entropy(self, text):
        """Detect randomness in URL"""
        prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
        entropy = -sum([p * math.log2(p) for p in prob])
        return round(entropy, 3)

    def _count_digits(self, url):
        return sum(c.isdigit() for c in url)

    def _count_hyphens(self, url):
        return url.count('-')

    def _is_suspicious_tld(self, hostname):
        parts = hostname.split('.')
        if len(parts) > 1:
            tld = parts[-1]
            return 1 if tld in self.suspicious_tlds else 0
        return 0

    # ========================
    # NEW LAYER 2 METHOD
    # ========================

    def _has_brand_name(self, url, hostname):
        """
        Detect brand name in URL but not official domain
        Example: paypal-secure-login.xyz
        """
        for brand in self.brand_keywords:
            if brand in url and brand not in hostname.split('.')[-2]:
                return 1
        return 0

    # ========================
    # NEW LAYER 3 METHOD
    # ========================

    def _has_redirect_pattern(self, url):
        redirect_patterns = ['redirect=', 'url=', 'next=', 'return=', 'goto=']
        for pattern in redirect_patterns:
            if pattern in url:
                return 1
        return 0

    def get_feature_names(self):
        return list(self.extract_features("example.com").keys())