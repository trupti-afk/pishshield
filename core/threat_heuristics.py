"""
PhishShield AI - Heuristic Threat Intelligence Engine
Performs rule-based security checks, brand impersonation detection, and anomaly screening.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any
import re

TARGETED_BRANDS = [
    "paypal", "netflix", "apple", "microsoft", "google", "amazon",
    "facebook", "instagram", "whatsapp", "chase", "wellsfargo",
    "bankofamerica", "citibank", "binance", "coinbase", "metamask",
    "steam", "dropbox", "adobe", "roblox", "linkedin", "twitter"
]

SUSPICIOUS_TLDS = {
    "xyz", "top", "work", "click", "buzz", "fit", "gq", "cf", "tk", "ml", "ga",
    "rest", "cam", "loan", "men", "bid", "stream", "trade", "country"
}

SECURITY_KEYWORDS = [
    "login", "verify", "verification", "secure", "account", "update", "banking",
    "signin", "confirm", "wallet", "support", "recovery", "checkpoint", "password"
]

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly", "ow.ly", "rebrand.ly",
    "cutt.ly", "shorturl.at"
}


@dataclass
class ThreatHeuristicReport:
    url: str
    risk_score_penalty: float = 0.0
    flags: List[Dict[str, str]] = field(default_factory=list)
    detected_brands: List[str] = field(default_factory=list)
    is_shortener: bool = False
    is_ip: bool = False
    has_homograph: bool = False


def analyze_heuristics(url: str, components: Dict[str, Any], features: Dict[str, Any]) -> ThreatHeuristicReport:
    """Analyze URL against cybersecurity threat heuristics and red flags."""
    report = ThreatHeuristicReport(url=url)
    hostname = components.get("hostname", "").lower()
    domain = components.get("domain", "").lower()
    tld = components.get("tld", "").lower()
    path = components.get("path", "").lower()
    subdomain = components.get("subdomain", "").lower()

    # 1. IP Address as Host
    if components.get("is_ip", 0) == 1:
        report.is_ip = True
        report.flags.append({
            "severity": "CRITICAL",
            "title": "Raw IP Address Host",
            "detail": f"Host '{hostname}' is an IP address instead of a domain name. Legitimate services almost always use domain names."
        })
        report.risk_score_penalty += 35.0

    # 2. Homograph / Punycode Attack
    if "xn--" in hostname:
        report.has_homograph = True
        report.flags.append({
            "severity": "HIGH",
            "title": "Punycode / Homograph Indicator",
            "detail": "Hostname contains internationalized Punycode ('xn--'), often used to spoof Cyrillic/Greek characters that look identical to Latin letters."
        })
        report.risk_score_penalty += 25.0

    # 3. Known URL Shortener
    if any(shortener in domain for shortener in SHORTENER_DOMAINS):
        report.is_shortener = True
        report.flags.append({
            "severity": "MEDIUM",
            "title": "URL Shortener Detected",
            "detail": f"Domain '{domain}' is a redirection shortener. Cybercriminals often use shorteners to mask final phishing destinations."
        })
        report.risk_score_penalty += 15.0

    # 4. Brand Impersonation in Subdomain or Path
    for brand in TARGETED_BRANDS:
        # If brand keyword is in subdomain or path, but NOT the legitimate registered domain
        if brand in hostname or brand in path:
            report.detected_brands.append(brand)
            if brand not in domain:
                report.flags.append({
                    "severity": "CRITICAL",
                    "title": f"Targeted Brand Impersonation: '{brand.title()}'",
                    "detail": f"The brand name '{brand.title()}' appears in the URL ({subdomain or path}), but the registered domain is '{domain}'. This is a classic phishing indicator."
                })
                report.risk_score_penalty += 30.0

    # 5. Suspicious / High-Abuse TLD
    cleaned_tld = tld.split(".")[-1]
    if cleaned_tld in SUSPICIOUS_TLDS:
        report.flags.append({
            "severity": "HIGH",
            "title": f"High-Abuse TLD (.{cleaned_tld})",
            "detail": f"The top-level domain '.{cleaned_tld}' has a statistically high rate of spam and phishing registrations."
        })
        report.risk_score_penalty += 15.0

    # 6. Sensitive Security Keywords in URL
    matched_keywords = [kw for kw in SECURITY_KEYWORDS if kw in (path + " " + hostname)]
    if len(matched_keywords) >= 2:
        report.flags.append({
            "severity": "MEDIUM",
            "title": "Sensitive Credential Keywords",
            "detail": f"Found credential-harvesting triggers: {', '.join(matched_keywords)}."
        })
        report.risk_score_penalty += 10.0

    # 7. Shannon Entropy Anomaly
    entropy = features.get("entropy", 0.0)
    if entropy >= 4.4:
        report.flags.append({
            "severity": "HIGH",
            "title": f"High Entropy (Randomness): {entropy:.2f} bits",
            "detail": "High entropy suggests a randomly generated, algorithmic domain (Domain Generation Algorithm - DGA) or obfuscated hash."
        })
        report.risk_score_penalty += 15.0

    # 8. Nested Subdomain Obfuscation
    subdom_cnt = components.get("subdom_cnt", 0)
    if subdom_cnt >= 2:
        report.flags.append({
            "severity": "MEDIUM",
            "title": f"Multiple Nested Subdomains ({subdom_cnt})",
            "detail": "Multiple subdomains are frequently stacked to push suspicious base domains off-screen on mobile devices."
        })
        report.risk_score_penalty += 10.0

    # 9. Insecure Protocol
    if components.get("scheme", "") == "http":
        report.flags.append({
            "severity": "LOW",
            "title": "Unencrypted HTTP Protocol",
            "detail": "URL uses plain HTTP instead of encrypted HTTPS."
        })
        report.risk_score_penalty += 5.0

    # Normalize penalty
    report.risk_score_penalty = min(report.risk_score_penalty, 50.0)
    return report
