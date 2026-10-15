"""
PhishShield AI - Feature Extractor
Extracts 22 numerical features matching the trained model, along with structural breakdown.
"""

from collections import Counter
import ipaddress
import math
import urllib.parse
from typing import Dict, Any, Tuple
import pandas as pd

FEATURE_COLUMNS = [
    "url_len",
    "dom_len",
    "is_ip",
    "tld_len",
    "subdom_cnt",
    "letter_cnt",
    "digit_cnt",
    "special_cnt",
    "eq_cnt",
    "qm_cnt",
    "amp_cnt",
    "dot_cnt",
    "dash_cnt",
    "under_cnt",
    "letter_ratio",
    "digit_ratio",
    "spec_ratio",
    "is_https",
    "slash_cnt",
    "entropy",
    "path_len",
    "query_len",
]

TWO_PART_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk",
    "com.au", "net.au", "org.au", "edu.au",
    "co.in", "firm.in", "net.in", "org.in",
    "gen.in", "ind.in", "ac.in", "edu.in",
    "gov.in", "res.in", "com.br", "co.jp",
    "co.nz", "com.sg", "com.tw", "gov.br"
}

FEATURE_METADATA = {
    "url_len": {
        "name": "URL Length",
        "desc": "Total characters in the URL. Phishing URLs often use lengthy strings to hide malicious domains.",
        "benign_range": "15 - 60",
        "unit": "chars"
    },
    "dom_len": {
        "name": "Domain Length",
        "desc": "Length of the core domain name. Abnormally long domains often mimic legitimate brands.",
        "benign_range": "6 - 25",
        "unit": "chars"
    },
    "is_ip": {
        "name": "IP Address as Host",
        "desc": "Whether the host uses a raw IPv4/IPv6 address instead of a registered domain name.",
        "benign_range": "0 (No)",
        "unit": "boolean"
    },
    "tld_len": {
        "name": "TLD Length",
        "desc": "Length of the Top-Level Domain suffix (e.g. .com, .edu.au, .online).",
        "benign_range": "2 - 6",
        "unit": "chars"
    },
    "subdom_cnt": {
        "name": "Subdomain Count",
        "desc": "Number of nested subdomains. Multiple subdomains are frequently used to impersonate brands.",
        "benign_range": "0 - 1",
        "unit": "count"
    },
    "letter_cnt": {
        "name": "Letter Count",
        "desc": "Total count of alphabetic letters in the URL.",
        "benign_range": "15 - 50",
        "unit": "chars"
    },
    "digit_cnt": {
        "name": "Digit Count",
        "desc": "Count of numeric digits in the URL. Phishing URLs often include random hashes or numeric IDs.",
        "benign_range": "0 - 5",
        "unit": "digits"
    },
    "special_cnt": {
        "name": "Special Characters",
        "desc": "Count of symbols such as slashes, dots, dashes, question marks, and percent signs.",
        "benign_range": "3 - 10",
        "unit": "symbols"
    },
    "eq_cnt": {
        "name": "Equal Sign Count",
        "desc": "Count of '=' symbols, indicating URL query parameters.",
        "benign_range": "0 - 2",
        "unit": "count"
    },
    "qm_cnt": {
        "name": "Question Mark Count",
        "desc": "Count of '?' indicating dynamic query strings.",
        "benign_range": "0 - 1",
        "unit": "count"
    },
    "amp_cnt": {
        "name": "Ampersand Count",
        "desc": "Count of '&' symbols separating query parameters.",
        "benign_range": "0 - 2",
        "unit": "count"
    },
    "dot_cnt": {
        "name": "Dot Count",
        "desc": "Total number of periods in the URL. Excessive dots are a strong indicator of subdomain obfuscation.",
        "benign_range": "1 - 3",
        "unit": "count"
    },
    "dash_cnt": {
        "name": "Hyphen Count",
        "desc": "Hyphens are rarely used in authentic brands but common in phishing (e.g. 'paypal-security-update').",
        "benign_range": "0 - 1",
        "unit": "count"
    },
    "under_cnt": {
        "name": "Underscore Count",
        "desc": "Count of underscores in the URL path and queries.",
        "benign_range": "0",
        "unit": "count"
    },
    "letter_ratio": {
        "name": "Letter Ratio",
        "desc": "Proportion of characters that are alphabetic letters.",
        "benign_range": "0.65 - 0.90",
        "unit": "ratio"
    },
    "digit_ratio": {
        "name": "Digit Ratio",
        "desc": "Proportion of characters that are numbers.",
        "benign_range": "0.00 - 0.15",
        "unit": "ratio"
    },
    "spec_ratio": {
        "name": "Special Character Ratio",
        "desc": "Proportion of characters that are non-alphanumeric symbols.",
        "benign_range": "0.10 - 0.25",
        "unit": "ratio"
    },
    "is_https": {
        "name": "HTTPS Protocol",
        "desc": "Whether the URL employs SSL/TLS encryption.",
        "benign_range": "1 (Yes)",
        "unit": "boolean"
    },
    "slash_cnt": {
        "name": "Forward Slash Count",
        "desc": "Count of '/' characters representing deep path structures.",
        "benign_range": "2 - 4",
        "unit": "count"
    },
    "entropy": {
        "name": "Shannon Entropy",
        "desc": "Measures the randomness/unpredictability of the URL characters. High entropy signals generated URLs.",
        "benign_range": "3.0 - 4.2",
        "unit": "bits"
    },
    "path_len": {
        "name": "Path Length",
        "desc": "Number of characters in the URL path component.",
        "benign_range": "0 - 30",
        "unit": "chars"
    },
    "query_len": {
        "name": "Query Length",
        "desc": "Number of characters in the query parameter string.",
        "benign_range": "0 - 40",
        "unit": "chars"
    },
}


def shannon_entropy(text: str) -> float:
    """Calculate the Shannon entropy of a string (in bits per symbol)."""
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


class URLFeatureExtractor:
    """Extracts features and structural metadata from URLs for phishing analysis."""

    def __init__(self, feature_columns=None):
        self.feature_columns = feature_columns or FEATURE_COLUMNS

    def parse_components(self, raw_url: str) -> Dict[str, Any]:
        """Normalize URL and decompose it into semantic components."""
        url = str(raw_url).strip()
        if not url:
            raise ValueError("URL cannot be empty.")

        # Ensure scheme
        has_original_scheme = url.startswith(("http://", "https://"))
        if not has_original_scheme:
            url_to_parse = "https://" + url
        else:
            url_to_parse = url

        parsed = urllib.parse.urlparse(url_to_parse)
        hostname = (parsed.hostname or "").lower()
        path = parsed.path or ""
        query = parsed.query or ""
        fragment = parsed.fragment or ""
        scheme = parsed.scheme.lower() if has_original_scheme else "https"

        if not hostname:
            # Fallback if parser didn't capture hostname
            parts = url.split("/", 1)
            hostname = parts[0].lower()
            path = "/" + parts[1] if len(parts) > 1 else ""

        # Check for IP address host
        try:
            ipaddress.ip_address(hostname)
            is_ip = 1
        except ValueError:
            is_ip = 0

        # Extract domain, tld, and subdomain matching Dataset.csv precision
        domain = hostname
        subdomain = ""
        tld = ""
        subdom_cnt = 0

        if not is_ip and hostname:
            extracted_via_lib = False
            try:
                import tldextract
                ext = tldextract.TLDExtract(include_psl_private_domains=False)
                res = ext(url_to_parse)
                if res.suffix:
                    tld = res.suffix
                    domain = f"{res.domain}.{res.suffix}" if res.domain else hostname
                    subdomain = res.subdomain or ""
                    subdom_cnt = len(subdomain.split(".")) if subdomain else 0
                    extracted_via_lib = True
            except Exception:
                pass

            if not extracted_via_lib:
                # Fallback rule-based parser
                labels = hostname.split(".")
                last_two = ".".join(labels[-2:]) if len(labels) >= 2 else ""
                if last_two in TWO_PART_SUFFIXES and len(labels) >= 3:
                    tld = last_two
                    domain = ".".join(labels[-3:])
                    subdomain = ".".join(labels[:-3])
                elif len(labels) >= 2:
                    tld = labels[-1]
                    domain = ".".join(labels[-2:])
                    subdomain = ".".join(labels[:-2])
                else:
                    tld = labels[-1] if labels else ""
                    domain = hostname
                    subdomain = ""

                subdom_cnt = len(subdomain.split(".")) if subdomain else 0

        return {
            "normalized_url": url_to_parse,
            "scheme": scheme,
            "hostname": hostname,
            "domain": domain,
            "subdomain": subdomain,
            "tld": tld,
            "path": path,
            "query": query,
            "fragment": fragment,
            "is_ip": is_ip,
            "subdom_cnt": subdom_cnt,
        }

    def extract(self, raw_url: str) -> Tuple[pd.DataFrame, Dict[str, Any]]:
        """
        Extract numerical features as a DataFrame row plus metadata dictionary.
        Returns: (features_df, components_dict)
        """
        comp = self.parse_components(raw_url)
        url = comp["normalized_url"]
        domain = comp["domain"]
        tld = comp["tld"]
        hostname = comp["hostname"]
        path = comp["path"]
        query = comp["query"]

        url_len = len(url)
        letter_cnt = sum(c.isalpha() for c in url)
        digit_cnt = sum(c.isdigit() for c in url)
        special_cnt = sum(not c.isalnum() for c in url)

        feature_dict = {
            "url_len": url_len,
            "dom_len": len(domain),
            "is_ip": comp["is_ip"],
            "tld_len": len(tld),
            "subdom_cnt": comp["subdom_cnt"],
            "letter_cnt": letter_cnt,
            "digit_cnt": digit_cnt,
            "special_cnt": special_cnt,
            "eq_cnt": url.count("="),
            "qm_cnt": url.count("?"),
            "amp_cnt": url.count("&"),
            "dot_cnt": url.count("."),
            "dash_cnt": url.count("-"),
            "under_cnt": url.count("_"),
            "letter_ratio": (letter_cnt / url_len) if url_len > 0 else 0.0,
            "digit_ratio": (digit_cnt / url_len) if url_len > 0 else 0.0,
            "spec_ratio": (special_cnt / url_len) if url_len > 0 else 0.0,
            "is_https": int(comp["scheme"] == "https"),
            "slash_cnt": url.count("/"),
            "entropy": shannon_entropy(url),
            "path_len": len(path),
            "query_len": len(query),
        }

        features_df = pd.DataFrame([feature_dict])[self.feature_columns]
        return features_df, comp


def extract_features(url: str, feature_columns=None) -> pd.DataFrame:
    """Convenience function matching original signature."""
    extractor = URLFeatureExtractor(feature_columns)
    df, _ = extractor.extract(url)
    return df
