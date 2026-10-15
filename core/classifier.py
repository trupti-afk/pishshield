"""
PhishShield AI - Classifier & Security Evaluation Engine
Loads the trained model with cross-version compatibility and computes calibrated risk scores.
"""

from dataclasses import dataclass, field
import os
import sys
import warnings
from typing import List, Dict, Any, Optional
import joblib
import pandas as pd

from .feature_extractor import URLFeatureExtractor, FEATURE_COLUMNS, FEATURE_METADATA
from .threat_heuristics import analyze_heuristics, ThreatHeuristicReport

# Compatibility patch for scikit-learn version variations during unpickling
try:
    from sklearn._loss import _loss
    sys.modules["_loss"] = _loss
except Exception:
    pass

# Suppress sklearn unpickling version warnings
warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")


@dataclass
class ScanResult:
    url: str
    is_phishing: bool
    probability: float          # 0.0 to 1.0 (phishing probability from ML model)
    risk_score: float           # 0.0 to 100.0 (calibrated blended score)
    risk_level: str             # "SAFE", "LOW RISK", "SUSPICIOUS", "CRITICAL PHISHING"
    components: Dict[str, Any]
    features: Dict[str, Any]
    features_df: pd.DataFrame
    heuristics: ThreatHeuristicReport
    anomalies: List[Dict[str, str]] = field(default_factory=list)
    verdict_badge: str = ""
    verdict_color: str = ""
    verdict_summary: str = ""


class PhishShieldClassifier:
    """Manages the trained AI model, inference, and multi-factor risk assessment."""

    DEFAULT_MODEL_PATHS = [
        "phishshield_model_v1.pkl",
        os.path.join(os.path.dirname(__file__), "..", "phishshield_model_v1.pkl"),
        os.path.join(os.path.expanduser("~"), "Downloads", "phishshield_model_v1.pkl"),
    ]

    def __init__(self, model_path: Optional[str] = None):
        self.model = None
        self.feature_columns = FEATURE_COLUMNS
        self.model_version = "v1"
        self.extractor = URLFeatureExtractor(self.feature_columns)
        self.model_path = model_path
        self._load_model()

    def _load_model(self):
        """Locate and load the pre-trained joblib model artifact."""
        target_path = None
        if self.model_path and os.path.exists(self.model_path):
            target_path = self.model_path
        else:
            for p in self.DEFAULT_MODEL_PATHS:
                abs_p = os.path.abspath(p)
                if os.path.exists(abs_p):
                    target_path = abs_p
                    break

        if not target_path:
            raise FileNotFoundError(
                "PhishShield model file 'phishshield_model_v1.pkl' could not be found. "
                "Please ensure the model file is in the project directory or run train.py."
            )

        package = joblib.load(target_path)
        if isinstance(package, dict):
            self.model = package.get("model")
            self.feature_columns = package.get("feature_columns", FEATURE_COLUMNS)
            self.model_version = package.get("version", "v1")
        else:
            self.model = package

        self.extractor = URLFeatureExtractor(self.feature_columns)
        self.model_path = target_path

    def _find_feature_anomalies(self, features: Dict[str, Any]) -> List[Dict[str, str]]:
        """Identify features that deviate significantly from benign norms."""
        anomalies = []

        if features.get("url_len", 0) > 85:
            anomalies.append({
                "feature": "URL Length",
                "value": f"{features['url_len']} chars",
                "note": "Abnormally long URL (phishing links often conceal payloads or bypass filters)."
            })

        if features.get("dom_len", 0) > 28:
            anomalies.append({
                "feature": "Domain Length",
                "value": f"{features['dom_len']} chars",
                "note": "Unusually long domain name."
            })

        if features.get("dot_cnt", 0) >= 4:
            anomalies.append({
                "feature": "Period Count",
                "value": f"{features['dot_cnt']} dots",
                "note": "Excessive dots indicating deep subdomain stacking."
            })

        if features.get("dash_cnt", 0) >= 3:
            anomalies.append({
                "feature": "Hyphen Count",
                "value": f"{features['dash_cnt']} hyphens",
                "note": "Multiple hyphens commonly found in spoofed domains."
            })

        if features.get("digit_ratio", 0.0) > 0.25:
            anomalies.append({
                "feature": "Digit Ratio",
                "value": f"{features['digit_ratio'] * 100:.1f}%",
                "note": "High concentration of numeric characters."
            })

        if features.get("entropy", 0.0) > 4.3:
            anomalies.append({
                "feature": "Shannon Entropy",
                "value": f"{features['entropy']:.2f} bits",
                "note": "High randomness indicating generated or encrypted tokens."
            })

        return anomalies

    def scan(self, url: str) -> ScanResult:
        """Perform full multi-layer analysis on a single URL."""
        features_df, components = self.extractor.extract(url)
        features_dict = features_df.iloc[0].to_dict()

        # Heuristic check
        heuristics = analyze_heuristics(url, components, features_dict)

        # ML model prediction
        if hasattr(self.model, "predict_proba"):
            probs = self.model.predict_proba(features_df)[0]
            # Assuming class 1 is phishing
            phishing_prob = float(probs[1]) if len(probs) > 1 else float(probs[0])
        else:
            raw_pred = self.model.predict(features_df)[0]
            phishing_prob = 1.0 if raw_pred == 1 else 0.0

        # Calibrate risk score (0 - 100) combining ML probability + heuristics
        base_ml_score = phishing_prob * 100.0
        has_critical = any(f.get("severity") == "CRITICAL" for f in heuristics.flags)
        has_high = any(f.get("severity") == "HIGH" for f in heuristics.flags)

        heuristic_adjustment = heuristics.risk_score_penalty * 0.75
        if has_critical:
            heuristic_adjustment = max(heuristic_adjustment, 45.0)
        elif has_high:
            heuristic_adjustment = max(heuristic_adjustment, 25.0)

        calibrated_score = min(max((base_ml_score * 0.65) + heuristic_adjustment, base_ml_score), 100.0)

        # Categorize
        if calibrated_score >= 60.0 or (phishing_prob >= 0.65) or (has_critical and calibrated_score >= 50.0):
            risk_level = "CRITICAL PHISHING"
            verdict_badge = "🚨 PHISHING DETECTED"
            verdict_color = "#FF3366"
            verdict_summary = "High probability of phishing attack. Do not enter credentials or download files."
            is_phishing = True
        elif calibrated_score >= 40.0 or (phishing_prob >= 0.40):
            risk_level = "SUSPICIOUS"
            verdict_badge = "⚠️ SUSPICIOUS URL"
            verdict_color = "#FF9900"
            verdict_summary = "Several anomalous indicators detected. Exercise strong caution before visiting."
            is_phishing = False
        elif calibrated_score >= 20.0:
            risk_level = "LOW RISK"
            verdict_badge = "⚡ MINOR ANOMALIES"
            verdict_color = "#33CCFF"
            verdict_summary = "URL is likely legitimate but displays minor atypical characteristics."
            is_phishing = False
        else:
            risk_level = "SAFE"
            verdict_badge = "🛡️ VERIFIED LEGITIMATE"
            verdict_color = "#00FF88"
            verdict_summary = "No phishing indicators detected. The URL structure matches standard benign patterns."
            is_phishing = False

        anomalies = self._find_feature_anomalies(features_dict)

        return ScanResult(
            url=url,
            is_phishing=is_phishing,
            probability=phishing_prob,
            risk_score=round(calibrated_score, 1),
            risk_level=risk_level,
            components=components,
            features=features_dict,
            features_df=features_df,
            heuristics=heuristics,
            anomalies=anomalies,
            verdict_badge=verdict_badge,
            verdict_color=verdict_color,
            verdict_summary=verdict_summary,
        )

    def scan_batch(self, urls: List[str]) -> List[ScanResult]:
        """Scan a list of URLs with error resilience."""
        results = []
        for url in urls:
            cleaned = str(url).strip()
            if not cleaned:
                continue
            try:
                results.append(self.scan(cleaned))
            except Exception as e:
                # Fallback for unparseable entries
                results.append(ScanResult(
                    url=cleaned,
                    is_phishing=True,
                    probability=1.0,
                    risk_score=100.0,
                    risk_level="INVALID / MALFORMED",
                    components={"hostname": "unknown", "domain": "unknown"},
                    features={},
                    features_df=pd.DataFrame(),
                    heuristics=ThreatHeuristicReport(url=cleaned),
                    verdict_badge="❌ INVALID URL",
                    verdict_color="#FF0000",
                    verdict_summary=f"Parsing error: {e}",
                ))
        return results
