"""
PhishShield AI - Intelligent Phishing URL Detection & Threat Analysis System
=============================================================================
Combines 22 mathematical/structural URL features with gradient boosting algorithms
and real-time heuristic threat intelligence.

Usage:
    python phishshield_ai.py              # Interactive launcher menu
    python phishshield_ai.py --web        # Launch modern Streamlit Web Dashboard
    python phishshield_ai.py --cli        # Launch Cyber Terminal CLI
    python phishshield_ai.py --scan <url> # Scan a specific URL directly
    python phishshield_ai.py --test       # Run self-test verification suite
    python phishshield_ai.py --train      # Retrain AI model on Dataset.csv
"""

import argparse
import os
import subprocess
import sys
from typing import List, Dict, Any

# Ensure standard UTF-8 console output for Windows
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from core.feature_extractor import URLFeatureExtractor, extract_features, shannon_entropy, FEATURE_COLUMNS
from core.classifier import PhishShieldClassifier, ScanResult
from core.threat_heuristics import analyze_heuristics


BANNER = r"""
  ____  _     _     _     ____  _     _      _     _       _    ___ 
 |  _ \| |__ (_)___| |__ / ___|| |__ (_) ___| | __| |     / \  |_ _|
 | |_) | '_ \| / __| '_ \\___ \| '_ \| |/ _ \ |/ _` |    / _ \  | | 
 |  __/| | | | \__ \ | | |___) | | | | |  __/ | (_| |   / ___ \ | | 
 |_|   |_| |_|_|___/_| |_|____/|_| |_|_|\___|_|\__,_|  /_/   \_\___|
 =================================================================
   Cybersecurity AI Engine — Real-Time Phishing Threat Detection
 =================================================================
"""


def scan_single_url(url: str, classifier: PhishShieldClassifier = None) -> ScanResult:
    """Scan and print the evaluation for a single URL."""
    if classifier is None:
        classifier = PhishShieldClassifier()
    result = classifier.scan(url)
    return result


def print_scan_report(result: ScanResult):
    """Print a clean, user-friendly text summary of a scan result."""
    print("\n" + "=" * 65)
    print(f"  TARGET: {result.url}")
    print("=" * 65)
    print(f"  Verdict:          {result.verdict_badge}")
    print(f"  Risk Level:       {result.risk_level}")
    print(f"  Risk Score:       {result.risk_score}%")
    print(f"  ML Probability:   {result.probability * 100:.2f}%")
    print(f"  Assessment:       {result.verdict_summary}")

    print("\n  [URL Breakdown]")
    c = result.components
    print(f"    • Scheme:       {c['scheme'].upper()} ({'Encrypted SSL' if c['scheme']=='https' else 'Unencrypted'})")
    print(f"    • Host:         {c['hostname']}")
    print(f"    • Domain:       {c['domain']}")
    print(f"    • Subdomain:    {c['subdomain'] or 'None (Root)'}")
    print(f"    • TLD:          {c['tld']}")
    print(f"    • Entropy:      {result.features.get('entropy', 0.0):.2f} bits")

    if result.heuristics.flags:
        print("\n  [Security Red Flags Triggered]")
        for f in result.heuristics.flags:
            print(f"    ▲ [{f['severity']}] {f['title']}: {f['detail']}")

    if result.anomalies:
        print("\n  [Statistical Feature Anomalies]")
        for a in result.anomalies:
            print(f"    * {a['feature']}: {a['value']} - {a['note']}")

    print("\n  [Action Guideline]")
    if result.is_phishing or result.risk_score >= 60:
        print("    🛑 DANGER: Do not open this link or submit any sensitive information!")
    elif result.risk_level == "SUSPICIOUS":
        print("    ⚠️ CAUTION: Inspect the domain carefully before authenticating.")
    else:
        print("    ✅ SAFE: No signs of phishing detected.")
    print("=" * 65 + "\n")


def run_self_test(classifier: PhishShieldClassifier = None):
    """Run an automated self-test suite across benign and malicious URLs."""
    print("\n[+] Running PhishShield AI Self-Test Suite...\n")
    if classifier is None:
        classifier = PhishShieldClassifier()

    test_cases = [
        ("https://www.google.com", "Safe (Search Engine)", False),
        ("https://www.wikipedia.org", "Safe (Encyclopedia)", False),
        ("https://github.com", "Safe (Developer Platform)", False),
        ("https://abacus-oo-niku-shiki.firebaseapp.com/", "Phishing (Firebase Spoof)", True),
        ("http://192.168.1.1/login-bank-verification", "Phishing (IP Host Attack)", True),
        ("https://paypal-security-verification.xyz/login", "Phishing (Brand Impersonation)", True),
    ]

    correct_cnt = 0
    for url, desc, expected_phish in test_cases:
        res = classifier.scan(url)
        is_correct = (res.is_phishing == expected_phish) or (expected_phish and res.risk_level in ("SUSPICIOUS", "CRITICAL PHISHING"))
        if is_correct:
            correct_cnt += 1
            status_icon = "✅ PASS"
        else:
            status_icon = "⚠️ CHECK"

        print(f"  {status_icon} | {desc:<32} | {res.verdict_badge:<22} | Score: {res.risk_score:5.1f}%")

    print(f"\n[✓] Diagnostic Completed: {correct_cnt}/{len(test_cases)} test cases passed validation.\n")


def launch_web():
    """Launch the Streamlit web dashboard."""
    app_path = os.path.join(CURRENT_DIR, "app.py")
    print("\n[+] Launching PhishShield AI Web Dashboard in your browser...")
    print("    Press Ctrl+C in this terminal window to stop the server.\n")
    try:
        subprocess.run([sys.executable, "-m", "streamlit", "run", app_path])
    except KeyboardInterrupt:
        print("\n[!] Web server stopped.")


def launch_cli():
    """Launch the interactive terminal CLI."""
    cli_path = os.path.join(CURRENT_DIR, "cli.py")
    subprocess.run([sys.executable, cli_path])


def interactive_menu():
    """Display an interactive terminal menu for effortless user interaction."""
    print(BANNER)
    classifier = None

    while True:
        print("Please choose an option:")
        print("  [1] 🌐 Launch Interactive Web Dashboard (Streamlit)")
        print("  [2] 💻 Open Cyber Terminal Scanner (CLI)")
        print("  [3] 🔍 Quick URL Scan")
        print("  [4] ⚡ Run Diagnostic Self-Test")
        print("  [5] 🧠 Retrain Model on Dataset.csv")
        print("  [0] 🚪 Exit")
        print("-" * 65)

        try:
            choice = input("Enter selection [0-5]: ").strip()
            if choice == "1":
                launch_web()
            elif choice == "2":
                launch_cli()
            elif choice == "3":
                if classifier is None:
                    print("\n[+] Loading AI model...")
                    classifier = PhishShieldClassifier()
                target = input("\nEnter URL to inspect: ").strip()
                if target:
                    res = classifier.scan(target)
                    print_scan_report(res)
            elif choice == "4":
                if classifier is None:
                    classifier = PhishShieldClassifier()
                run_self_test(classifier)
            elif choice == "5":
                import train
                train.run_training(data_path="Dataset.csv")
            elif choice in ("0", "exit", "quit", "q"):
                print("\nThank you for using PhishShield AI. Stay safe! 🛡️\n")
                break
            else:
                print("\n[!] Invalid option. Please enter a number between 0 and 5.\n")
        except KeyboardInterrupt:
            print("\nExiting.")
            break
        except Exception as e:
            print(f"\n[!] Error: {e}\n")


def main():
    parser = argparse.ArgumentParser(description="PhishShield AI - Phishing URL Threat Defense")
    parser.add_argument("--web", action="store_true", help="Launch Streamlit web dashboard")
    parser.add_argument("--cli", action="store_true", help="Launch interactive CLI scanner")
    parser.add_argument("--scan", type=str, help="Scan a URL directly and print the threat verdict")
    parser.add_argument("--test", action="store_true", help="Run automated diagnostic self-test")
    parser.add_argument("--train", action="store_true", help="Retrain AI model on Dataset.csv")
    args = parser.parse_args()

    if args.web:
        launch_web()
    elif args.cli:
        launch_cli()
    elif args.scan:
        classifier = PhishShieldClassifier()
        res = classifier.scan(args.scan)
        print_scan_report(res)
    elif args.test:
        classifier = PhishShieldClassifier()
        run_self_test(classifier)
    elif args.train:
        import train
        train.run_training(data_path="Dataset.csv")
    else:
        interactive_menu()


if __name__ == "__main__":
    main()