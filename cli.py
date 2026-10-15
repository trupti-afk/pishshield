"""
PhishShield AI - Interactive Cyber Terminal CLI
Fast, colorful, and user-friendly command-line phishing scanner.
"""

import argparse
import os
import sys
from typing import List

# Configure UTF-8 stdout for Windows
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

# Ensure local imports
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

try:
    import colorama
    from colorama import Fore, Style, Back
    colorama.init(autoreset=True)
    HAS_COLOR = True
except ImportError:
    HAS_COLOR = False
    class Fore:
        RED = GREEN = YELLOW = CYAN = MAGENTA = BLUE = WHITE = LIGHTBLACK_EX = ""
    class Style:
        BRIGHT = DIM = RESET_ALL = ""
    class Back:
        RED = GREEN = YELLOW = ""

from core.classifier import PhishShieldClassifier, ScanResult


BANNER = rf"""{Fore.CYAN}{Style.BRIGHT}
  ____  _     _     _     ____  _     _      _     _       _    ___ 
 |  _ \| |__ (_)___| |__ / ___|| |__ (_) ___| | __| |     / \  |_ _|
 | |_) | '_ \| / __| '_ \\___ \| '_ \| |/ _ \ |/ _` |    / _ \  | | 
 |  __/| | | | \__ \ | | |___) | | | | |  __/ | (_| |   / ___ \ | | 
 |_|   |_| |_|_|___/_| |_|____/|_| |_|_|\___|_|\__,_|  /_/   \_\___|
{Fore.LIGHTBLACK_EX} ─────────────────────────────────────────────────────────────────
{Fore.WHITE} [ AI-Powered Phishing URL Defense & Deep Threat Inspection ]
{Fore.LIGHTBLACK_EX} ─────────────────────────────────────────────────────────────────{Style.RESET_ALL}
"""


def render_progress_meter(score: float, width: int = 24) -> str:
    """Render an ASCII visual threat risk meter."""
    filled = int((score / 100.0) * width)
    unfilled = width - filled

    if score >= 65:
        color = Fore.RED
    elif score >= 40:
        color = Fore.YELLOW
    elif score >= 20:
        color = Fore.CYAN
    else:
        color = Fore.GREEN

    bar = f"{color}[{'█' * filled}{'░' * unfilled}] {score:.1f}%{Style.RESET_ALL}"
    return bar


def display_scan_result(res: ScanResult):
    """Format and print a single scan result with colors and details."""
    print()
    print(f"{Fore.CYAN}Target URL:{Style.RESET_ALL} {Style.BRIGHT}{res.url}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Threat Level:{Style.RESET_ALL} {res.verdict_badge}  {render_progress_meter(res.risk_score)}")
    print(f"{Fore.LIGHTBLACK_EX}Summary:{Style.RESET_ALL} {res.verdict_summary}")

    # Structural Breakdown
    c = res.components
    print()
    print(f"{Fore.LIGHTBLACK_EX}── {Fore.WHITE}URL Architecture{Fore.LIGHTBLACK_EX} ─────────────────────────────{Style.RESET_ALL}")
    scheme_color = Fore.GREEN if c['scheme'] == 'https' else Fore.RED
    print(f"  • Scheme:       {scheme_color}{c['scheme'].upper()}{Style.RESET_ALL}")
    print(f"  • Host:         {Fore.WHITE}{c['hostname']}{Style.RESET_ALL}")
    print(f"  • Domain:       {Fore.CYAN}{c['domain']}{Style.RESET_ALL}")
    print(f"  • Subdomain:    {c['subdomain'] if c['subdomain'] else 'None (Root)'}")
    print(f"  • TLD:          {c['tld']}")
    print(f"  • Entropy:      {res.features.get('entropy', 0.0):.2f} bits")

    # Red Flags
    if res.heuristics.flags:
        print()
        print(f"{Fore.RED}── Security Red Flags ──────────────────────────────{Style.RESET_ALL}")
        for f in res.heuristics.flags:
            sev_color = Fore.RED if f['severity'] in ('CRITICAL', 'HIGH') else Fore.YELLOW
            print(f"  {sev_color}▲ [{f['severity']}] {f['title']}{Style.RESET_ALL}")
            print(f"    {f['detail']}")

    # Anomalies
    if res.anomalies:
        print()
        print(f"{Fore.YELLOW}── Numerical Anomalies ─────────────────────────────{Style.RESET_ALL}")
        for a in res.anomalies:
            print(f"  * {Fore.WHITE}{a['feature']}:{Style.RESET_ALL} {a['value']} ({a['note']})")

    # Defense Recommendation
    print()
    if res.is_phishing or res.risk_score >= 60:
        print(f"{Back.RED}{Fore.WHITE}{Style.BRIGHT} [!] ACTION REQUIRED {Style.RESET_ALL} {Fore.RED}Do NOT authenticate, provide credentials, or proceed to this website!{Style.RESET_ALL}")
    elif res.risk_level == "SUSPICIOUS":
        print(f"{Back.YELLOW}{Fore.BLACK}{Style.BRIGHT} [?] CAUTION {Style.RESET_ALL} {Fore.YELLOW}Verify domain ownership and SSL certificate before continuing.{Style.RESET_ALL}")
    else:
        print(f"{Back.GREEN}{Fore.BLACK}{Style.BRIGHT} [✓] SAFE {Style.RESET_ALL} {Fore.GREEN}No suspicious phishing characteristics detected.{Style.RESET_ALL}")
    print()


def interactive_mode(classifier: PhishShieldClassifier):
    """Run interactive terminal shell."""
    print(BANNER)
    print(f"{Fore.WHITE}Type a URL, {Fore.CYAN}'presets'{Fore.WHITE}, {Fore.CYAN}'help'{Fore.WHITE}, or {Fore.CYAN}'exit'{Fore.WHITE} to quit.{Style.RESET_ALL}\n")

    presets = [
        ("https://www.google.com", "Legitimate Global Search"),
        ("https://www.wikipedia.org", "Legitimate Knowledge Base"),
        ("https://abacus-oo-niku-shiki.firebaseapp.com/", "Phishing Firebase Impersonation"),
        ("http://192.168.1.1/login-bank-verification", "Phishing Raw IP Host"),
        ("https://paypal-security-verification.xyz/login", "Phishing Brand Impersonation"),
    ]

    while True:
        try:
            user_input = input(f"{Fore.CYAN}PhishShield{Fore.LIGHTBLACK_EX} > {Style.RESET_ALL}").strip()
            if not user_input:
                continue

            cmd = user_input.lower()
            if cmd in ("exit", "quit", "q"):
                print(f"\n{Fore.GREEN}Goodbye! Stay safe online. 🛡️{Style.RESET_ALL}")
                break

            elif cmd in ("help", "?"):
                print(f"""
{Fore.CYAN}Available Commands:{Style.RESET_ALL}
  <url>           Scan any URL directly (e.g. 'https://github.com')
  presets         Show and scan quick preset URLs
  audit <file>    Scan all URLs in a text file
  clear           Clear screen
  exit            Exit PhishShield CLI
""")
            elif cmd == "presets":
                print(f"\n{Fore.CYAN}Select a preset to test:{Style.RESET_ALL}")
                for idx, (p_url, p_desc) in enumerate(presets, 1):
                    print(f"  [{idx}] {p_desc} -> {Fore.WHITE}{p_url}{Style.RESET_ALL}")
                choice = input(f"\nEnter preset number (1-{len(presets)}): ").strip()
                if choice.isdigit() and 1 <= int(choice) <= len(presets):
                    chosen_url = presets[int(choice) - 1][0]
                    res = classifier.scan(chosen_url)
                    display_scan_result(res)
                else:
                    print(f"{Fore.RED}Invalid selection.{Style.RESET_ALL}")

            elif cmd.startswith("audit "):
                path = user_input[6:].strip().strip('"').strip("'")
                if not os.path.exists(path):
                    print(f"{Fore.RED}File not found: {path}{Style.RESET_ALL}")
                    continue
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    urls = [line.strip() for line in f if line.strip()]
                print(f"{Fore.CYAN}Scanning {len(urls)} URLs...{Style.RESET_ALL}\n")
                for u in urls:
                    r = classifier.scan(u)
                    print(f"[{r.verdict_badge}] {r.risk_score:5.1f}%  {u}")
                print()

            elif cmd == "clear":
                os.system("cls" if os.name == "nt" else "clear")
                print(BANNER)

            else:
                # Treat as URL
                res = classifier.scan(user_input)
                display_scan_result(res)

        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}Scan aborted by user.{Style.RESET_ALL}")
            break
        except Exception as e:
            print(f"{Fore.RED}Error scanning URL: {e}{Style.RESET_ALL}")


def main():
    parser = argparse.ArgumentParser(description="PhishShield AI - Terminal Threat Scanner")
    parser.add_argument("url", nargs="?", help="URL to scan directly")
    parser.add_argument("--batch", "-b", help="Path to text or CSV file containing URLs")
    args = parser.parse_args()

    try:
        classifier = PhishShieldClassifier()
    except Exception as e:
        print(f"{Fore.RED}Failed to load AI model: {e}{Style.RESET_ALL}")
        sys.exit(1)

    if args.url:
        res = classifier.scan(args.url)
        print(BANNER)
        display_scan_result(res)
    elif args.batch:
        if not os.path.exists(args.batch):
            print(f"{Fore.RED}File not found: {args.batch}{Style.RESET_ALL}")
            sys.exit(1)
        print(BANNER)
        with open(args.batch, "r", encoding="utf-8", errors="ignore") as f:
            urls = [line.strip() for line in f if line.strip()]
        print(f"{Fore.CYAN}Batch Auditing {len(urls)} URLs:{Style.RESET_ALL}\n")
        for u in urls:
            r = classifier.scan(u)
            print(f"  {r.verdict_badge:20}  {render_progress_meter(r.risk_score, 12)}  {u}")
        print()
    else:
        interactive_mode(classifier)


if __name__ == "__main__":
    main()
