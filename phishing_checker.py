"""
EWB Phishing URL Awareness Checker
An educational, text-based heuristic tool to detect common structural warning signs in URLs.
Defensive learning only. Never opens, scrapes, or visits target endpoints.
"""

import re
from urllib.parse import urlparse

# Messages that represent operational status rather than security warning signs
INFO_MESSAGES = (
    "No URL entered.",
    "Could not identify a hostname.",
    "This text is not a valid URL format.",
    "No listed warning signs found. This does NOT prove safety."
)


def has_warnings(findings: list[str]) -> bool:
    """Check if the findings contain actual warning flags rather than status messages."""
    if not findings:
        return False
    return not findings[0].startswith(INFO_MESSAGES)


def inspect_url(raw_url: str) -> list[str]:
    """Inspects URL string heuristics for suspicious structural characteristics."""
    url = raw_url.strip()
    findings = []

    if not url:
        return ["No URL entered."]

    # Prepend http:// if scheme missing to ensure urlparse extracts host correctly
    candidate = url if "://" in url else "http://" + url

    # Safe parsing: handle malformed URLs (e.g., http://[bad) gracefully
    try:
        parsed = urlparse(candidate)
    except ValueError:
        return ["This text is not a valid URL format."]

    host = (parsed.hostname or "").lower()
    if not host:
        return ["Could not identify a hostname."]

    # Heuristic 1: Credential / redirect confusion via '@'
    if "@" in candidate:
        findings.append("Contains an @ symbol; inspect carefully.")

    # Heuristic 2: Length threshold (> 100 characters)
    if len(url) > 100:
        findings.append("Unusually long URL (over 100 characters).")

    # Heuristic 3: Bare IPv4 address as hostname
    if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host):
        findings.append("Uses an IP address instead of a familiar domain.")

    # Heuristic 4: Excessive hostname segments (5 or more labels)
    labels = [part for part in host.split(".") if part]
    if len(labels) >= 5:
        findings.append("Contains many hostname segments/subdomains.")

    # Heuristic 5: Punycode homograph indicators
    if "xn--" in host:
        findings.append("Contains a punycode-style hostname.")

    # Heuristic 6: Insecure plaintext HTTP transport
    if parsed.scheme.lower() == "http":
        findings.append("Uses HTTP. HTTPS alone does not prove trust.")

    # Default message when no heuristics are tripped
    if not findings:
        findings.append("No listed warning signs found. This does NOT prove safety.")

    return findings


def main():
    """CLI execution loop."""
    print("=" * 55)
    print("      EWB Phishing URL Awareness Checker")
    print(" Text checks only — this program does not open URLs.")
    print("=" * 55)

    while True:
        raw_url = input("\nEnter a sample URL to inspect (or 'q' to quit): ").strip()
        if raw_url.lower() in ("q", "quit", "exit"):
            print("\nExiting. Stay safe online!")
            break

        findings = inspect_url(raw_url)

        print("\nResult:")
        for item in findings:
            print(f"- {item}")

        # Summary count for active warning signs
        if has_warnings(findings):
            print(f"\nREVIEW CAREFULLY: {len(findings)} warning sign(s) found.")

        print("\nNever enter passwords from unexpected links.")


if __name__ == "__main__":
    main()