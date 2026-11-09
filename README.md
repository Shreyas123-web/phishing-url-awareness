# EWB Phishing URL Awareness Checker

## Overview
Phishing is a social engineering technique where attackers use deceptive links to trick users into divulging sensitive data such as credentials or financial details. This project is a lightweight Python command-line utility that inspects the raw text of a URL for common structural anomalies and warning signs. It operates strictly via static text analysis and never sends web traffic or accesses remote servers.

## Features
- **@ Symbol Detection:** Flags links utilizing the `@` symbol, which can mislead users regarding the true destination host.
- **URL Length Checking:** Identifies URLs exceeding 100 characters that may obscure payloads.
- **IP Address Hostname Detection:** Detects raw IPv4 host addresses substituted for domain names.
- **Subdomain Depth Analysis:** Flags excessive hostname labels (5 or more segments).
- **Punycode Homograph Identification:** Alerts on `xn--` prefixes commonly used in internationalized domain spoofing.
- **Insecure Protocol Advisory:** Flags unencrypted `http://` connections.
- **Interactive Session Loop:** Allows continuous inspection without restarting.
- **Defensive Error Handling:** Safely intercepts malformed URL structures without script termination.

## Requirements
- Python 3.10 or higher
- Built using Python standard libraries (`re`, `urllib.parse`). No third-party packages needed.

## How to Run

```bash
# Clone the repository
git clone [https://github.com/](https://github.com/)<YOUR-USERNAME>/phishing-url-awareness.git
cd phishing-url-awareness

# Run the program
python phishing_checker.py