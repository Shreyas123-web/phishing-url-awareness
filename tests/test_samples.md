# Test Results

- **Tool:** EWB Phishing URL Awareness Checker
- **Python Version:** 3.10+
- **Evaluation Type:** Static URL Text Heuristics

| # | Input | Expected Result | Actual Result | Pass/Fail |
|---|---|---|---|---|
| 1 | `https://www.example.com/login` | No listed warning signs | No listed warning signs found. This does NOT prove safety. | PASS |
| 2 | `http://192.0.2.10/account` | IP address + HTTP | Uses an IP address instead of a familiar domain.<br>Uses HTTP. HTTPS alone does not prove trust. | PASS |
| 3 | `http://example.com@sample.invalid/login` | @ symbol + HTTP | Contains an @ symbol; inspect carefully.<br>Uses HTTP. HTTPS alone does not prove trust. | PASS |
| 4 | `https://a.b.c.d.e.example.invalid/path` | Many hostname segments | Contains many hostname segments/subdomains. | PASS |
| 5 | `https://xn--example.invalid/` | Punycode-style hostname | Contains a punycode-style hostname. | PASS |

## Notes & Observations
- **Missing Schemes:** Typing a raw hostname (e.g., `www.example.com`) without `http://` or `https://` defaults to `http://` prefixing to enable parsing, triggering the plaintext HTTP advisory.
- **Safety Limitations:** Clean test outputs on synthetic links illustrate why heuristic tools are strictly advisory; zero flags does not establish domain legitimacy or lack of malicious intent.
- **Malformed Input Defense:** Inputs such as `http://[bad` are caught via `try/except ValueError` rather than crashing the runtime.