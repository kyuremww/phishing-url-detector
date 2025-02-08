# Phishing URL Detector

A Python script that analyzes URLs to detect potential phishing attempts based on various heuristics.

## Features

- Checks for suspicious keywords in the URL
- Detects excessive use of hyphens
- Evaluates the length of the URL
- Identifies the presence of multiple subdomains
- (Optional) Integrates with VirusTotal for further analysis

## Installation

1. Clone the repository

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

Run the script and input URLs for analysis:

```bash
python detector.py
```

## Example

```python
from detector import is_suspicious_url

url = "http://paypal-update-account.com"
if is_suspicious_url(url):
    print("Suspicious URL detected!")
else:
    print("URL appears safe.")
```

## Optional: VirusTotal Integration

To use VirusTotal for deeper analysis, obtain an API key from [VirusTotal](https://www.virustotal.com/) and add it to the script.

## Disclaimer

This tool is for educational purposes only. Use responsibly and ethically.

## License

MIT License

