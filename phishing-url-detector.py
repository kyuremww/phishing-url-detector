import re
import requests
import tldextract

def is_suspicious_url(url):
    """Detects if a URL is potentially a phishing attempt"""
    phishing_keywords = ['login', 'secure', 'verify', 'update', 'bank', 'account', 'payment', 'signin', 'confirm']
    
    if len(url) > 75:
        print("[⚠️] The URL is very long, which may be suspicious.")
        return True
    
    if any(keyword in url.lower() for keyword in phishing_keywords):
        print("[⚠️] The URL contains a suspicious keyword.")
        return True
    
    if url.count('-') > 3:
        print("[⚠️] The URL contains too many hyphens, a common phishing trait.")
        return True
    
    extracted = tldextract.extract(url)
    domain = extracted.domain + '.' + extracted.suffix
    if extracted.subdomain and len(extracted.subdomain.split('.')) > 2:
        print("[⚠️] The URL uses multiple subdomains, which may be suspicious.")
        return True
    
    return False

def check_virustotal(url, api_key):
    """Check the URL with VirusTotal (optional)"""
    headers = {"x-apikey": api_key}
    response = requests.get(f"https://www.virustotal.com/api/v3/urls/{url}", headers=headers)
    
    if response.status_code == 200:
        data = response.json()
        if 'data' in data and 'attributes' in data['data']:
            stats = data['data']['attributes']['last_analysis_stats']
            print("VirusTotal Results:", stats)
            if stats['malicious'] > 0:
                return True
    return False
