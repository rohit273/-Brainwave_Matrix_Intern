import re
import requests
from urllib.parse import urlparse

# OpenPhish database URL
OPENPHISH_FEED = "https://openphish.com/feed.txt"

# Function to fetch the latest phishing URLs from OpenPhish
def get_phishing_list():
    try:
        response = requests.get(OPENPHISH_FEED, timeout=10)
        if response.status_code == 200:
            return set(response.text.split("\n"))
        else:
            print("Error fetching phishing database.")
            return set()
    except requests.exceptions.RequestException:
        print("Error connecting to OpenPhish.")
        return set()

# Function to extract domain from URL
def get_domain(url):
    parsed_url = urlparse(url)
    return parsed_url.netloc

# Heuristic-based detection of phishing
def is_suspicious(url):
    suspicious_patterns = [
        r"(?:login|account|verify|secure|update|bank|paypal)[\W]",  # Suspicious keywords
        r"[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/[a-zA-Z0-9]{15,}",  # Long random paths
        r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",  # IP-based URLs
        r"https?://[^\s]*@.*",  # URLs with '@' symbol
    ]
    
    for pattern in suspicious_patterns:
        if re.search(pattern, url):
            return True
    return False

# Main function to check a URL
def check_url(url, phishing_db):
    domain = get_domain(url)
    if url in phishing_db or domain in phishing_db:
        return f"⚠️ WARNING: {url} is a known phishing site!"
    
    if is_suspicious(url):
        return f"⚠️ ALERT: {url} has suspicious characteristics."
    
    return f"✅ SAFE: {url} appears to be safe."

# Example usage
if __name__ == "__main__":
    phishing_db = get_phishing_list()
    
    test_urls = [
        "https://paypal.secure-login.com",
        "http://192.168.1.1/login",
        "https://www.google.com",
        "https://bank-update-login.com/verify",
        "https://www.instagram.com/",
        "facebookztv[.]com",
    ]
    
    for url in test_urls:
        print(check_url(url, phishing_db))
