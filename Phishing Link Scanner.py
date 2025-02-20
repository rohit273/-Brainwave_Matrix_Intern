import re
import requests
import urllib.parse

def is_suspicious_url(url):
    """
    Checks for common phishing patterns in URLs.
    """
    phishing_patterns = [
        r"free.*",  # Domains offering free stuff
        r".*account.*verify.*",  # Verification scams
        r".*login.*",  # Fake login pages
        r".*bank.*",  # Banking scams
        r".*paypal.*",  # PayPal phishing
        r".*secure.*",  # Fake secure messages
    ]
    
    for pattern in phishing_patterns:
        if re.search(pattern, url, re.IGNORECASE):
            return True
    return False

def check_google_safe_browsing(api_key, url):
    """
    Checks the URL against Google's Safe Browsing API.
    """
    google_api_url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    payload = {
        "client": {"clientId": "your_client_id", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    headers = {"Content-Type": "application/json"}
    response = requests.post(f"{google_api_url}?key={api_key}", json=payload, headers=headers)
    
    if response.status_code == 200:
        result = response.json()
        if "matches" in result:
            return True  # URL is flagged as unsafe
    return False

def main():
    url = input("Enter URL to check: ").strip()
    parsed_url = urllib.parse.urlparse(url)
    
    if not parsed_url.scheme:
        url = "http://" + url  # Ensure proper formatting
    
    print("\nChecking URL...")
    
    if is_suspicious_url(url):
        print("[WARNING] The URL contains phishing-related patterns!")
    
    api_key = "YOUR_GOOGLE_SAFE_BROWSING_API_KEY"
    if check_google_safe_browsing(api_key, url):
        print("[DANGER] This URL is flagged as unsafe by Google Safe Browsing!")
    else:
        print("[SAFE] The URL is not flagged in Google Safe Browsing.")
    
if __name__ == "__main__":
    main()
