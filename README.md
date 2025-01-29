# **Ultimate AI-Powered Vulnerability Scanner** 🚀🔍

## **Description** 🌟
Welcome to the **Ultimate AI-Powered Vulnerability Scanner**! This advanced tool harnesses the power of AI to dynamically mutate payloads and bypass even the most advanced Web Application Firewalls (WAFs). It supports tests for **XSS**, **SQL Injection**, **RCE**, **Prototype Pollution**, and much more!

The scanner fetches payloads from **GitHub**, integrates with **Tor** for anonymous scanning, and uses **OpenAI** to generate unique mutations for payloads. Ideal for pen testers, ethical hackers, and anyone seeking to enhance web application security.

---

## **Features** ⚙️
- **AI-Powered Payload Mutation:** Uses OpenAI's GPT to generate custom payloads for bypassing WAFs.
- **Tor Integration:** Keeps your scanning anonymous by routing traffic through the Tor network.
- **GitHub Payload Fetching:** Fetches the latest payloads from GitHub repositories to stay updated with current attack vectors.
- **WAF Detection:** Detects popular WAFs such as **Cloudflare**, **Akamai**, **Imperva**, and others.
- **Security Header Scanning:** Flags missing or insecure headers such as **X-XSS-Protection**, **Content-Security-Policy**, etc.
- **JavaScript Vulnerability Scanning:** Scans JS files for dangerous functions like **eval** and **document.cookie**.

---

## **Installation** 🔧

### 1. Clone the Repository

```bash
git clone https://github.com/REDAOUZIDANE/limbo_scanner.py
cd limbo_scanner.py
pip install -r requirements.txt

