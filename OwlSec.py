import tkinter as tk
from tkinter import scrolledtext, filedialog, ttk
import requests
import socket
import threading
from queue import Queue, Empty
import warnings
import json
import re
import time
from bs4 import BeautifulSoup

warnings.filterwarnings("ignore", message="Unverified HTTPS request")

BG_COLOR = "#000000"
FG_COLOR = "#00FF00"
FONT = ("Consolas", 11)

scanning = False
q = Queue()
results_queue = Queue()
domain_global = ""
session = requests.Session()

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                  "AppleWebKit/537.36 (KHTML, like Gecko) "
                  "Chrome/115.0 Safari/537.36"
}

def get_url(domain, path=""):
    for proto in ["https://", "http://"]:
        try:
            url = f"{proto}{domain}/{path}".rstrip('/')
            resp = session.head(url, timeout=5, allow_redirects=True, verify=False, headers=HEADERS)
            if resp.status_code < 400:
                return url, resp
        except:
            continue
    return None, None

def dir_brute_worker(progress_callback=None):
    while True:
        path = q.get()
        if path is None:
            break
        try:
            url, resp = get_url(domain_global, path)
            if url and resp:
                if resp.status_code == 200:
                    results_queue.put(f"[+] Found path: {url}\n")
                elif resp.status_code == 403:
                    results_queue.put(f"[!] Forbidden (403): {url}\n")
        except Exception as e:
            results_queue.put(f"[!] Error checking {path}: {str(e)}\n")
        if progress_callback:
            progress_callback()
        q.task_done()
        time.sleep(0.05)

def start_dir_bruteforce():
    global domain_global, q, results_queue, scanning, scanned_items_count
    domain = domain_entry.get().strip()
    if not domain:
        output_text.delete(1.0, tk.END)
        output_text.insert(tk.END, "Please enter a domain.\n")
        return

    output_text.delete(1.0, tk.END)
    output_text.insert(tk.END, f"Starting directory bruteforce on {domain}...\n")
    root.update()

    domain_global = domain
    q = Queue()
    results_queue = Queue()
    scanning = True
    scanned_items_count = 0

    common_paths = [
        "admin/", "login.php", "login.html", "dashboard/", "robots.txt", "sitemap.xml",
        "index.php.bak", "backup.zip", "test.php", "panel/", ".git/HEAD", ".env",
        "config.php", "db_backup.sql", "old/", "backup/", "uploads/", "wp-admin/", "wp-login.php",
        "phpinfo.php", "server-status", "cgi-bin/", "web.config", "README.md", "LICENSE",
        "error_log", "info.php", "admin.php", "config/", "data/", "logs/", "test/", "api/"
    ]
    num_paths = len(common_paths)

    progress_bar["maximum"] = num_paths
    progress_bar["value"] = 0

    def progress_update():
        global scanned_items_count
        scanned_items_count += 1
        progress_bar["value"] = scanned_items_count

    num_threads = 30
    for _ in range(num_threads):
        t = threading.Thread(target=dir_brute_worker, args=(progress_update,))
        t.daemon = True
        t.start()

    for path in common_paths:
        q.put(path)

    def finish_scan():
        q.join()
        for _ in range(num_threads):
            q.put(None)
        global scanning
        scanning = False
        output_text.insert(tk.END, "\n[+] Directory bruteforce completed.\n")

    threading.Thread(target=finish_scan).start()
    process_queue()

def start_xss_sqli_scan():
    domain = domain_entry.get().strip()
    if not domain:
        output_text.delete(1.0, tk.END)
        output_text.insert(tk.END, "Please enter a domain.\n")
        return
    
    output_text.delete(1.0, tk.END)
    output_text.insert(tk.END, f"Starting XSS/SQLi scan for {domain}...\n")
    root.update()

    try:
        url, resp_head = get_url(domain)
        if not url:
            output_text.insert(tk.END, f"Could not reach {domain} via HTTP or HTTPS.\n")
            return
        resp = session.get(url, timeout=7, headers=HEADERS, verify=False)
        soup = BeautifulSoup(resp.text, 'html.parser')
        
        forms = soup.find_all('form')
        if not forms:
            output_text.insert(tk.END, "No forms found on the page.\n")
            return
        
        for i, form in enumerate(forms):
            action_raw = form.get('action')
            action = action_raw if action_raw and action_raw.startswith('http') else url.rstrip('/') + '/' + (action_raw or '')
            method = form.get('method', 'get').lower()
            
            output_text.insert(tk.END, f"\n--- Form {i+1} ---\n")
            xss_payload = "<script>alert(1)</script>"
            sqli_payload = "' OR '1'='1"

            inputs = form.find_all(['input', 'textarea'])
            data_xss = {}
            data_sqli = {}
            for input_tag in inputs:
                name = input_tag.get('name')
                if name:
                    data_xss[name] = xss_payload
                    data_sqli[name] = sqli_payload
            
            if method == 'post':
                xss_resp = session.post(action, data=data_xss, timeout=7, headers=HEADERS, verify=False)
            else:
                xss_resp = session.get(action, params=data_xss, timeout=7, headers=HEADERS, verify=False)
            
            if xss_payload in xss_resp.text:
                output_text.insert(tk.END, f"[!!!] Possible XSS vulnerability found in form at {action}\n")
            else:
                output_text.insert(tk.END, f"[i] XSS check passed for form at {action}\n")
                
            if method == 'post':
                sqli_resp = session.post(action, data=data_sqli, timeout=7, headers=HEADERS, verify=False)
            else:
                sqli_resp = session.get(action, params=data_sqli, timeout=7, headers=HEADERS, verify=False)
            
            if re.search(r"sql|syntax|mysql|error|warning", sqli_resp.text, re.I):
                output_text.insert(tk.END, f"[!!!] Possible SQLi vulnerability found in form at {action}\n")
            else:
                output_text.insert(tk.END, f"[i] SQLi check passed for form at {action}\n")

        output_text.insert(tk.END, "\nXSS/SQLi scan completed.\n")

    except Exception as e:
        output_text.insert(tk.END, f"Error during scan: {str(e)}\n")

def start_email_harvesting():
    domain = domain_entry.get().strip()
    if not domain:
        output_text.delete(1.0, tk.END)
        output_text.insert(tk.END, "Please enter a domain.\n")
        return
    
    output_text.delete(1.0, tk.END)
    output_text.insert(tk.END, f"Starting email harvesting on {domain}...\n")
    root.update()

    emails = set()
    try:
        url, _ = get_url(domain)
        if not url:
            output_text.insert(tk.END, f"Could not reach {domain}.\n")
            return
        resp = session.get(url, timeout=10, headers=HEADERS, verify=False)
        
        email_regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        found_emails = re.findall(email_regex, resp.text)
        
        for email in found_emails:
            emails.add(email)
        
        if emails:
            output_text.insert(tk.END, f"Found {len(emails)} emails:\n")
            for email in emails:
                output_text.insert(tk.END, f" - {email}\n")
        else:
            output_text.insert(tk.END, "No emails found on the main page.\n")
    except Exception as e:
        output_text.insert(tk.END, f"Error harvesting emails: {str(e)}\n")

def start_source_code_disclosure_check():
    global domain_global, q, results_queue, scanning, scanned_items_count
    domain = domain_entry.get().strip()
    if not domain:
        output_text.delete(1.0, tk.END)
        output_text.insert(tk.END, "Please enter a domain.\n")
        return

    output_text.delete(1.0, tk.END)
    output_text.insert(tk.END, f"Checking for source code disclosure on {domain}...\n")
    root.update()

    domain_global = domain
    q = Queue()
    results_queue = Queue()
    scanning = True
    scanned_items_count = 0
    
    disclosure_paths = [
        ".git/config", ".env", "web.config.bak", "index.php.old",
        "archive.zip", "website.sql", "config.php.bak", "backup.tar.gz",
        "db.sql", "db.sql.gz", "backup.sql", "config.bak"
    ]
    num_paths = len(disclosure_paths)

    progress_bar["maximum"] = num_paths
    progress_bar["value"] = 0

    def progress_update():
        global scanned_items_count
        scanned_items_count += 1
        progress_bar["value"] = scanned_items_count

    num_threads = 30
    for _ in range(num_threads):
        t = threading.Thread(target=dir_brute_worker, args=(progress_update,))
        t.daemon = True
        t.start()

    for path in disclosure_paths:
        q.put(path)

    def finish_scan():
        q.join()
        for _ in range(num_threads):
            q.put(None)
        global scanning
        scanning = False
        output_text.insert(tk.END, "\n[+] Source code disclosure scan completed.\n")

    threading.Thread(target=finish_scan).start()
    process_queue()

def start_csrf_check():
    domain = domain_entry.get().strip()
    if not domain:
        output_text.delete(1.0, tk.END)
        output_text.insert(tk.END, "Please enter a domain.\n")
        return
    
    output_text.delete(1.0, tk.END)
    output_text.insert(tk.END, f"Checking for CSRF tokens on {domain}...\n")
    root.update()

    try:
        url, _ = get_url(domain)
        if not url:
            output_text.insert(tk.END, f"Could not reach {domain}.\n")
            return
        resp = session.get(url, timeout=7, headers=HEADERS, verify=False)
        soup = BeautifulSoup(resp.text, 'html.parser')
        
        forms = soup.find_all('form')
        if not forms:
            output_text.insert(tk.END, "No forms found on the page.\n")
            return
        
        for i, form in enumerate(forms):
            output_text.insert(tk.END, f"\n--- Form {i+1} ---\n")
            
            csrf_token_found = False
            hidden_inputs = form.find_all('input', type='hidden')
            for input_tag in hidden_inputs:
                name = input_tag.get('name')
                if name and 'csrf' in name.lower():
                    csrf_token_found = True
                    output_text.insert(tk.END, f"[i] CSRF token found: {name}\n")
                    break
            
            if not csrf_token_found:
                output_text.insert(tk.END, "[!!!] Potential CSRF vulnerability (no token found).\n")
        
        output_text.insert(tk.END, "\nCSRF token check completed.\n")
    except Exception as e:
        output_text.insert(tk.END, f"Error checking CSRF tokens: {str(e)}\n")

def start_dorking_info():
    domain = domain_entry.get().strip()
    if not domain:
        output_text.delete(1.0, tk.END)
        output_text.insert(tk.END, "Please enter a domain.\n")
        return
    
    output_text.delete(1.0, tk.END)
    output_text.insert(tk.END, f"Here are some Google Dorks for {domain}:\n\n")
    output_text.insert(tk.END, f"--- Dorking for sensitive information ---\n")
    output_text.insert(tk.END, f"site:{domain} filetype:pdf\n")
    output_text.insert(tk.END, f"site:{domain} filetype:doc\n")
    output_text.insert(tk.END, f"site:{domain} intitle:'index of'\n")
    output_text.insert(tk.END, f"site:{domain} inurl:admin\n")
    output_text.insert(tk.END, f"site:{domain} login\n")
    output_text.insert(tk.END, f"\n--- Dorking for subdomains and related sites ---\n")
    output_text.insert(tk.END, f"site:*.{domain}\n")
    output_text.insert(tk.END, f"\nCopy and paste these dorks into Google to find more information.\n")

def start_ip_geolocation():
    domain = domain_entry.get().strip()
    if not domain:
        output_text.delete(1.0, tk.END)
        output_text.insert(tk.END, "Please enter a domain.\n")
        return

    output_text.delete(1.0, tk.END)
    output_text.insert(tk.END, f"Fetching IP geolocation for {domain}...\n")
    root.update()

    try:
        ip = socket.gethostbyname(domain)
        output_text.insert(tk.END, f"IP Address: {ip}\n")
        
        response = session.get(f"http://ip-api.com/json/{ip}", timeout=5)
        response.raise_for_status()
        data = response.json()
        
        if data['status'] == 'success':
            output_text.insert(tk.END, f"Country: {data.get('country')}\n")
            output_text.insert(tk.END, f"City: {data.get('city')}\n")
            output_text.insert(tk.END, f"Region: {data.get('regionName')}\n")
            output_text.insert(tk.END, f"ISP: {data.get('isp')}\n")
            output_text.insert(tk.END, f"Organization: {data.get('org')}\n")
        else:
            output_text.insert(tk.END, "Could not get geolocation information.\n")

    except socket.gaierror:
        output_text.insert(tk.END, f"Error: Could not resolve domain name {domain}\n")
    except requests.exceptions.RequestException as e:
        output_text.insert(tk.END, f"Error connecting to geolocation API: {str(e)}\n")

def start_waf_detection():
    domain = domain_entry.get().strip()
    if not domain:
        output_text.delete(1.0, tk.END)
        output_text.insert(tk.END, "Please enter a domain.\n")
        return

    output_text.delete(1.0, tk.END)
    output_text.insert(tk.END, f"Detecting WAF for {domain}...\n")
    root.update()

    try:
        url, _ = get_url(domain)
        if not url:
            output_text.insert(tk.END, f"Could not reach {domain}.\n")
            return

        response = session.get(url, headers=HEADERS, timeout=7, verify=False)
        headers = response.headers

        waf_found = False
        waf_signatures = {
            'Cloudflare': 'Cloudflare-Ray',
            'Sucuri': 'X-Sucuri-ID',
            'Incapsula': 'X-CDN-Backend',
            'Akamai': 'AkamaiGHost',
            'ModSecurity': 'Mod_Security',
            'Tencent Cloud': 'X-Content-Security-Policy-Report-Only'
        }

        output_text.insert(tk.END, "HTTP Headers:\n")
        for key, value in headers.items():
            output_text.insert(tk.END, f" - {key}: {value}\n")
            for waf_name, signature in waf_signatures.items():
                if signature.lower() in key.lower():
                    output_text.insert(tk.END, f"\n[!] WAF Detected: {waf_name}\n")
                    waf_found = True
                    break
            if waf_found:
                break
        
        if not waf_found:
            output_text.insert(tk.END, "\n[i] No known WAF signatures found in headers.\n")
        output_text.insert(tk.END, "\nWAF detection completed.\n")
    except Exception as e:
        output_text.insert(tk.END, f"Error: {str(e)}\n")

def start_cors_check():
    domain = domain_entry.get().strip()
    if not domain:
        output_text.delete(1.0, tk.END)
        output_text.insert(tk.END, "Please enter a domain.\n")
        return

    output_text.delete(1.0, tk.END)
    output_text.insert(tk.END, f"Checking CORS headers for {domain}...\n")
    root.update()

    try:
        url, _ = get_url(domain)
        if not url:
            output_text.insert(tk.END, f"Could not reach {domain}.\n")
            return

        response = session.get(url, headers=HEADERS, timeout=7, verify=False)
        cors_headers = {
            "Access-Control-Allow-Origin": response.headers.get("Access-Control-Allow-Origin"),
            "Access-Control-Allow-Credentials": response.headers.get("Access-Control-Allow-Credentials"),
            "Access-Control-Allow-Methods": response.headers.get("Access-Control-Allow-Methods"),
            "Access-Control-Allow-Headers": response.headers.get("Access-Control-Allow-Headers")
        }

        for header, value in cors_headers.items():
            output_text.insert(tk.END, f"{header}: {value}\n")

        output_text.insert(tk.END, "\nCORS header check completed.\n")

    except Exception as e:
        output_text.insert(tk.END, f"Error: {str(e)}\n")

def start_robots_analysis():
    domain = domain_entry.get().strip()
    if not domain:
        output_text.delete(1.0, tk.END)
        output_text.insert(tk.END, "Please enter a domain.\n")
        return
    
    output_text.delete(1.0, tk.END)
    output_text.insert(tk.END, f"Fetching robots.txt for {domain}...\n")
    root.update()
    try:
        url, _ = get_url(domain)
        if not url:
            output_text.insert(tk.END, f"Could not reach {domain}.\n")
            return
        robots_url = url.rstrip('/') + "/robots.txt"
        resp = session.get(robots_url, headers=HEADERS, timeout=7, verify=False)
        if resp.status_code == 200:
            output_text.insert(tk.END, resp.text + "\n")
        else:
            output_text.insert(tk.END, "robots.txt not found or inaccessible.\n")
    except Exception as e:
        output_text.insert(tk.END, f"Error: {str(e)}\n")

def save_report():
    content = output_text.get(1.0, tk.END)
    if not content.strip():
        return
    filename = filedialog.asksaveasfilename(
        defaultextension=".txt",
        filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
    )
    if filename:
        with open(filename, "w", encoding="utf-8") as f:
            f.write(content)

def process_queue():
    while True:
        try:
            msg = results_queue.get_nowait()
        except Empty:
            break
        output_text.insert(tk.END, msg)
    if scanning:
        root.after(100, process_queue)

root = tk.Tk()
root.title("Advanced Recon Tool - khaled.s.haddad")
root.configure(bg=BG_COLOR)

domain_label = tk.Label(root, text="Domain:", bg=BG_COLOR, fg=FG_COLOR, font=FONT)
domain_label.grid(row=0, column=0, sticky="w", padx=10, pady=5)

domain_entry = tk.Entry(root, width=40, bg=BG_COLOR, fg=FG_COLOR, insertbackground=FG_COLOR, font=FONT)
domain_entry.grid(row=0, column=1, padx=10, pady=5, sticky="ew")

start_dir_button = tk.Button(root, text="Start Dir Bruteforce", command=start_dir_bruteforce, bg=BG_COLOR, fg=FG_COLOR, font=FONT)
start_dir_button.grid(row=1, column=0, padx=10, pady=5)

start_xss_sqli_button = tk.Button(root, text="Start XSS/SQLi Scan", command=start_xss_sqli_scan, bg=BG_COLOR, fg=FG_COLOR, font=FONT)
start_xss_sqli_button.grid(row=1, column=1, padx=10, pady=5)

start_email_button = tk.Button(root, text="Harvest Emails", command=start_email_harvesting, bg=BG_COLOR, fg=FG_COLOR, font=FONT)
start_email_button.grid(row=2, column=0, padx=10, pady=5)

start_source_code_button = tk.Button(root, text="Source Code Disclosure", command=start_source_code_disclosure_check, bg=BG_COLOR, fg=FG_COLOR, font=FONT)
start_source_code_button.grid(row=2, column=1, padx=10, pady=5)

start_csrf_button = tk.Button(root, text="Check CSRF Tokens", command=start_csrf_check, bg=BG_COLOR, fg=FG_COLOR, font=FONT)
start_csrf_button.grid(row=3, column=0, padx=10, pady=5)

start_dorking_button = tk.Button(root, text="Show Google Dorks", command=start_dorking_info, bg=BG_COLOR, fg=FG_COLOR, font=FONT)
start_dorking_button.grid(row=3, column=1, padx=10, pady=5)

start_ip_geo_button = tk.Button(root, text="IP Geolocation", command=start_ip_geolocation, bg=BG_COLOR, fg=FG_COLOR, font=FONT)
start_ip_geo_button.grid(row=4, column=0, padx=10, pady=5)

start_waf_button = tk.Button(root, text="Detect WAF", command=start_waf_detection, bg=BG_COLOR, fg=FG_COLOR, font=FONT)
start_waf_button.grid(row=4, column=1, padx=10, pady=5)

start_cors_button = tk.Button(root, text="Check CORS", command=start_cors_check, bg=BG_COLOR, fg=FG_COLOR, font=FONT)
start_cors_button.grid(row=5, column=0, padx=10, pady=5)

start_robots_button = tk.Button(root, text="Analyze robots.txt", command=start_robots_analysis, bg=BG_COLOR, fg=FG_COLOR, font=FONT)
start_robots_button.grid(row=5, column=1, padx=10, pady=5)

save_button = tk.Button(root, text="Save Report", command=save_report, bg=BG_COLOR, fg=FG_COLOR, font=FONT)
save_button.grid(row=6, column=0, columnspan=2, pady=10)

progress_bar = ttk.Progressbar(root, orient=tk.HORIZONTAL, length=400, mode='determinate')
progress_bar.grid(row=7, column=0, columnspan=2, padx=10, pady=10)

output_text = scrolledtext.ScrolledText(root, width=90, height=30, bg=BG_COLOR, fg=FG_COLOR, font=FONT, insertbackground=FG_COLOR)
output_text.grid(row=8, column=0, columnspan=2, padx=10, pady=10)

root.grid_columnconfigure(1, weight=1)
root.mainloop()
