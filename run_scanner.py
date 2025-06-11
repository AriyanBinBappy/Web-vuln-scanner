import sys
import urllib3
import concurrent.futures
from utils.crawler import AdvancedCrawler  # <- Use the upgraded crawler

# ── disable SSL warnings (self-signed certs etc.) ────────────────────
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── import vulnerability modules ─────────────────────────────────────
from modules import (
    sql_injection, xss, xxe, lfi, rfi,
    directory_traversal, cookie_tampering,
    waf_detection, login_bruteforce, command_injection
)

BANNER = r"""   
  ___       _          ____             _       ____      _               
 / _ \  ___| |_ ___   |  _ \  __ _ _ __| | __  / ___|   _| |__   ___ _ __ 
| | | |/ __| __/ _ \  | | | |/ _` | '__| |/ / | |  | | | | '_ \ / _ \ '__|
| |_| | (__| || (_) | | |_| | (_| | |  |   <  | |__| |_| | |_) |  __/ |   
 \___/ \___|\__\___/  |____/ \__,_|_|  |_|\_\  \____\__, |_.__/ \___|_|   
                                                    |___/                 
 ____                            _ 
/ ___|  __ _ _   _  __ _ _ __ __| |
\___ \ / _` | | | |/ _` | '__/ _` |
 ___) | (_| | |_| | (_| | | | (_| |
|____/ \__, |\__,_|\__,_|_|  \__,_|
          |_|                      

    🛠️  Octo Dark Cyber Squad Web Vuln Scanner & Exploit – Beta Version
    👤 Made by: Ariyan Bin Bappy
    ☠️  Group: Octo Dark Cyber Squad
    ⚠️  For authorized testing only 
"""

# ── tiny URL-filter helpers ──────────────────────────────────────────
has_q     = lambda u: '?' in u
is_xml    = lambda u: u.lower().endswith(('.xml', '.wsdl', '.svc'))
looks_log = lambda u: any(k in u.lower() for k in ('login', 'signin'))
always    = lambda _: True

MODULES = {
    "1": ("SQL Injection",          sql_injection.scan,       has_q),
    "2": ("XSS",                    xss.scan,                 has_q),
    "3": ("Command Injection",      command_injection.scan,   has_q),
    "4": ("LFI",                    lfi.scan,                 has_q),
    "5": ("RFI",                    rfi.scan,                 has_q),
    "6": ("Directory Traversal",    directory_traversal.scan, has_q),
    "7": ("Cookie Tampering",       cookie_tampering.scan,    always),
    "8": ("XXE",                    xxe.scan,                 is_xml),
    "9": ("WAF Detection",          waf_detection.scan,       always),
   "10": ("Login Brute Force",      login_bruteforce.scan,    looks_log),
}

def menu():
    print("\n=== Select attack type ===")
    for k in sorted(MODULES, key=lambda x: int(x)):
        print(f" {k}. {MODULES[k][0]}")
    print(" 0. Exit")
    return input("Choice: ").strip()

def main():
    print(BANNER)
    base = input("Enter BASE URL (e.g., https://example.com): ").strip()
    if not base.startswith("http://") and not base.startswith("https://"):
        print("[!] URL must start with http:// or https://")
        sys.exit(1)

    while True:
        choice = menu()
        if choice == "0":
            print("Bye.")
            break
        if choice not in MODULES:
            print("[!] Invalid choice.")
            continue

        name, scan_fn, filt = MODULES[choice]

        # ── crawling ────────────────────────────────────────────────
        print(f"\n[*] Crawling {base} for {name} …")
        crawler = AdvancedCrawler(base_url=base, max_depth=3, delay=0.3)
        urls = crawler.crawl()
        targets = [u for u in urls if filt(u)]
        print(f"[+] {len(urls)} URLs found, {len(targets)} relevant to {name}.")

        if not targets:
            print("[!] Nothing to test.\n")
            continue

        # ── multithreaded scanning ─────────────────────────────────
        print(f"[*] Running {name} module with 10 threads …")
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
            future_to_url = {pool.submit(scan_fn, u): u for u in targets}
            for future in concurrent.futures.as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    res = future.result()
                    if res:
                        print(f"\n--- {url} ---\n{res}")
                except Exception as exc:
                    print(f"[!] {url} raised exception: {exc}")

if __name__ == "__main__":
    main()
