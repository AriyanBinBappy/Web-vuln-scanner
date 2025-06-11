import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import time
import threading

class AdvancedCrawler:
    def __init__(self, base_url, max_depth=4, delay=0.4, user_agent="OctoScanner/1.0"):
        self.base_url = base_url.rstrip('/')
        self.max_depth = max_depth
        self.delay = delay
        self.headers = {'User-Agent': user_agent}
        self.visited = set()
        self.lock = threading.Lock()
        self.all_links = []

    def crawl(self):
        print(f"[*] Starting crawl on {self.base_url} up to depth {self.max_depth}...")
        self._crawl_recursive(self.base_url, 0)
        return list(set(self.all_links))

    def _crawl_recursive(self, url, depth):
        if depth > self.max_depth:
            return
        with self.lock:
            if url in self.visited:
                return
            self.visited.add(url)

        try:
            time.sleep(self.delay)
            response = requests.get(url, headers=self.headers, timeout=10, verify=False)
            if 'text/html' not in response.headers.get('Content-Type', ''):
                return

            soup = BeautifulSoup(response.text, 'html.parser')
            links = [urljoin(url, a.get('href')) for a in soup.find_all('a', href=True)]
            forms = [urljoin(url, form.get('action')) for form in soup.find_all('form', action=True)]
            candidates = links + forms

            for link in candidates:
                parsed = urlparse(link)
                if parsed.netloc == urlparse(self.base_url).netloc:
                    clean_url = parsed.scheme + "://" + parsed.netloc + parsed.path
                    if parsed.query:
                        clean_url += '?' + parsed.query
                    with self.lock:
                        if clean_url not in self.visited:
                            self.all_links.append(clean_url)
                            threading.Thread(target=self._crawl_recursive, args=(clean_url, depth + 1)).start()

        except requests.RequestException:
            pass
