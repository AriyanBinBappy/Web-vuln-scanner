import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import time
import threading
import queue
import re

class Crawler:
    def __init__(self, base_url, session, auth_headers=None, proxies=None, max_depth=2, rate_limit=1):
        self.base_url = base_url.rstrip("/")
        self.session = session
        self.auth_headers = auth_headers or {}
        self.proxies = proxies
        self.max_depth = max_depth
        self.rate_limit = rate_limit  # seconds between requests
        self.visited = set()
        self.to_visit = queue.Queue()
        self.to_visit.put((self.base_url, 0))
        self.lock = threading.Lock()
        self.robots_rules = set()
        self.parse_robots_txt()

    def parse_robots_txt(self):
        robots_url = urljoin(self.base_url, "/robots.txt")
        try:
            resp = self.session.get(robots_url, headers=self.auth_headers, proxies=self.proxies, timeout=10)
            if resp.status_code == 200:
                lines = resp.text.splitlines()
                user_agent = None
                for line in lines:
                    line = line.strip()
                    if line.lower().startswith("user-agent:"):
                        user_agent = line.split(":")[1].strip()
                    elif user_agent == "*" and line.lower().startswith("disallow:"):
                        path = line.split(":")[1].strip()
                        if path:
                            self.robots_rules.add(urljoin(self.base_url, path))
        except Exception:
            pass

    def allowed_by_robots(self, url):
        for rule in self.robots_rules:
            if url.startswith(rule):
                return False
        return True

    def crawl(self):
        results = set()
        threads = []
        num_threads = 5
        for _ in range(num_threads):
            t = threading.Thread(target=self.worker, args=(results,))
            t.daemon = True
            t.start()
            threads.append(t)

        self.to_visit.join()

        for t in threads:
            t.join(timeout=0.1)
        return list(results)

    def worker(self, results):
        while True:
            try:
                url, depth = self.to_visit.get(timeout=3)
            except queue.Empty:
                return
            with self.lock:
                if url in self.visited or depth > self.max_depth or not self.allowed_by_robots(url):
                    self.to_visit.task_done()
                    continue
                self.visited.add(url)
            try:
                time.sleep(self.rate_limit)
                resp = self.session.get(url, headers=self.auth_headers, proxies=self.proxies, timeout=10, verify=False)
                if resp.status_code != 200:
                    self.to_visit.task_done()
                    continue
                results.add(url)
                links = self.extract_links(resp.text, url)
                with self.lock:
                    for link in links:
                        if link not in self.visited:
                            self.to_visit.put((link, depth + 1))
            except Exception:
                pass
            self.to_visit.task_done()

    def extract_links(self, html, base):
        soup = BeautifulSoup(html, "html.parser")
        links = set()
        for tag in soup.find_all("a", href=True):
            href = tag.get("href")
            href_parsed = urlparse(href)
            if href_parsed.scheme in ["http", "https", ""]:
                joined = urljoin(base, href)
                if joined.startswith(self.base_url):
                    links.add(joined.split("#")[0])  # strip fragments
        return links
