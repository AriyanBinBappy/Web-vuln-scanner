import concurrent.futures as cf
import re, time, threading, urllib.robotparser
from urllib.parse import urljoin, urlparse, urldefrag, urlencode, parse_qsl
import requests
from bs4 import BeautifulSoup

class AdvancedCrawler:
    """
    Fast, thread-pooled crawler that stays on the starting host, skips static
    assets, (optionally) respects robots.txt, and returns a de-duplicated list
    of page/form URLs.
    """

    _STATIC_RE = re.compile(r".*\\.(?:jpg|jpeg|png|gif|svg|css|js|woff2?|ttf|eot|ico)(\\?.*)?$", re.I)

    def __init__(
        self,
        base_url: str,
        max_depth: int = 3,
        delay: float = 0.4,
        max_workers: int = 16,
        user_agent: str = "OctoScanner/1.0",
        obey_robots: bool = False,
    ):
        self.base_url = base_url.rstrip("/")
        self.max_depth = max_depth
        self.delay = delay
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": user_agent})
        self.host = urlparse(self.base_url).netloc
        self.visited: set[str] = set()
        self.links: set[str] = set()
        self.lock = threading.Lock()
        self.obey_robots = obey_robots
        self.disallowed = self._load_robots() if obey_robots else set()
        self.max_workers = max_workers

    # ── public API ────────────────────────────────────────────────────
    def crawl(self) -> list[str]:
        """Breadth-first crawl; returns list of discovered URLs."""
        print(f"[*] Crawling {self.base_url} (depth ≤ {self.max_depth}) …")
        with cf.ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            queue: list[tuple[str, int]] = [(self.base_url, 0)]
            while queue:
                url, depth = queue.pop()
                if depth > self.max_depth:
                    continue
                norm = self._normalize(url)
                with self.lock:
                    if norm in self.visited:
                        continue
                    self.visited.add(norm)
                    self.links.add(norm)
                # fetch & parse in background
                fut = pool.submit(self._fetch_links, norm, depth + 1)
                for new_url, new_depth in fut.result():
                    queue.append((new_url, new_depth))
        return sorted(self.links)

    # ── helpers ───────────────────────────────────────────────────────
    def _load_robots(self) -> set[str]:
        rp = urllib.robotparser.RobotFileParser()
        try:
            rp.set_url(urljoin(self.base_url, "/robots.txt"))
            rp.read()
            return {p for p in rp.default_entry.disallow_all}
        except Exception:
            return set()

    def _normalize(self, url: str) -> str:
        url = urldefrag(url)[0]                    # drop fragment
        parsed = urlparse(url)
        # sort query parameters to avoid duplicate permutations
        query = urlencode(sorted(parse_qsl(parsed.query)))
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}" + (f"?{query}" if query else "")

    def _allowed(self, url: str) -> bool:
        if self._STATIC_RE.match(url):
            return False
        parsed = urlparse(url)
        if parsed.netloc != self.host:
            return False
        if any(parsed.path.startswith(p) for p in self.disallowed):
            return False
        return True

    def _fetch_links(self, url: str, depth: int) -> list[tuple[str, int]]:
        time.sleep(self.delay)
        try:
            r = self.session.get(url, timeout=8, verify=False, allow_redirects=True)
            if "text/html" not in r.headers.get("Content-Type", ""):
                return []
            soup = BeautifulSoup(r.text, "html.parser")
            anchors = [urljoin(url, a["href"]) for a in soup.find_all("a", href=True)]
            forms   = [urljoin(url, f.get("action")) for f in soup.find_all("form", action=True)]
            next_links = anchors + forms
            return [
                (link, depth)
                for link in next_links
                if self._allowed(link)
            ]
        except requests.RequestException:
            return []
