import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

REMOTE_FILES = [
    "http://raw.githubusercontent.com/OWASP/owasp-mstg/master/README.md",
    "https://example.com/robots.txt",
]

def _inj(url, param, payload):
    p = urlparse(url)
    qs = parse_qs(p.query)
    qs[param] = payload
    return urlunparse(p._replace(query=urlencode(qs, doseq=True)))


def scan(url, proxies=None, session=None, **kw):
    session = session or requests.Session()
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    if not params:
        return {"module": "RFI", "vulnerable": False}
    vulnerable = False
    findings = []
    for p in params:
        for remote in REMOTE_FILES:
            u = _inj(url, p, remote)
            r = session.get(u, proxies=proxies, timeout=8, verify=False)
            if "# Mobile Security Testing Guide" in r.text or "User-agent" in r.text:
                findings.append({"param": p, "payload": remote, "url": u})
                vulnerable = True
                break
    return {"module": "RFI", "vulnerable": vulnerable, "findings": findings}
