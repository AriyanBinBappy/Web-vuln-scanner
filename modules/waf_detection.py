import requests
SIGS = [
    ("Server", "cloudflare"),
    ("X-Akamai-Transformed", ""),
    ("X-Sucuri-ID", ""),
    ("Set-Cookie", "__cfduid"),
]

def scan(url, proxies=None, session=None, **kw):
    session = session or requests.Session()
    r = session.get(url, proxies=proxies, timeout=8, verify=False)
    hits = []
    for header, keyword in SIGS:
        val = r.headers.get(header, "").lower()
        if keyword.lower() in val:
            hits.append({"header": header, "value": val})
    return {"module": "WAF", "waf_detected": bool(hits), "details": hits}