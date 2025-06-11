import requests

def scan(url, proxies=None, session=None, **kw):
    creds = [("admin", "admin"), ("root", "toor"), ("test", "test123")]
    session = session or requests.Session()
    for u, p in creds:
        try:
            r = session.post(url, data={"username": u, "password": p}, proxies=proxies, timeout=8, verify=False)
            if "incorrect" not in r.text.lower() and r.status_code in (200, 302):
                return {"module": "Brute", "vulnerable": True, "cred": f"{u}:{p}"}
        except Exception:
            pass
    return {"module": "Brute", "vulnerable": False}