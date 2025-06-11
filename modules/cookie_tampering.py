import requests, copy, json

def scan(url, proxies=None, session=None, **kw):
    session = session or requests.Session()
    try:
        baseline = session.get(url, proxies=proxies, timeout=8, verify=False)
    except Exception as e:
        return {"module": "Cookie", "vulnerable": False, "error": str(e)}

    findings = []
    for cookie in session.cookies:
        tampered = copy.copy(session.cookies)
        tampered.set(cookie.name, "admin", domain=cookie.domain, path=cookie.path)
        try:
            r = session.get(url, cookies=tampered, proxies=proxies, timeout=8, verify=False)
            if r.text != baseline.text:
                findings.append({"tampered_cookie": cookie.name, "evidence_len_diff": len(baseline.text) - len(r.text)})
        except Exception:
            pass

    return {"module": "Cookie", "vulnerable": bool(findings), "findings": findings}
