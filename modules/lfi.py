from .directory_traversal import PAYLOADS, _inj, scan as traversal_scan

def scan(url, proxies=None, session=None, **kw):
    result = traversal_scan(url, proxies, session)
    result["module"] = "LFI"
    return result