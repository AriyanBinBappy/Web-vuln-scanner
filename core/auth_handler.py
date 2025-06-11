import json

def get_auth_headers(config):
    cfg = config.get("auth", {})
    if not cfg.get("enabled"):
        return {}
    typ = cfg["type"].lower()
    val = cfg["value"]
    if typ == "cookie":
        return {"Cookie": val}
    if typ == "header":
        return json.loads(val)
    return {}
