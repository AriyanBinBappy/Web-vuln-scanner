import random

def setup_proxies(config):
    cfg = config.get("proxy", {})
    if not cfg.get("enabled"):
        return None
    with open(cfg["source"], "r") as f:
        proxies = [p.strip() for p in f if p.strip()]
    return proxies

def get_random_proxy(proxies):
    return random.choice(proxies) if proxies else None
