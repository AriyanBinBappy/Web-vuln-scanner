from core.config_loader import load_config
from core.proxy_handler import setup_proxies
from core.auth_handler import get_auth_headers
from core.crawler import crawl_site
from core.scanner import run_all_modules
from core.report_generator import generate_report

def scan_url(url: str, modules: list | None = None, config_path: str = "scanner_config.yaml", generate: bool = False):
    """Programmatic helper to scan a single URL."""
    config = load_config(config_path)
    if modules:
        config["modules"] = modules
    config["targets"] = [url]

    proxies = setup_proxies(config)
    headers = get_auth_headers(config)

    urls = crawl_site(url, headers, proxies)
    results = run_all_modules(urls, config, headers, proxies)

    if generate:
        from pathlib import Path
        Path(config["output"]["directory"]).mkdir(parents=True, exist_ok=True)
        generate_report(url, results, config)

    return results
