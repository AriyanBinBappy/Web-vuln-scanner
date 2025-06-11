import importlib, json
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.metasploit import get_client, run_module as msf_run


def run_all_modules(found_urls, config, headers, proxies):
    modules = config["modules"]
    thread_count = config.get("threads", 10)

    # 1️⃣  Detect WAF first
    waf_info = {"detected": False, "details": None}
    if "waf_detection" in modules:
        waf_mod = importlib.import_module("modules.waf_detection")
        waf_res = waf_mod.scan([{"url": u["url"]} for u in found_urls], headers, proxies)
        if waf_res:
            waf_info = {"detected": True, "details": waf_res}

    metasploit_cli = get_client(config.get("metasploit", {}))

    def task(mod_name):
        if mod_name == "waf_detection":
            return {"module": mod_name, "result": waf_info["details"]}
        mod = importlib.import_module(f"modules.{mod_name}")
        targets = [u for u in found_urls if mod_name in u.get("attack_surface", [])]
        if not targets:
            return {"module": mod_name, "skipped": True}
        res = mod.scan(targets, headers, proxies, waf_info, metasploit_cli)
        return {"module": mod_name, "result": res}

    with ThreadPoolExecutor(max_workers=thread_count) as pool:
        futs = {pool.submit(task, m): m for m in modules}
        return [f.result() for f in as_completed(futs)]