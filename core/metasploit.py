import os, time
from typing import Optional
try:
    from metasploit.msfrpc import MsfRpcClient  # requires pip install pymetasploit3
except ImportError:
    MsfRpcClient = None

def get_client(cfg: dict):
    if not cfg.get("enabled", False):
        return None
    if MsfRpcClient is None:
        raise RuntimeError("pymetasploit3 not installed – `pip install pymetasploit3`.")
    return MsfRpcClient(password=cfg["password"], server=cfg["host"], port=cfg.get("port", 55552))

def run_module(client, mname: str, opts: dict, job=False):
    mod = client.modules.use("exploit", mname)
    for k, v in opts.items():
        mod[k] = v
    if job:
        job_id = mod.execute(payload=opts.get("PAYLOAD"), RunInJob=True)
        return job_id
    return mod.execute(payload=opts.get("PAYLOAD"))
