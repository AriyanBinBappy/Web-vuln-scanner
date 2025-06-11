import json, yaml, os

def load_config(path: str):
    if not os.path.exists(path):
        raise FileNotFoundError(path)
    if path.endswith((".yaml", ".yml")):
        with open(path) as f:
            return yaml.safe_load(f)
    if path.endswith(".json"):
        with open(path) as f:
            return json.load(f)
    raise ValueError("Unsupported config format")
