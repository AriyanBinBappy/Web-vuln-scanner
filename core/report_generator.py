import os
import json
from datetime import datetime

def generate_report(target, results, config):
    directory = config.get("output", {}).get("directory", "reports")
    os.makedirs(directory, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = target.replace("://", "_").replace("/", "_")
    json_path = os.path.join(directory, f"{safe_target}_{timestamp}.json")

    with open(json_path, "w") as f:
        json.dump(results, f, indent=2)

    print(f"[+] Report saved to {json_path}")
