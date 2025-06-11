import os
import json
from datetime import datetime

class ReportGenerator:
    def __init__(self, config):
        self.format = config.get('format', 'json')
        self.output_dir = config.get('output_dir', 'reports')
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

    def generate(self, results):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"report_{timestamp}.{self.format}"

        if self.format == 'json':
            path = os.path.join(self.output_dir, filename)
            with open(path, 'w') as f:
                json.dump(results, f, indent=4)
            print(f"[+] JSON report saved to {path}")

        # PDF and other formats can be added here later
