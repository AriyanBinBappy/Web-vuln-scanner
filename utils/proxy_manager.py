class ProxyManager:
    def __init__(self, config):
        self.enabled = config.get('enabled', False)
        self.proxy_type = config.get('type', 'http')
        self.address = config.get('address', '')
        self.port = config.get('port', 0)

    def get_proxy_dict(self):
        if not self.enabled:
            return None
        proxy_url = f"{self.proxy_type}://{self.address}:{self.port}"
        return {
            'http': proxy_url,
            'https': proxy_url
        }
