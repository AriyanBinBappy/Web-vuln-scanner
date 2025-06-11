class AuthHandler:
    def __init__(self, config):
        self.enabled = config.get('enabled', False)
        self.username = config.get('username', '')
        self.password = config.get('password', '')

    def get_auth(self):
        if self.enabled:
            return (self.username, self.password)
        return None
