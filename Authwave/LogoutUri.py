from Authwave.Token import Token
from Authwave.BaseProviderUri import BaseProviderUri

class LogoutUri(BaseProviderUri):
    
    def __init__(self, token, currentPath, baseRemoteUri = BaseProviderUri.DEFAULT_BASE_PROVIDER_URI):
        baseRemoteUri = self.normaliseBaseUri(baseRemoteUri)
        super().__init__(baseRemoteUri)
        self._str = str(baseRemoteUri)
        self.uri = self.buildQuery(
            token,
            currentPath,
            self._str,
            "action=logout"
        )