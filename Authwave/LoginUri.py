from Authwave.Token import Token
from Authwave.BaseProviderUri import BaseProviderUri

class LoginUri(BaseProviderUri):

    def __init__(self, token, currentPath, baseRemoteUri = BaseProviderUri.DEFAULT_BASE_PROVIDER_URI):
        ## returns remote uri with token in query
        baseRemoteUri = self.normaliseBaseUri(baseRemoteUri)
        super().__init__(baseRemoteUri)
        self._str = str(baseRemoteUri)
        self.uri = baseRemoteUri.buildQuery(
            token,
            currentPath,
            self._str,
            "action=login"
        )