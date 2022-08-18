from Token import Token
from BaseProviderUri import BaseProviderUri

class LoginUri(BaseProviderUri):

    def __init__(self, token, currentPath, baseRemoteUri = BaseProviderUri.DEFAULT_BASE_PROVIDER_URI):
        baseRemoteUri = self.normaliseBaseUri(baseRemoteUri)
        super().__init__(baseRemoteUri)
        self.query = self.buildQuery(
            token,
            currentPath,
            "action=login"
        )