from Authwave.BaseProviderUri import BaseProviderUri

class AdminUri(BaseProviderUri):
    def __init__(self, baseRemoteUri = BaseProviderUri.DEFAULT_BASE_PROVIDER_URI):
        baseRemoteUri = self.normaliseBaseUri(baseRemoteUri)
        super().__init__(baseRemoteUri)
        self._str = str(baseRemoteUri)
        self._path = "/admin/"