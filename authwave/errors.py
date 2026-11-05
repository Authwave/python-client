"""Client errors and redirect control flow."""


class AuthwaveException(Exception):
    pass


class SessionNotStartedException(AuthwaveException):
    pass


class NotLoggedInException(AuthwaveException):
    pass


class InsecureProtocolException(AuthwaveException):
    pass


class InvalidUserDataSerializationException(AuthwaveException):
    pass


class ResponseCipherDecryptionException(AuthwaveException):
    """Compatibility declaration; decryption raises DecryptionFailureException."""


class DecryptionFailureException(AuthwaveException):
    pass


class EncryptionFailureException(AuthwaveException):
    pass


class RedirectSignal(AuthwaveException):
    def __init__(self, uri: str, code: int = 303):
        self.uri = str(uri)
        self.code = code
        super().__init__(self.uri)


class RedirectHandler:
    def redirect(self, uri: str, code: int = 303) -> None:
        raise RedirectSignal(str(uri), code)


class SessionRegenerationException(AuthwaveException):
    pass
