import base64
import json
import threading
from .cipher import InitVector, CipherText, decrypt
from .errors import InvalidUserDataSerializationException, TokenReuseException
from .user import UserResponseData


class Token:
    def __init__(
        self,
        secret: str,
        session_iv: InitVector | None = None,
        iv: InitVector | None = None,
    ):
        self._secret = secret
        self._request_plaintext = None
        self._request_lock = threading.Lock()
        self._session_iv = session_iv if session_iv is not None else InitVector()
        self._iv = iv if iv is not None else InitVector()

    def get_iv(self) -> InitVector:
        return self._iv

    def get_secret_iv(self) -> InitVector:
        return self._session_iv

    def generate_request_cipher(self, message: str = "") -> CipherText:
        with self._request_lock:
            plaintext = f"{message}&secretIv={self._session_iv}"
            if (
                self._request_plaintext is not None
                and self._request_plaintext != plaintext
            ):
                raise TokenReuseException("Create a new token for a different request.")
            cipher = CipherText(plaintext, self._iv, self._secret)
            self._request_plaintext = plaintext
            return cipher

    def decode(self, cipher: str) -> UserResponseData:
        plain = decrypt(cipher, self._iv, self._secret)
        try:
            data = json.loads(plain)
            if not isinstance(data, dict):
                raise ValueError()
            id = data.get("uuid") if data.get("uuid") is not None else data.get("id")
            if not isinstance(id, str) or not isinstance(data.get("email"), str):
                raise ValueError()
            return UserResponseData(id, data["email"])
        except (ValueError, TypeError) as error:
            raise InvalidUserDataSerializationException() from error

    def to_dict(self) -> dict:
        """Sensitive data: save only in server-side session storage."""
        with self._request_lock:
            return {
                "secret": self._secret,
                "session_iv": str(self._session_iv),
                "iv": str(self._iv),
                "request_plaintext": self._request_plaintext,
            }

    @classmethod
    def from_dict(cls, data: dict) -> "Token":
        token = cls(
            data["secret"],
            InitVector().with_bytes(base64.b64decode(data["session_iv"])),
            InitVector().with_bytes(base64.b64decode(data["iv"])),
        )

        # Legacy records can decrypt responses but cannot safely encrypt another request.
        token._request_plaintext = data.get("request_plaintext", "")
        return token
