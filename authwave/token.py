import base64
import json
from .cipher import InitVector, CipherText, decrypt
from .errors import InvalidUserDataSerializationException
from .user import UserResponseData


class Token:
    def __init__(
        self,
        secret: str,
        session_iv: InitVector | None = None,
        iv: InitVector | None = None,
    ):
        self._secret = secret
        self._session_iv = session_iv if session_iv is not None else InitVector()
        self._iv = iv if iv is not None else InitVector()

    def get_iv(self) -> InitVector:
        return self._iv

    def get_secret_iv(self) -> InitVector:
        return self._session_iv

    def generate_request_cipher(self, message: str = "") -> CipherText:
        return CipherText(
            f"{message}&secretIv={self._session_iv}", self._iv, self._secret
        )

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
        return {
            "secret": self._secret,
            "session_iv": str(self._session_iv),
            "iv": str(self._iv),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Token":
        return cls(
            data["secret"],
            InitVector().with_bytes(base64.b64decode(data["session_iv"])),
            InitVector().with_bytes(base64.b64decode(data["iv"])),
        )
