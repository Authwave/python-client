"""Sodium-compatible XSalsa20-Poly1305 secretbox messages."""

import base64
import secrets
from nacl.secret import SecretBox
from .errors import EncryptionFailureException, DecryptionFailureException


class InitVector:
    def __init__(self, byte_length: int = 24):
        if byte_length < 1:
            raise ValueError("IV byte length must be positive")
        self._bytes = secrets.token_bytes(byte_length)

    def get_bytes(self) -> bytes:
        return self._bytes

    def with_bytes(self, value: bytes) -> "InitVector":
        other = InitVector()
        other._bytes = bytes(value)
        return other

    def __str__(self) -> str:
        return base64.b64encode(self._bytes).decode("ascii")


class CipherText:
    def __init__(self, data: str, iv: InitVector, secret: str):
        try:
            self._bytes = (
                SecretBox(secret.encode())
                .encrypt(data.encode(), iv.get_bytes())
                .ciphertext
            )
        except Exception as error:
            raise EncryptionFailureException(
                "Error encrypting cipher message"
            ) from error

    def get_bytes(self) -> bytes:
        return self._bytes

    def __str__(self) -> str:
        return base64.b64encode(self._bytes).decode("ascii")


def decrypt(data: str, iv: InitVector, secret: str) -> str:
    try:
        return (
            SecretBox(secret.encode())
            .decrypt(base64.b64decode(data), iv.get_bytes())
            .decode()
        )
    except Exception as error:
        raise DecryptionFailureException("Error decrypting cipher message") from error
