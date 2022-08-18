import unittest
from unittest.mock import Mock, MagicMock, patch
from Cipher.DecryptionFailureException import DecryptionFailureException
from InvalidUserDataSerializationException import InvalidUserDataSerializationException
from Token import Token
from Cipher.InitVector import InitVector
import pysodium as s

import base64

keyString = "0" * s.crypto_secretbox_KEYBYTES

sessionIv = InitVector()
iv = InitVector()
# sessionIv.getBytes.return_value = b"a" * s.crypto_secretbox_NONCEBYTES
# iv.getBytes.return_value = b"f" * s.crypto_secretbox_NONCEBYTES

nonce = iv.getBytes()
manualCipherString = s.crypto_secretbox(
    b"{badly-formed: json]",
    nonce,
    keyString
)

#decryptedCipherString = s.crypto_secretbox_open(manualCipherString)

base64Cipher = base64.encodebytes(manualCipherString)
sut = Token(keyString, sessionIv, iv)
sut.decode(base64Cipher)