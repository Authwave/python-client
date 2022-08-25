import os
import sys
sys.path.append( os.path.abspath(os.path.dirname(__file__)+'/..') )







import unittest
from unittest.mock import Mock, MagicMock, patch

from Cipher.DecryptionFailureException import DecryptionFailureException
from InvalidUserDataSerializationException import InvalidUserDataSerializationException
from UserResponseData import UserResponseData
from Token import Token
from Cipher.InitVector import InitVector

import pysodium as s

import base64
import os
import json

class TokenTest(unittest.TestCase):
    
    def test_firstTest(self):
        self.assertEqual(4, 4, "Something has gone terribly wrong")

    @unittest.expectedFailure
    def test_wrongTest(self):
        self.assertEqual(2, 4, "Maths is correct")

    def test_GenerateRequestCipher_sameForSameToken(self):
        token = Token("0" * 32)

        cipher1 = token.generateRequestCipher()
        cipher2 = token.generateRequestCipher()

        self.assertEqual(cipher1._bytes, cipher2._bytes)
        self.assertEqual(cipher1._iv, cipher2._iv) 

    def testGenerateRequestCipher_differentForDifferentTokenSameDetails(self):
        key = "0" * 32
        token1 = Token(key)
        token2 = Token(key)
        cipher1 = token1.generateRequestCipher()
        cipher2 = token2.generateRequestCipher()

        self.assertNotEqual(cipher1._bytes, cipher2._bytes)
        self.assertNotEqual(cipher1._iv, cipher2._iv) 

    @patch('Cipher.InitVector')
    def test_getIv(self, iv):
        sut = Token("", None, iv)
        sut_iv = sut.getIv()
        self.assertEqual(iv, sut_iv)

    def test_DecryptResponseCipherInvalid(self):
        key = "0" * 32
        sut = Token(key)
        with self.assertRaises(DecryptionFailureException):
            sut.decode("not a real cipher")
    
    @patch("Cipher.InitVector", autospec=InitVector)
    @patch("Cipher.InitVector", autospec=InitVector)
    def test_DecryptResponseCipherBadJson(self, sessionIv, iv):
        keyString = os.urandom(s.crypto_secretbox_KEYBYTES)

        sessionIv.getBytes.return_value = b"a" * s.crypto_secretbox_NONCEBYTES
        iv.getBytes.return_value = b"f" * s.crypto_secretbox_NONCEBYTES
        
        nonce = iv.getBytes()
        manualCipherString = s.crypto_secretbox(
            b"{badly-formed: json]",
            nonce,
            keyString
        )

        #decryptedCipherString = s.crypto_secretbox_open(manualCipherString)
    
        base64Cipher = base64.encodebytes(manualCipherString)
        sut = Token(keyString, sessionIv, iv)
        with self.assertRaises(InvalidUserDataSerializationException):
            sut.decode(base64Cipher)

    @patch("Cipher.InitVector", autospec=InitVector)
    @patch("Cipher.InitVector", autospec=InitVector)
    def test_DecryptResponseCipher(self, secretIv, iv):
        clientKeyBytes = b"0" * s.crypto_secretbox_KEYBYTES
        ivBytes = b"1" * s.crypto_secretbox_NONCEBYTES
        id = "abcdef"
        email = "person@example.com"
        msg = bytes(json.dumps({"id": id,"email" : email}), 'utf-8')
        cipher = s.crypto_secretbox(
            msg,
            ivBytes,
            clientKeyBytes
        )

        iv.getBytes.return_value = ivBytes

        sut = Token(clientKeyBytes, secretIv, iv)
        userData = sut.decode(base64.b64encode(cipher))

        self.assertIsInstance(userData, UserResponseData)
        self.assertEqual(id, userData.getId())
        self.assertEqual(email, userData.getEmail())




if __name__ == "__main__":
    unittest.main()