from dataclasses import InitVar
import pysodium as s
import inspect
import ctypes
import base64
import urllib

from Authwave.Cipher.InitVector import InitVector
from Authwave.Cipher.Key import Key

class CipherText():
    _bytes = None

    def __init__(self, data, iv, key):
        # maybe check _iv and _key are correct object types
        if not isinstance(iv, InitVector):
            raise TypeError("iv must be of type InitVector.")
        if not isinstance(key, Key):
            raise TypeError("key must be of type Key.")
        self._iv = iv
        self._bytes = s.crypto_secretbox(bytes(data, 'utf-8'), iv.getBytes(), key.getBytes())

    def __str__(self):

        ## need to pad bytes for b64decode
        bytes = CipherText.ensurePadding(self.getBytes())
        return base64.b64encode(bytes).decode('utf-8')
    
    def ensurePadding(byteVal):
        if len(byteVal) % 4 != 0:
            byteVal += b"="
            return CipherText.ensurePadding(byteVal)
        
        return byteVal

        

    def getBytes(self):
        return self._bytes

    def getQueryString(self, host):
        if not isinstance(host, str):
            raise TypeError("host must be of type str.")
        params = {
            "cipher": base64.urlsafe_b64encode(self.getBytes() + b"=="),
            "iv": base64.urlsafe_b64encode(self._iv.getBytes() + b"==")
        }

        host += "?"
        host += "cipher=" + urllib.parse.quote(params["cipher"].decode('utf-8'))
        host += "&iv=" + urllib.parse.quote(params["iv"].decode('utf-8'))
        return host
