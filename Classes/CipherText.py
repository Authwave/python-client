from dataclasses import InitVar
import pysodium as s
import inspect
import ctypes
import base64
import requests

from Classes.InitVector import InitVector
from Classes.Key import Key

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

    def getBytes(self):
        return self._bytes

    def getURI(self, host):
        if not isinstance(host, str):
            raise TypeError("host must be of type str.")
        params = {
            "cipher": base64.b64encode(self.getBytes()),
            "iv": base64.b64encode(self._iv.getBytes())
        }
        request = requests.get(host, params=params)
        return request.url

