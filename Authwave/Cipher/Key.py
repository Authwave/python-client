import os

import pysodium as s


class Key():

    def __init__(self, binaryData = None):
        if binaryData == None:
            # Default
            binaryData = os.urandom(s.crypto_secretbox_KEYBYTES)
        elif isinstance(binaryData, str):
            binaryData = bytes(binaryData, 'utf-8')
        self._binaryData = binaryData

    def __str__(self):
        return self._binaryData.decode('utf-8')

    def __len__(self):
        return len(self._binaryData)

    def getBytes(self):
        return self._binaryData
