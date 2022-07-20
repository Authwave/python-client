import os

import pysodium as s


class Key():

    def __init__(self, binaryData = None):
        if binaryData == None:
            # Default
            binaryData = os.urandom(s.crypto_secretbox_KEYBYTES)
        self._binaryData = binaryData

    def __str__(self):
        return self._binaryData.hex() ## not this encoding type but keep trying different onces
        # https://docs.python.org/2.4/lib/standard-encodings.html

    def __len__(self):
        return len(self._binaryData)

    def getBytes(self):
        return self._binaryData
