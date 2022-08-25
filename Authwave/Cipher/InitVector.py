import os
import pysodium as s
import copy
import base64

class InitVector():

    def __init__(self, bytelength = s.crypto_secretbox_NONCEBYTES):
        if bytelength < 1:
            # TODO: Raise CipherException: IV byte length must be greater than 1
            pass
        self.bytes = os.urandom(bytelength)

    def getBytes(self):
        return self.bytes

    def withBytes(self, bytes):
        clone = copy.deepcopy(self)
        clone.bytes = bytes
        return clone

    def __str__(self):
        return base64.b64encode(self.getBytes()).decode('utf-8')