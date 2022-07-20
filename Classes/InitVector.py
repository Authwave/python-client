import os
import pysodium as s
import copy

class InitVector():

    bytes = None

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
        return self.bytes.hex()