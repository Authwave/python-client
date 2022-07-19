import pysodium as s
import inspect

from Classes.KeyPair import KeyPair

class CipherText():
    _bytes = None

    def __init__(self, data, _iv, _keyPair):
        if isinstance(_keyPair, KeyPair) :
            lockingKeyPair = s.crypto_box_beforenm(_keyPair.getPrivateKey().__str__, _keyPair.getPublicKey().__str__)