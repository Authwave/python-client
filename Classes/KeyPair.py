import pysodium as s

from Classes.PublicKey import PublicKey
from Classes.PrivateKey import PrivateKey

class KeyPair():
    
    def __init__(self, privateKey = None, publicKey = None):
        if ((privateKey and not publicKey) or (not privateKey and publicKey)):
            # Raise exception
            pass
        
        if not privateKey and not publicKey:
            sodiumKeyPair = s.crypto_box_keypair()
            privateKey = PrivateKey(sodiumKeyPair[0])
            publicKey = PublicKey(sodiumKeyPair[1])

        self._privateKey = privateKey
        self._publicKey = publicKey


    def getPrivateKey(self):
        return self._privateKey

    def getPublicKey(self):
        return self._publicKey
