import pysodium as s

from Classes.AbstractMessage import AbstractMessage
from Classes.PlainTextMessage import PlainTextMessage
from Classes.KeyPair import KeyPair

class EncryptedMessage(AbstractMessage):
    
    def decrypt(self, receiverPrivateKey, senderPublicKey):
        unlockingKeyPair = KeyPair(receiverPrivateKey, senderPublicKey)
        decrypted = s.crypto_box_open_afternm(self._data, self._iv.getBytes(), unlockingKeyPair)

        return PlainTextMessage(decrypted, self._iv)