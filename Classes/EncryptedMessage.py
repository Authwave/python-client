import pysodium as s

from Classes.AbstractMessage import AbstractMessage
from Classes.PlainTextMessage import PlainTextMessage
from Classes.Key import Key

class EncryptedMessage(AbstractMessage):
    
    def decrypt(self, sharedKey):
        decrypted = s.crypto_secretbox_open(self.data, self._iv.getBytes(), sharedKey.getBytes())

        return PlainTextMessage(decrypted.decode(), self._iv)