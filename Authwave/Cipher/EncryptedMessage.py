import pysodium as s
import base64

from Authwave.Cipher.AbstractMessage import AbstractMessage
from Authwave.Cipher.PlainTextMessage import PlainTextMessage
from Authwave.Cipher.Key import Key
from Authwave.Cipher.DecryptionFailureException import DecryptionFailureException

class EncryptedMessage(AbstractMessage):
    
    def decrypt(self, sharedKey):
        try: 
            decrypted = s.crypto_secretbox_open(base64.b64decode(self.data), self._iv.getBytes(), sharedKey.getBytes())
        except:
            raise DecryptionFailureException("Error decrypting cipher message")
        
        return PlainTextMessage(decrypted.decode(), self._iv)