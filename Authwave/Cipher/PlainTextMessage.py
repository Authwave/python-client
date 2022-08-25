from Authwave.Cipher.AbstractMessage import AbstractMessage
from Authwave.Cipher.CipherText import CipherText

class PlainTextMessage(AbstractMessage):

    def __init__(self, message, iv = None):
        if not isinstance(message, str):
            raise TypeError("message must be of type str.")
        super().__init__(message, iv)
        

    
    def encrypt(self, sharedKey):
        return CipherText(self.data, self._iv, sharedKey)

    # def __str__(self):
    #     return self.data.decode()
