from Classes.AbstractMessage import AbstractMessage
from Classes.KeyPair import KeyPair
from Classes.CipherText import CipherText

class PlainTextMessage(AbstractMessage):
    
    def encrypt(self, senderPrivateKey, receiverPublicKey):
        lockingKeyPair = KeyPair(senderPrivateKey, receiverPublicKey)
        return CipherText(self.data, self.iv, lockingKeyPair)
