import os
import base64
import pysodium as s

from Classes.EncryptedMessage import EncryptedMessage
from Classes.KeyPair import KeyPair
from Classes.PlainTextMessage import PlainTextMessage

senderKeyPair = KeyPair()
receiverKeyPair = KeyPair()

message = PlainTextMessage("This is the message that will be encrypted")

cipherText = message.encrypt(
    senderKeyPair.getPrivateKey(),
    receiverKeyPair.getPublicKey()
)

print(cipherText)

encryptedMessage = EncryptedMessage(cipherText, message._iv)
decrypted = encryptedMessage.decrypt(receiverKeyPair.getPrivateKey(), senderKeyPair.getPublicKey())


print("Decrypted: " + decrypted)