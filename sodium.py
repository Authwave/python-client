import os
import base64
import pysodium as s

from Classes.EncryptedMessage import EncryptedMessage
from Classes.PlainTextMessage import PlainTextMessage

from Classes.Key import Key

sharedKey = Key()
message = PlainTextMessage(2)

print("Message to send: " + str(message))

cipherText = message.encrypt(sharedKey)

# could use base64urlsafe_b64encode() to communicate over a URL pattern 
# but since this is talking to CipherTest at the moment, just plain old
# base64 is required.
print("Shared Key: " + str(base64.b64encode(sharedKey.getBytes())))
print("IV: " + str(base64.b64encode(message.getIv().getBytes())))
print("Cipher: " + str(base64.b64encode(cipherText.getBytes())))

encryptedMessage = EncryptedMessage(cipherText.getBytes(), message.getIv())
decryptedMessage = encryptedMessage.decrypt(sharedKey)

print(str(decryptedMessage))
print(cipherText.getURI("https://cipher-test.g105b.com"))