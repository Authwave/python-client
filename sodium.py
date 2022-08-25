import os
import base64
import pysodium as s

from Authwave.Cipher.EncryptedMessage import EncryptedMessage
from Authwave.Cipher.PlainTextMessage import PlainTextMessage

from Authwave.Cipher.Key import Key

sharedKey = Key()
message = PlainTextMessage("This is the test message @~::>>>?>><<")

print("Message to send: " + str(message))

cipherText = message.encrypt(sharedKey)

print("Shared Key: " + str(base64.b64encode(sharedKey.getBytes())))
print("IV: " + str(base64.b64encode(message.getIv().getBytes())))
print("Cipher: " + str(base64.b64encode(cipherText.getBytes())))

encryptedMessage = EncryptedMessage(base64.b64encode(cipherText.getBytes()), message.getIv())
decryptedMessage = encryptedMessage.decrypt(sharedKey)

print(str(decryptedMessage))
print(cipherText.getQueryString("https://cipher-test.g105b.com"))