import json
from Cipher.Key import Key
from Cipher.InitVector import InitVector
from Cipher.PlainTextMessage import PlainTextMessage
from Cipher.EncryptedMessage import EncryptedMessage

from UserResponseData import UserResponseData
from ResponseCipherDecryptionException import ResponseCipherDecryptionException
from InvalidUserDataSerializationException import InvalidUserDataSerializationException

class Token():
    def __init__(
        self,
        keyString,
        secretSessionIv = None,
        iv = None
    ):
        self._key = Key(keyString)
        if secretSessionIv == None:
            secretSessionIv = InitVector()
        self._secretSessionIv = secretSessionIv 
        if iv == None:
            iv = InitVector()
        self._iv = iv 
        pass

    def getIv(self):
        return self._iv

    def getSecretIv(self):
        return self._secretSessionIv

    def generateRequestCipher(self, message = ""):
        plainTextmessage = PlainTextMessage(message + "&secretIv=" + str(self.getSecretIv()), self.getIv())
        return plainTextmessage.encrypt(self._key)

    def decode(self, base64cipher): 
        encryptedMessage = EncryptedMessage(base64cipher, self.getIv())
        decrypted = encryptedMessage.decrypt(self._key)

        if (not decrypted):
            raise ResponseCipherDecryptionException()

        try:
            data = json.loads(str(decrypted))
        except:
            raise InvalidUserDataSerializationException()

        if ("fiels" not in data.keys()):
            fields = None
        else:
            fields = data["fields"]

        return UserResponseData(data["id"], data["email"], fields)