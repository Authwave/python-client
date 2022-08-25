import json
import base64

from Authwave.Cipher.Key import Key
from Authwave.Cipher.InitVector import InitVector
from Authwave.Cipher.PlainTextMessage import PlainTextMessage
from Authwave.Cipher.EncryptedMessage import EncryptedMessage

from Authwave.UserResponseData import UserResponseData
from Authwave.ResponseCipherDecryptionException import ResponseCipherDecryptionException
from Authwave.InvalidUserDataSerializationException import InvalidUserDataSerializationException

class Token():
    def __init__(
        self,
        key,
        secretSessionIv = None,
        iv = None
    ):
        if isinstance(key, Key):
            self._key = key
        else: # as keystring
            self._key = Key(key)
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
        plainTextmessage = PlainTextMessage(message + "&secretIv=" + base64.b64encode(self.getSecretIv().getBytes()).decode('utf-8'), self.getIv())
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

    def serialize(self):
        sessionDict = {}
        sessionDict["key"] = str(self._key)
        sessionDict["secretSessionIv"] = str(self._secretSessionIv)
        sessionDict["iv"] = str(self._iv)

        return sessionDict

    def deserialize(data):
        try:
            key = data["key"]
            key = Key(key)
        except:
            key = None

        try:
            secretSessionIv = data["secretSessionIv"]
            secretSessionIv = InitVector().withBytes(base64.b64decode(secretSessionIv))
        except:
            secretSessionIv = None

        try:
            iv = data["iv"]
            iv = InitVector().withBytes(base64.b64decode(iv))
        except:
            iv = None

        return Token(key, secretSessionIv, iv)