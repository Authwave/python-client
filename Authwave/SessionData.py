from Authwave.Token import Token
from Authwave.BaseResponseData import BaseResponseData
from Authwave.UserResponseData import UserResponseData
from Authwave.NotLoggedInException import NotLoggedInException

class SessionData():
    def __init__(
        self,
        token = None,
        data = None
    ):
        if (isinstance(token, Token) or token == None):
            self._token = token
        
        if (isinstance(data, BaseResponseData) or data == None):
            self._data = data
        
    def getToken(self):
        if (self._token == None):
            raise NotLoggedInException
        
        return self._token
    
    def getData(self):
        if (self._data == None):
            raise NotLoggedInException
        
        return self._data

    def serialize(self):
        sessionDict = {}
        sessionDict["token"] = self._token.serialize()
        if self._data != None:
            sessionDict["data"] = self._data.serialize()

        return sessionDict

    def deserialize(data):
        try:
            token = data["token"]
            token = Token.deserialize(token)
        except KeyError:
            token = None
        try:
            data = data["data"]
            data = UserResponseData(data["id"], data["email"], data["kvp"])
        except KeyError:
            data = None

        sessionData = SessionData(token, data)
        return sessionData
        