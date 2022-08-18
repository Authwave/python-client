from Token import Token
from BaseResponseData import BaseResponseData
from NotLoggedInException import NotLoggedInException

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