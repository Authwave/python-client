from contextlib import redirect_stderr
import sys

if sys.version_info >= (3,): # Python v 3.x
    from urllib import parse as parse
else:
    import urlparse as parse


if sys.version_info >= (3,3): # > Python 3.3.x
    from collections.abc import Mapping as Mapping
else:
    from collections import Mapping as Mapping

# from SessionWrapperInterface import SessionWrapperInterface
from SessionData import SessionData
from SessionNotDictLikeException import SessionNotDictLikeException
from IncompatableRedirectHandlerException import IncompatableRedirectHandlerException
from User import User
from UserResponseData import UserResponseData
from NotLoggedInException import NotLoggedInException
from BaseProviderUri import BaseProviderUri
from Token import Token
from LoginUri import LoginUri
from LogoutUri import LogoutUri

import json
# from GlobalSessionContainer import GlobalSessionContainer

from Cipher.EncryptedMessage import EncryptedMessage
from Cipher.Key import Key

class Authenticator:

    SESSION_KEY = "AUTHWAVE_SESSION"
    RESPONSE_QUERY_PARAMETER = "AUTHWAVE_RESPONSE_DATA"

    def __init__(
        self,
        clientKey,
        currentUri,
        sessionObject,
        redirectHandler,
        authwaveHost = "login.authwave.com"
    ):
        self._clientKey = clientKey
        self._currentUri = currentUri
        # this may present a problem in the future. It depends on how the framework implements session
        # if it bases off of Mapping, it will work.
        # Could also create our own function that checks for dictionary operations with try/except
        if isinstance(sessionObject, Mapping):
            self._sessionObject = sessionObject
        else:
            raise SessionNotDictLikeException
        self._authwaveHost = authwaveHost        

        self._redirectHandler = redirectHandler

        data = self._sessionObject.get(str(SessionData.__name__))
        if (data):
            self._sessionData = data

            try:
                responseData = self._sessionData.getData()
                if (isinstance(responseData, UserResponseData)):
                    self._user = User(
                        responseData.getId(),
                        responseData.getEmail(),
                        responseData.getAllFields()
                    )
            except NotLoggedInException:
                pass

        if (isinstance(currentUri, str)):
            currentUri = BaseProviderUri(currentUri)
        self._currentUri = currentUri

        self._completeAuth()

    def isLoggedIn(self):
        try:
            self._user
            return True
        except:
            return False

    def login(self, token = None):
        if self.isLoggedIn():
            return
        
        if token == None:
            token = Token(self._clientKey)

        self._sessionData = SessionData(token)
        self._sessionObject[str(SessionData.__name__)] = self._sessionData

        self._redirectHandler.redirect(self.getLoginUri(token))

    def getLoginUri(self, token):
        return LoginUri(
            token,
            self._currentUri,
            self._authwaveHost
        )

    def logout(self, token = None):
        if token == None:
            token = Token(self._clientKey)

        self._sessionData = SessionData(token)
        self._sessionObject[str(SessionData.__name__)] = self._sessionData
        self._redirectHandler.redirect(self.getLogoutUri(token))

    def getLogoutUri(self, token):
        return LogoutUri(
            token,
            self._currentUri,
            self._authwaveHost
        )



    def _completeAuth(self):
        queryData = self._getQueryData()

        if queryData == None:
            return

        try:
            token = self._sessionData.getToken()
        except:
            return

        secretSessionIv = token.getSecretIv()
        encrypted = EncryptedMessage(queryData, secretSessionIv)
        key = Key(self._clientKey)
        decrypted = encrypted.decrypt(Key)
        data = json.dumps(decrypted)

        kvp = []
        if "kvp" in data.keys():
            kvp = data["kvp"]

        userData = UserResponseData(
            data["id"],
            data["email"],
            kvp
        )

        #self._sessionObject
        # investigate
        
        try:
            self._redirectHandler.redirect((BaseProviderUri(self._currentUri)).withoutQueryValue(self.RESPONSE_QUERY_PARAMETER))
        except:
            raise IncompatableRedirectHandlerException

    def _getQueryData(self):
        queryString = parse.parse_qs(self._currentUri._components.query)

        if queryString == False:
            return None
        
        if self.RESPONSE_QUERY_PARAMETER not in queryString.keys():
            return None

        return queryString[self.RESPONSE_QUERY_PARAMETER]


