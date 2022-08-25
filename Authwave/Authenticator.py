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
from Authwave.SessionData import SessionData
from Authwave.SessionNotDictLikeException import SessionNotDictLikeException
from Authwave.IncompatableRedirectHandlerException import IncompatableRedirectHandlerException
from Authwave.User import User
from Authwave.UserResponseData import UserResponseData
from Authwave.NotLoggedInException import NotLoggedInException
from Authwave.BaseProviderUri import BaseProviderUri
from Authwave.Token import Token
from Authwave.LoginUri import LoginUri
from Authwave.LogoutUri import LogoutUri

import json
# from GlobalSessionContainer import GlobalSessionContainer

from Authwave.Cipher.EncryptedMessage import EncryptedMessage
from Authwave.Cipher.Key import Key

class Authenticator:

    SESSION_KEY = "AUTHWAVE_SESSION"
    RESPONSE_QUERY_PARAMETER = "AUTHWAVE_RESPONSE_DATA"

    def __init__(
        self,
        clientKey,
        currentUri,
        sessionObject,
        redirectHandler,
        authwaveHost = "https://login.authwave.com"
    ):
        self._clientKey = clientKey
        self._currentUri = currentUri
        try:
            sessionObject["test"] = "testing"
            sessionObject.pop("test")
        except:
            raise SessionNotDictLikeException
        else:
            self._sessionObject = sessionObject
            
        self._authwaveHost = authwaveHost        

        self._redirectHandler = redirectHandler

        try:
            data = self._sessionObject[self.SESSION_KEY]
        except:
            pass
        else:
            if (data):
                self._sessionData = data

                try:
                    self._sessionData = SessionData.deserialize(self._sessionData)
                    responseData = self._sessionData.getData()
                    if (isinstance(responseData, UserResponseData)):
                        self._user = User(
                            responseData.getId(),
                            responseData.getEmail(),
                            responseData.getAllFields()
                        )
                except NotLoggedInException:
                    pass

        # if (isinstance(currentUri, str)):
        #     currentUri = BaseProviderUri(currentUri)
        # self._currentUri = currentUri
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
        self._sessionObject[self.SESSION_KEY] = self._sessionData.serialize()

        loginUri = self.getLoginUri(token)
        return self._redirectHandler.redirect(loginUri.uri)

    def getLoginUri(self, token):
        return LoginUri(
            token,
            self._currentUri,
            self._authwaveHost
        )

    def logout(self, token = None):
        if token == None:
            token = Token(self._clientKey)

        try:
            del self._user
            del self._sessionObject[self.SESSION_KEY]
        except:
            raise NotLoggedInException
        
        return 
    def getLogoutUri(self, token):
        return LogoutUri(
            token,
            self._currentUri,
            self._authwaveHost
        )

    def getAdminUri(self):
        raise NotImplementedError

    def getProfileUri(self):
        raise NotImplementedError

    def _completeAuth(self):
        queryData = self._getQueryData()

        if queryData == None:
            return

        try:
            token = self._sessionData._token
        except:
            return

        secretSessionIv = token.getSecretIv()
        encrypted = EncryptedMessage(queryData, secretSessionIv)
        key = Key(self._clientKey)
        decrypted = encrypted.decrypt(key)
        data = json.loads(decrypted.data)

        kvp = []
        if "kvp" in data.keys():
            kvp = data["kvp"]

        userData = UserResponseData(
            data["id"],
            data["email"],
            kvp
        )

        sessionData = SessionData(token, userData)
        self._sessionObject[self.SESSION_KEY] = sessionData.serialize()

        #self._sessionObject
        # investigate
        
        try:
            uri = BaseProviderUri.withoutQueryValue(self._currentUri, "AUTHWAVE_RESPONSE_DATA")

            ####### TODO: THIS IS DEBUG. REMOVE IN PRODUCTION
            # Reason: Django's redirect handler doesn't allow "localhost"
            uri = uri.split("/")
            del uri[0]
            uri = "/".join(uri)

            if uri == "?":
                uri = "/"

            self._redirectHandler.redirect(uri)
        except:
            raise IncompatableRedirectHandlerException

    def _getQueryData(self):
        # queryString = parse.parse_qs(self._currentUri._query)
        queryString = parse.parse_qs(parse.urlparse(self._currentUri).query)

        if queryString == False:
            return None
        
        if self.RESPONSE_QUERY_PARAMETER not in queryString.keys():
            return None

        return queryString[self.RESPONSE_QUERY_PARAMETER][0]


