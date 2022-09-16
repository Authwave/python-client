from binhex import binhex
import os
import sys
from urllib import parse
import base64
from Authwave.UserResponseData import UserResponseData
import pysodium as s
sys.path.append( os.path.abspath(os.path.dirname(__file__)+'/..') )
import json

import unittest
from unittest.mock import DEFAULT, Mock, MagicMock, patch

from Authwave.Authenticator import Authenticator
from Authwave.SessionNotDictLikeException import SessionNotDictLikeException
from Authwave.NotLoggedInException import NotLoggedInException
from Authwave.SessionData import SessionData
from Authwave.LoginUri import LoginUri
from Authwave.BaseProviderUri import BaseProviderUri
from Authwave.Token import Token
from Authwave.Cipher.InitVector import InitVector
from Authwave.Cipher.CipherText import CipherText
from Authwave.BaseResponseData import BaseResponseData

class AuthenticatorTest(unittest.TestCase):

    dummyKey = b'11111111111111111111111111111111'
    dummyId = "example-id"
    dummyEmail = "person@example.com"

    def dummyUserSession(self):
        token = {
            "key": self.dummyKey
        }
        userData = {
            "id": self.dummyId,
            "email": self.dummyEmail,
            "kvp": {}
        }
        
        sessionDict = {}
        sessionDict["token"] = token
        sessionDict["data"] = userData

        session = {
            Authenticator.SESSION_KEY: sessionDict
        }

        return session
    
    @patch("Authwave.RedirectHandler.RedirectHandler", autospec=True)
    def test_constructWithNoSession(self, redirectHandler):

        with self.assertRaises(TypeError):
            Authenticator("test-key", "/", redirectHandler=redirectHandler)
    
    @patch("Authwave.RedirectHandler.RedirectHandler", autospec=True)
    def test_constructWithNonDictSession(self, redirectHandler):
        session = "sessionid: 12, page: 3"

        with self.assertRaises(SessionNotDictLikeException):
            Authenticator("test-key", "/", session, redirectHandler)

    @patch("Authwave.RedirectHandler.RedirectHandler", autospec=True)
    def test_constructWithExistingSession(self, redirectHandler):

        sessiondata = {
            "id": 34,
            "pageentry": "welcome.html"
        }

        authenticator = Authenticator("test-key", "https://whateversite.com/", sessiondata, redirectHandler)

        self.assertEqual(sessiondata, authenticator._sessionObject)

    @patch("Authwave.RedirectHandler.RedirectHandler", autospec=True)
    def test_trackSessionChanges(self, redirectHandler):

        sessiondata = {
            "id": 34,
            "pageentry": "welcome.html"
        }

        authenticator = Authenticator("test-key", "/", sessiondata, redirectHandler)

        sessiondata["testvalue"] = "somedata"

        self.assertEqual(sessiondata, authenticator._sessionObject)

    @patch("Authwave.RedirectHandler.RedirectHandler", autospec=True)
    def test_isLoggedInFalseByDefault(self, redirectHandler):
        sessiondata = {
            "id": 34,
            "pageentry": "welcome.html"
        }

        sut = Authenticator("test-key", "/", sessiondata, redirectHandler)

        self.assertFalse(sut.isLoggedIn())

    @patch("Authwave.Token.Token", autospec=True)
    @patch("Authwave.UserResponseData.UserResponseData", autospec=True)
    @patch("Authwave.RedirectHandler.RedirectHandler", autospec=True)
    def test_isLoggedInTrueWhenSessionDataSet(self, redirectHandler, userResponseData, token):
       
        token = {
            "key": self.dummyKey
        }
        userData = {
            "id": "example-id",
            "email": "person@example.com",
            "kvp": {}
        }
        
        sessionDict = {}
        sessionDict["token"] = token
        sessionDict["data"] = userData

        session = {
            Authenticator.SESSION_KEY: sessionDict
        }

        sut = Authenticator("test-key", "/", session, redirectHandler)

        self.assertTrue(sut.isLoggedIn())

    @patch("Authwave.RedirectHandler.RedirectHandler", autospec=True)
    def test_logoutClearsSession(self, redirectHandler):
        session = self.dummyUserSession()

        sut = Authenticator("test-key", "/", session, redirectHandler)
        self.assertNotEqual({}, sut._sessionObject)
        sut.logout()

        self.assertEqual({}, sut._sessionObject)

    @patch("Authwave.RedirectHandler.RedirectHandler", autospec=True)
    def test_loginRedirects(self, redirectHandler):
        calledWith = []
        def side_effect(*args, **kwargs):
            calledWith.append(args)
        redirectHandler.redirect = Mock(return_value=None, side_effect=side_effect)

        session = {}
        sut = Authenticator(
            self.dummyKey,
            "https://localhost",
            session,
            redirectHandler
        )

        sut.login()

        if not calledWith: # if there isn't anything in the list
            self.fail()

    @patch("Authwave.RedirectHandler.RedirectHandler", autospec=True)
    def test_loginRedirectsLocalhost(self, redirectHandler):
        calledWith = []
        def side_effect(*args, **kwargs):
            try:
                urlParts = args[0].split(":")
                scheme = urlParts[0]
                host = urlParts[1].replace("/", "") # remove slashes
                port = urlParts[2].split("?", 1)[0] # remove query
                if (scheme == "http" and host == "localhost" and port == "8081"):
                    calledWith.append(args)
            except:
                self.fail()
        redirectHandler.redirect = Mock(return_value=None, side_effect=side_effect)

        session = {}
        sut = Authenticator(
            self.dummyKey,
            "https://localhost",
            session,
            redirectHandler,
            "http://localhost:8081"
        )

        sut.login()

        if not calledWith: # if there isn't anything in the list
            self.fail()

    @patch("Authwave.RedirectHandler.RedirectHandler")
    def test_loginRedirectsWithCorrectQueryString(self, redirectHandler):
        # build expected query string
        currentUri = "https://localhost/test"

        cipherBytes = b"example-cipher"
        ivStringBytes = b"example-iv"

        iv = MagicMock()
        iv.getBytes.return_value = ivStringBytes

        cipher = MagicMock(spec=CipherText)
        cipher.__str__.return_value = cipherBytes
        cipher.getBytes.return_value = cipherBytes
        token = MagicMock(spec=Token)
        token.generateRequestCipher.return_value = cipher
        token.getIv.return_value = iv

        # create side effect that looks for query string values
        calledWith = []
        def side_effect(*args, **kwargs):
            try:
                urlParts = parse.parse_qs(parse.urlsplit(args[0]).query)
                urlcipher = base64.b64decode(urlParts["cipher"][0])
                urliv = base64.b64decode(urlParts["iv"][0])
                urlpath = bytes.fromhex(urlParts["path"][0]).decode('utf-8')
                if (cipherBytes == urlcipher and ivStringBytes == urliv and currentUri == urlpath):
                    calledWith.append(args)
            except:
                self.fail()
        redirectHandler.redirect = Mock(return_value=None, side_effect=side_effect)

        # create authenticator object
        session = {}
        sut = Authenticator(
            self.dummyKey,
            currentUri,
            session,
            redirectHandler
        )

        # login
        sut.login(token)

        # test contents of calledWith
        if not calledWith:
            self.fail()

    @patch("Authwave.RedirectHandler.RedirectHandler")
    def test_loginDoesNothingWhenAlreadyLoggedIn(self, redirectHandler):
        session = self.dummyUserSession()

        # create side effect that looks for query string values
        calledWith = []
        def side_effect(*args, **kwargs):
            try:
                # no matter the arguements, add it to the log
                # the redirect method should not be called at all
                calledWith.append(args)
            except:
                self.fail()
        redirectHandler.redirect = Mock(return_value=None, side_effect=side_effect)

        sut = Authenticator(
            self.dummyKey,
            "http://localhost",
            session,
            redirectHandler
        )
        sut.login()

        if calledWith:
            self.fail()

    @patch("Authwave.RedirectHandler.RedirectHandler")
    def test_getId(self, redirectHandler):
        dummyId = "example-id"
        session = self.dummyUserSession()

        sut = Authenticator(
            "test-key",
            "/",
            session,
            redirectHandler
        )

        self.assertEqual(dummyId, sut.getUser().id)

    @patch("Authwave.RedirectHandler.RedirectHandler")
    def test_getEmailThrowsExceptionWhenNotLoggedIn(self, redirectHandler):
        session = {}

        sut = Authenticator(
            self.dummyKey,
            "http://localhost",
            session,
            redirectHandler
        )

        with self.assertRaises(NotLoggedInException):
            sut.getEmail()

    @patch("Authwave.RedirectHandler.RedirectHandler")
    def test_getEmail(self, redirectHandler):
        session = self.dummyUserSession()

        sut = Authenticator(
            self.dummyKey,
            "http://localhost",
            session,
            redirectHandler
        )
        email = sut.getEmail()

        self.assertEqual(email, self.dummyEmail)

    @patch("Authwave.RedirectHandler.RedirectHandler")
    def test_completeAuthNotAffectedByQueryString(self, redirectHandler):
        
        # create side effect that looks for query string values
        calledWith = []
        def side_effect(*args, **kwargs):
            try:
                # no matter the arguements, add it to the log
                # the redirect method should not be called at all
                calledWith.append(args)
            except:
                self.fail()
        redirectHandler.redirect = Mock(return_value=None, side_effect=side_effect)

        sut = Authenticator(
            self.dummyKey,
            "http://localhost/?filter=something",
            {},
            redirectHandler
        )

        if calledWith:
            self.fail()

    @patch("Authwave.RedirectHandler.RedirectHandler")
    def test_getAdminUri(self, redirectHandler):

        auth = Authenticator(
            self.dummyKey,
            "http://localhost",
            {},
            redirectHandler
        )
        sut = auth.getAdminUri()
        self.assertEqual("/admin/", sut.getPath())

    @patch("Authwave.RedirectHandler.RedirectHandler")
    def test_getUserThrowsExceptionWhenNotLoggedIn(self, redirectHandler):
        currentUri = "/?" + Authenticator.RESPONSE_QUERY_PARAMETER + "=123456789abcdef"

        auth = Authenticator(
            self.dummyKey,
            currentUri,
            {},
            redirectHandler
        )
        with self.assertRaises(NotLoggedInException):
            auth.getUser()

    @patch("Authwave.RedirectHandler.RedirectHandler")
    def test_completeAuth(self, redirectHandler):
        keyBytes = bytes("0" * s.crypto_secretbox_KEYBYTES, 'utf-8')
        ivBytes = bytes("1" * s.crypto_secretbox_NONCEBYTES, 'utf-8')
        plainTextMessage = json.dumps({
            "id": self.dummyId,
            "email": self.dummyEmail
        })
        encryptedMessage = s.crypto_secretbox(bytes(plainTextMessage, 'utf-8'), ivBytes, keyBytes)

        currentUri = "/my-page?filter=something" + Authenticator.RESPONSE_QUERY_PARAMETER + "=" + str(base64.b64encode(encryptedMessage))

        calledWith = []
        def side_effect(*args, **kwargs):
            try:
                # filter here
                urlParts = parse.urlsplit(args[0])
                if (urlParts["path"] == "my-page" and urlParts["query"] == "filter=something"):
                    calledWith.append(args)
            except:
                self.fail()
        redirectHandler.redirect = Mock(return_value=None, side_effect=side_effect)

        iv = MagicMock(spec=InitVector)
        iv.getBytes.return_value = ivBytes
        token = MagicMock(spec=Token)
        token.getSecretIv.return_value = iv

        sessionData = MagicMock()
        sessionData.__getitem__.return_value = token

        session = {
            Authenticator.SESSION_KEY: sessionData
        }
        sessionOld = {
            Authenticator.SESSION_KEY: sessionData
        }
        auth = Authenticator(
            keyBytes,
            currentUri,
            session,
            redirectHandler
        )

        self.assertEqual(sessionOld, session)
        self.assertIsInstance(session, SessionData)
        newSessionData = session[Authenticator.SESSION_KEY]
        self.assertIsInstance(newSessionData.getData(), BaseResponseData)

####### THIS TEST IS COMMENTED OUT BECAUSE the logout method shouldn't actually call the redirect handler in Python.
####### The developer is expected to handle logout redirects themselves (unlike the PHP implementation).
####### This test remains here as an example of using side effects in unittest, as I'm sure they may be used elsewhere.
    # @patch("Authwave.Token.Token", autospec=True)
    # @patch("Authwave.RedirectHandler.RedirectHandler", autospec=True)
    # def test_logoutCallsLogoutUri(self, redirectHandler, token):
       
    #     token = MagicMock(spec=Token)
    #     token.generateRequestCipher.return_value = "example-request-cipher"
    
    #     token = {
    #         "key": b'11111111111111111111111111111111'
    #     }
    #     userData = {
    #         "id": "example-id",
    #         "email": "person@example.com",
    #         "kvp": {}
    #     }
    #     sessionData = {
    #         "token": token,
    #         "data": userData
    #     }
    #     session = {
    #         Authenticator.SESSION_KEY: sessionData
    #     }

    #     calledWith = []
    #     def side_effect(*args, **kwargs):
    #         calledWith.append(args)
    #     redirectHandler.redirect = Mock(return_value=None, side_effect=side_effect)

    #     clientKey = os.urandom(s.crypto_secretbox_KEYBYTES)

    #     sut = Authenticator(
    #         clientKey,
    #         "https://localhost/",
    #         session,
    #         redirectHandler
    #     )

    #     sut.logout()

    #     if calledWith[0][0]._host != "login.authwave.com":
    #         self.fail()
    #     query = calledWith[0][0].query
    #     query = parse_qs(query)
    #     sessionObj = session[Authenticator.SESSION_KEY]
    #     tokenObj = sessionObj.getToken()
    #     decrypted = token.decode(query[BaseProviderUri.QUERY_STRING_CIPHER])
    #     self.assertNotEqual(session, {})
    

    # @patch("Token.Token", autospec=True)
    # @patch("Cipher.InitVector.InitVector", autospec=True)
    # @patch("Cipher.CipherText.CipherText", autospec=True)
    # @patch("RedirectHandler.RedirectHandler", autospec=True)
    # def test_loginRedirectWithCorrectQueryString(self, redirectHandler, cipherText, iv, token):
    #     sessiondata = {
    #         "id": 34,
    #         "pageentry": "welcome.html"
    #     }

    #     key = "key-" + str(os.urandom(5))
    #     currentPath = "/path/" + str(os.urandom(5))

    #     cipherString = "example-cipher"
    #     cipherText.__str__.return_value = cipherString

    #     ivString = "example-iv"
    #     iv.__str__.return_value = ivString

    #     token.generateRequestCipher.return_value = cipherText
    #     token.getIv.return_value = iv

    #     expectedQueryComponents = {
    #         LoginUri.QUERY_STRING_CIPHER: str(cipherText),
    #         LoginUri.QUERY_STRING_INIT_VECTOR: ivString,
    #         LoginUri.QUERY_STRING_CURRENT_PATH: currentPath
    #     }

    #     expectedQuery = urlencode(expectedQueryComponents)

    #     #sideEffect = lambda obj: obj.getQuery() == expectedQuery
    #     redirectHandlerPassed = "nothing given"
    #     def side_effect(*args, **kwargs):
    #         redirectHandlerPassed = DEFAULT
    #     redirectHandler.redirect = Mock(return_value=None, side_effect=side_effect)
        
    #     sut = Authenticator(key, currentPath, sessiondata, redirectHandler)

    #     sut.login()

    #     # redirectHandler.redirect.assert_called_once_with()
    #     self.assertEqual(redirectHandlerPassed, expectedQuery)