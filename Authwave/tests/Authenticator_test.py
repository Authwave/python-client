from binhex import binhex
import os
import sys
from urllib.parse import parse_qs, urlencode, urlparse
from Authwave.UserResponseData import UserResponseData
import pysodium as s
sys.path.append( os.path.abspath(os.path.dirname(__file__)+'/..') )

import unittest
from unittest.mock import DEFAULT, Mock, MagicMock, patch

from Authwave.Authenticator import Authenticator
from Authwave.SessionNotDictLikeException import SessionNotDictLikeException
# from Authwave.GlobalSessionContainer import GlobalSessionContainer
# from Authwave.MySessionArrayWrapper import MySessionArrayWrapper
from Authwave.SessionData import SessionData
from Authwave.LoginUri import LoginUri
from Authwave.BaseProviderUri import BaseProviderUri
from Authwave.Token import Token

class AuthenticatorTest(unittest.TestCase):
    
    @patch("RedirectHandler.RedirectHandler", autospec=True)
    def test_constructWithNoSession(self, redirectHandler):

        with self.assertRaises(TypeError):
            Authenticator("test-key", "/", redirectHandler=redirectHandler)
    
    @patch("RedirectHandler.RedirectHandler", autospec=True)
    def test_constructWithNonDictSession(self, redirectHandler):
        session = "sessionid: 12, page: 3"

        with self.assertRaises(SessionNotDictLikeException):
            Authenticator("test-key", "/", session, redirectHandler)

    @patch("RedirectHandler.RedirectHandler", autospec=True)
    def test_constructWithExistingSession(self, redirectHandler):

        sessiondata = {
            "id": 34,
            "pageentry": "welcome.html"
        }

        authenticator = Authenticator("test-key", "https://whateversite.com/", sessiondata, redirectHandler)

        self.assertEqual(sessiondata, authenticator._sessionObject)

    @patch("RedirectHandler.RedirectHandler", autospec=True)
    def test_trackSessionChanges(self, redirectHandler):

        sessiondata = {
            "id": 34,
            "pageentry": "welcome.html"
        }

        authenticator = Authenticator("test-key", "/", sessiondata, redirectHandler)

        sessiondata["testvalue"] = "somedata"

        self.assertEqual(sessiondata, authenticator._sessionObject)

    @patch("RedirectHandler.RedirectHandler", autospec=True)
    def test_isLoggedInFalseByDefault(self, redirectHandler):
        sessiondata = {
            "id": 34,
            "pageentry": "welcome.html"
        }

        sut = Authenticator("test-key", "/", sessiondata, redirectHandler)

        self.assertFalse(sut.isLoggedIn())

    @patch("Token.Token", autospec=True)
    @patch("UserResponseData.UserResponseData", autospec=True)
    @patch("SessionData.SessionData", autospec=True)
    @patch("RedirectHandler.RedirectHandler", autospec=True)
    def test_isLoggedInTrueWhenSessionDataSet(self, redirectHandler, sessionData, userResponseData, token):
       
        token = {
            "key": b'11111111111111111111111111111111'
        }
        userData = {
            "id": "ub92n3fwjnf39",
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

    @patch("Token.Token", autospec=True)
    @patch("RedirectHandler.RedirectHandler", autospec=True)
    @patch("SessionData.SessionData", autospec=True)
    def test_logoutCallsLogoutUri(self, sessionData, redirectHandler, token):
       
        token.generateRequestCipher.return_value = "example-request-cipher"
        session = {
            Authenticator.SESSION_KEY: sessionData
        }
        session[Authenticator.SESSION_KEY].getToken.return_value = token

        calledWith = []
        def side_effect(*args, **kwargs):
            calledWith.append(args)
        redirectHandler.redirect = Mock(return_value=None, side_effect=side_effect)

        clientKey = os.urandom(s.crypto_secretbox_KEYBYTES)

        sut = Authenticator(
            clientKey,
            "https://localhost/",
            session,
            redirectHandler
        )

        sut.logout()

        if calledWith[0][0]._host != "login.authwave.com":
            self.fail()
        query = calledWith[0][0].query
        query = parse_qs(query)
        sessionObj = session[Authenticator.SESSION_KEY]
        tokenObj = sessionObj.getToken()
        decrypted = token.decode(query[BaseProviderUri.QUERY_STRING_CIPHER])
        self.assertNotEqual(session, {})
    

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