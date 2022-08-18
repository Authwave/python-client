from binhex import binhex
import os
import sys
from urllib.parse import urlencode, urlparse
sys.path.append( os.path.abspath(os.path.dirname(__file__)+'/..') )

import unittest
from unittest.mock import DEFAULT, Mock, MagicMock, patch

from Authenticator import Authenticator
from SessionNotDictLikeException import SessionNotDictLikeException
from GlobalSessionContainer import GlobalSessionContainer
from MySessionArrayWrapper import MySessionArrayWrapper
from RedirectHandler import RedirectHandler
from SessionData import SessionData
from LoginUri import LoginUri

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

        ##### rewrite with new session structure

        sessiondata = {
            "id": 34,
            "pageentry": "welcome.html"
        }

        authenticator = Authenticator("test-key", "/", sessiondata, redirectHandler)

        self.assertEqual(sessiondata, authenticator._sessionObject)

    @patch("RedirectHandler.RedirectHandler", autospec=True)
    def test_trackSessionChanges(self, redirectHandler):
        
        ##### rewrite with new session structure

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

    @patch("UserResponseData.UserResponseData", autospec=True)
    @patch("SessionData.SessionData", autospec=True)
    @patch("RedirectHandler.RedirectHandler", autospec=True)
    def test_isLoggedInTrueWhenSessionDataSet(self, redirectHandler, sessionData, userResponseData):

        #### This test is broken. There's most likely an issue with how we are setting up the sessiondata variable
        # Debug and step through, see what's up

        userResponseData.getId.return_value = 12
        userResponseData.getEmail.return_value = "person@example.com"
        userResponseData.getAllFields.return_value = {
            "test_data": "test_value"
        }
        sessionData.getData.return_value = userResponseData

        session = {
            str(SessionData.__name__): sessionData
        }

        sut = Authenticator("test-key", "/", session, redirectHandler)

        self.assertTrue(sut.isLoggedIn())

    @patch("RedirectHandler.RedirectHandler", autospec=True)
    @patch("SessionData.SessionData", autospec=True)
    def test_logoutCallsLogoutUri(self, sessionData, redirectHandler):
        session = {
            Authenticator.SESSION_KEY: sessionData
        }

        redirectHandlerPassed = "nothing given"
        def side_effect(*args, **kwargs):
            redirectHandlerPassed = DEFAULT
        redirectHandler.redirect = Mock(return_value=None, side_effect=side_effect)

        sut = Authenticator(
            "test-key",
            "/",
            session,
            redirectHandler,
            "http://localhost:1/login.html",
        )

        sut.logout()
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