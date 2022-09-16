import os
import sys
sys.path.append( os.path.abspath(os.path.dirname(__file__)+'/..') )

import unittest
from unittest.mock import patch
from Authwave.Token import Token
from Authwave.SessionData import SessionData
from Authwave.UserResponseData import UserResponseData
from Authwave.NotLoggedInException import NotLoggedInException
from Authwave.Token import Token


class SessionDataTest(unittest.TestCase):
    
    def test_getTokenNull(self):
        sut = SessionData()
        self.assertRaises(NotLoggedInException, sut.getToken)

    @patch("Authwave.Token.Token", autospec=Token)
    def test_getToken(self, token):
        sut = SessionData(token)
        self.assertEqual(token, sut.getToken())

    @patch("Authwave.UserResponseData.UserResponseData", autospec=UserResponseData)
    @patch("Authwave.Token.Token", autospec=Token)
    def test_getUserData(self, token, userData):
        sut = SessionData(token, userData)
        self.assertEqual(userData, sut.getData())



if __name__ == "__main__":
    unittest.main()