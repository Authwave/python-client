import os
import sys
sys.path.append( os.path.abspath(os.path.dirname(__file__)+'/..') )






import unittest
from unittest.mock import patch
from Token import Token
from SessionData import SessionData
from UserResponseData import UserResponseData
from NotLoggedInException import NotLoggedInException
from Token import Token


class SessionDataTest(unittest.TestCase):
    
    def test_getTokenNull(self):
        sut = SessionData()
        self.assertRaises(NotLoggedInException, sut.getToken)

    @patch("Token.Token", autospec=Token)
    def test_getToken(self, token):
        sut = SessionData(token)
        self.assertEqual(token, sut.getToken())

    @patch("UserResponseData.UserResponseData", autospec=UserResponseData)
    @patch("Token.Token", autospec=Token)
    def test_getUserData(self, token, userData):
        sut = SessionData(token, userData)
        self.assertEqual(userData, sut.getData())



if __name__ == "__main__":
    unittest.main()