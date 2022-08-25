from Authwave.BaseResponseData import BaseResponseData

class UserResponseData(BaseResponseData):
    def __init__(
        self,
        id,
        email,
        kvp = None,
        message = None
    ):
        self._id = id
        self._email = email
        if (kvp == None):
            self._kvp = []
        else:
            self._kvp = kvp
        if (message == None):
            self._message = []
        else:
            self._message = message

        super().__init__(message)

    def getId(self):
        return self._id

    def getEmail(self):
        return self._email

    def getField(self, name):
        if (self._kvp[name] != None):
            return self._kvp[name]
        else:
            return None
        
    def getAllFields(self):
        return self._kvp

    def serialize(self):
        objDict = {}

        objDict["id"] = self._id
        objDict["email"] = self._email
        objDict["kvp"] = self._kvp

        return objDict