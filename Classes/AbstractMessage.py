from Classes.InitVector import InitVector

class AbstractMessage():
    
    def __init__(self, data, iv = None):
        if iv == None:
            iv = InitVector()

        self.data = data
        self.iv = iv

    def getIv(self):
        return self._iv
