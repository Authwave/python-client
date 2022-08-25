from Authwave.Cipher.InitVector import InitVector

class AbstractMessage():
    
    def __init__(self, data, iv = None):
        if iv == None:
            iv = InitVector()
        elif not isinstance(iv, InitVector):
            raise TypeError("iv must be of type Initvector.")

        self.data = data
        self._iv = iv

    def __str__(self):
        return self.data

    def getIv(self):
        return self._iv
