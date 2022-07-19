class Key():

    def __init__(self, binaryData):
        self._binaryData = binaryData

    def __str__(self):
        return self._binaryData.decode("cp437") ## not this encoding type but keep trying different onces
        # https://docs.python.org/2.4/lib/standard-encodings.html

    def __len__(self):
        return len(self._binaryData)
