class User():
    def __init__(
        self, id, email, kvp
    ):
        self.id = id
        self.email = email
        self._kvp = kvp

    def getData(key):
        # use key to return value in kvp
        # if failure, just return None
        try:
            return self._kvp[key]
        except:
            return None