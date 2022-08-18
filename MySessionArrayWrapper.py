import zope.interface
from SessionWrapperInterface import SessionWrapperInterface


@zope.interface.implementer(SessionWrapperInterface)
class MySessionArrayWrapper():
    def __init__(self, sourceArray = None):
        self._sourceArray = sourceArray

    def get(self, key):
        if key in self._sourceArray.keys():
            return self._sourceArray[key]
        else:
            return

    def set(self, key, value):
        self._sourceArray[key] = value

    def contains(self, key):
        return key in self._sourceArray.keys()

    def remove(self, key):
        if key in self._sourceArray.keys():
            del self._sourceArray[key]

    
    def getAsArray(self):
        return self._sourceArray