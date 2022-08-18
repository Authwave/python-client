# from SessionNotStartedException import SessionNotStartedException
import zope.interface

class SessionWrapperInterface(zope.interface.Interface):
    def __init__(self):
        pass

    def get(self, key):
        pass

    def set(self, key, value):
        pass

    def contains(self, key):
        pass

    def remove(self, key):
        pass