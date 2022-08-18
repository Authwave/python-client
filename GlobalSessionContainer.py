from MySessionArrayWrapper import MySessionArrayWrapper
from SessionNotDictLikeException import SessionNotDictLikeException

class GlobalSessionContainer(MySessionArrayWrapper):
    def __init__(self, source):
        # source must be readable dict-like session data object - not a copy
        # if source is None:
        #     raise SessionArrayWrapperNotImplementedException
        # super().__init__(source)
        pass

        ## another possible way of doing this would be to provide an object that abides by an interface.
        # GlobalSessionContainer2.py is an example
