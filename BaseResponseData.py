from abc import ABC

class BaseResponseData(ABC):
    def __init__(
        self,
        message
    ):
        self._message = message

    def getMessage(self):
        return self._message