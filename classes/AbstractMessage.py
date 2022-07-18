## Test class 
# Non-functional


from abc import ABC, abstractmethod
import this #import abstract base class abilities

class AbstractMethod(ABC):

    DEFAULT_ALGO = "aes-256-ctr"
    DEFAULT_OPTIONS = {
        "algo": DEFAULT_ALGO
    }

    _algo = None
    _iv = None

    def AbstractMethod(self, data, key, iv = None, options = this.DEFAULT_OPTIONS):
        if (iv == None):
            length = False
            
