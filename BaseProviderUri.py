from urllib import parse

from InsecureProtocolException import InsecureProtocolException
from PortOutOfBoundsException import PortOutOfBoundsException

class BaseProviderUri():

    DEFAULT_BASE_PROVIDER_URI = "login.authwave.com"
    QUERY_STRING_CIPHER = "cipher"
    QUERY_STRING_INIT_VECTOR = "iv"
    QUERY_STRING_CURRENT_PATH = "path"

    def __init__(self, currentUri):
        ########################## implement applyparts() in __init__()

        components = parse.urlsplit(currentUri)
        self.applyComponents(components)

    # def withoutQueryValue(self):
    #     query = self._components.query
    #     pass
        # expand and remove values

    def normaliseBaseUri(self, baseUri):
        parsedUri = parse.urlparse(baseUri)

        self._scheme = parsedUri.scheme
        self._host = parsedUri.hostname
        self._port = parsedUri.port

        if (
            self._host != "localhost"
            and self._host != "127.0.0.127"
            and self._scheme != "https"
        ):
            raise InsecureProtocolException(self._scheme)

        return self

    def buildQuery(self, token, currentPath, message = ""):
        return parse.urlencode({
            self.QUERY_STRING_CIPHER: str(token.generateRequestCipher(message)),
            self.QUERY_STRING_INIT_VECTOR: str(token.getIv()),
            self.QUERY_STRING_CURRENT_PATH: hex(currentPath)
        })

    def applyComponents(self, components):
        scheme = components.scheme
        if scheme != None:
            self._scheme = self.filterScheme(components.scheme)
        else:
            self._scheme = None

        username = components.username
        password = components.password
        if username != None or password != None:
            self._userInfo = self.filterUserInfo(components.username, components.password) # must accept None
        else:
            self._userInfo = None
        
        host = components.host
        if host != None:
            self._host = self.filterHost(components.host)
        else:
            self._host = None

        port = components.port
        if port != None:
            self._port = self.filterPort(components.port)
        else:
            self._port = None

        path = components.path
        if path != None:
            self._path = self.filterPath(components.path)
        else:
            self._path = None

        query = components.query
        if query != None:
            self._query = self.filterQueryAndFragment(components.query)
        else:
            self._query = None

        fragment = components.fragment
        if fragment != None:
            self._fragment = self.filterQueryAndFragment(components.fragment)
        else:
            self._fragment = None

        self.setDefaults() # it may be better to weave this into this function but perhaps we should go with what is considered the "standard", even if that "standard" only exists in PHP.

    ## Component Filters
    def filterScheme(scheme):
        return scheme.lower()

    def filterHost(host):
        return host.lower()

    def filterPort(port = None):
        if port == None:
            return None
        
        if port < 1 or port > 0xffff:
            raise PortOutOfBoundsException(str(port))
        
        return str(port)


    def __str__(self):
        out = ""

        scheme = self.getScheme()
        if scheme != None:
            out += scheme
            out += ":"

        authority = self.getAuthority()
        if authority != None or scheme == "file":
            out += "//"
            out += authority 

        out += self.getPath()

        query = self.getQuery()
        if query != None:
            out += "?"
            out += query

        fragment = self.getFragment()
        if fragment != None:
            out += "#"
            out += fragment

        return out

    def getScheme(self):
        try:
            return self._scheme
        except NameError:
            return None

    def getAuthority(self):
        try:
            return self._authority
        except NameError:
            return None

    def getPath(self):
        try:
            return self._path
        except NameError:
            return None

    def getQuery(self):
        try:
            return self._query
        except NameError:
            return None
    
    def getFragment(self):
        try:
            return self._fragment
        except NameError:
            return None

    
## Need to decide how to do this. In the PHP client, Uri is a PhpGt class.
## But we don't have that here. Now it does implement an interface, so perhaps
## defining an interface here would be best.

# Maybe make a note of all the Uri methods that we need from this python
# client (to make it the least possible work for the developer)