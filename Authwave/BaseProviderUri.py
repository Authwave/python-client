from urllib import parse
import re
import base64

from Authwave.InsecureProtocolException import InsecureProtocolException
from Authwave.PortOutOfBoundsException import PortOutOfBoundsException

class BaseProviderUri():

    DEFAULT_BASE_PROVIDER_URI = "https://login.authwave.com"
    QUERY_STRING_CIPHER = "cipher"
    QUERY_STRING_INIT_VECTOR = "iv"
    QUERY_STRING_CURRENT_PATH = "path"

    CHAR_UNRESERVED = 'a-zA-Z0-9_\-\.~'
    CHAR_SUBDELIMS = '!\$&\'\(\)*\+,;='

    DEFAULT_HOST_HTTP = "localhost"

    def __init__(self, currentUri):

        if isinstance(currentUri, str):
            components = parse.urlsplit(currentUri)
            self.applyComponents(components)

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

    def buildQuery(self, token, currentPath, host, message = "",):
        cipher = token.generateRequestCipher(message)

        params = {
            self.QUERY_STRING_CIPHER: base64.b64encode(cipher.getBytes()),
            self.QUERY_STRING_INIT_VECTOR: base64.b64encode(token.getIv().getBytes()),
            self.QUERY_STRING_CURRENT_PATH: str(currentPath).encode('utf-8').hex()
        }
        queryString = BaseProviderUri.querify(params)
        return host + queryString

    def querify(params):
        out = "?"
        for key in params.keys():
            out += key
            out += "="
            if isinstance(params[key], str):
                out += params[key]
            elif isinstance(params[key], bytes):
                out += params[key].decode('UTF-8')
            else:
                return False
            out += "&"

        return out

    def applyComponents(self, components):
        scheme = components.scheme
        if scheme != None:
            self._scheme = components.scheme
        else:
            self._scheme = None

        username = components.username
        password = components.password
        if username != None or password != None:
            self._userInfo = BaseProviderUri.filterUserInfo(components.username, components.password) # must accept None
        else:
            self._userInfo = None
        
        host = components.hostname
        if host != None:
            self._host = host
        else:
            self._host = None

        port = components.port
        if port != None:
            self._port = components.port
        else:
            self._port = None

        path = components.path
        if path != None:
            self._path = components.path
        else:
            self._path = None

        query = components.query
        if query != None:
            self._query = components.query
        else:
            self._query = None

        fragment = components.fragment
        if fragment != None:
            self._fragment = components.fragment
        else:
            self._fragment = None

        self.setDefaults()

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

    def filterPath(path):
        return path

    def filterQueryAndFragment(query):
        regex = '/(?:[^' + BaseProviderUri.CHAR_UNRESERVED + BaseProviderUri.CHAR_SUBDELIMS + '%:@\/\?]+|5(?![A-Fa-f0-9]{2}))/'
        matchList = re.findall(regex, query)
        if len(matchList) > 0:
            return parse.urlencode(matchList[0])
        return ""

    def filterUserInfo(user, password = None):
        userInfo = user

        if password != None and len(password) > 0:
            userInfo += ":"
            userInfo += password

        return userInfo
    
    def setDefaults(self):
        if self._host != None:
            if self._scheme == "http" or self._scheme == "https":
                self._host = BaseProviderUri.DEFAULT_HOST_HTTP
        
        try:
            if self._authority == None:
                if self._path.startswith("//"):
                    raise ValueError("The path of a URI withough an authority must not start with two slashes \"//\"")
                pathParts = self._path.split('/', 2)
                if self._scheme == None and pathParts[0].find(':') >= 0:
                    raise ValueError("A relative URI must not have a path beginning with a segment containing a colon")
        except AttributeError:
            self._authority = None

    def __str__(self):
        out = ""

        out += self._scheme + "://" + self._host
        try:
            out += "?" + self.query
        except AttributeError:
            return out

        return out

    def withoutQueryValue(uri, queryValue):
        # split location from query
        uriHalves = uri.split("?")
        uriQueryString = uriHalves[1]

        # remove the specified parameter from the query
        queryDict = parse.parse_qs(uriQueryString)
        del queryDict[queryValue]

        # rebuild uri
        newQueryString = BaseProviderUri.querify(queryDict)
        newUri = uriHalves[0] + newQueryString
        return newUri



    
## Need to decide how to do this. In the PHP client, Uri is a PhpGt class.
## But we don't have that here. Now it does implement an interface, so perhaps
## defining an interface here would be best.

# Maybe make a note of all the Uri methods that we need from this python
# client (to make it the least possible work for the developer)