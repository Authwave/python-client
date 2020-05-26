from urllib.parse import urlsplit, urlunsplit, urlencode, unquote
from .errors import InsecureProtocolException
from .token import Token


def build_query(data: dict[str, str]) -> str:
    # PHP RFC1738 encoding escapes tilde as well.
    return urlencode(data).replace("~", "%7E")


class Uri(str):
    def get_query(self) -> str:
        return urlsplit(self).query

    def get_path(self) -> str:
        return urlsplit(self).path

    def get_host(self) -> str:
        return urlsplit(self).hostname or ""

    def get_scheme(self) -> str:
        return urlsplit(self).scheme

    def get_port(self) -> int | None:
        return urlsplit(self).port

    def with_query(self, query: str) -> "Uri":
        parts = urlsplit(self)
        return Uri(
            urlunsplit(
                (
                    parts.scheme,
                    parts.netloc,
                    parts.path,
                    query.replace("#", "%23"),
                    parts.fragment,
                )
            )
        )

    def without_query_value(self, key: str) -> "Uri":
        query = "&".join(
            p
            for p in self.get_query().split("&")
            if unquote(p.split("=", 1)[0]) != unquote(key)
        )
        return self.with_query(query)


class BaseProviderUri(Uri):
    DEFAULT_BASE_REMOTE_URI = "login.authwave.com"
    QUERY_STRING_CIPHER = "c"
    QUERY_STRING_INIT_VECTOR = "i"
    QUERY_STRING_CURRENT_URI = "u"
    QUERY_STRING_DEPLOYMENT_ID = "d"

    @staticmethod
    def normalize_base_uri(base: str) -> str:
        parts = urlsplit(base if "://" in base else "https://" + base)
        if not parts.hostname:
            raise ValueError("Provider hostname is required")
        if (
            parts.hostname not in ("localhost", "127.0.0.127")
            and parts.scheme != "https"
        ):
            raise InsecureProtocolException(parts.scheme)
        host = parts.hostname
        if ":" in host:
            host = "[" + host + "]"
        return f"{parts.scheme}://{host}" + (
            f":{parts.port}" if parts.port is not None else ""
        )

    @staticmethod
    def build_query(
        token: Token, deployment_id: str, current_path: str, message: str = ""
    ) -> str:
        return build_query(
            {
                "c": str(token.generate_request_cipher(message)),
                "d": deployment_id,
                "i": str(token.get_iv()),
                "u": current_path.encode().hex(),
            }
        )


class LoginUri(BaseProviderUri):
    def __new__(
        cls,
        token: Token,
        current_path: str,
        deployment_id: str,
        base_remote_uri: str = BaseProviderUri.DEFAULT_BASE_REMOTE_URI,
    ):
        message = {"action": "login"}
        query = Uri(current_path).get_query()
        if query and query != "0":
            message["returnQuery"] = query
        return super().__new__(
            cls,
            cls.normalize_base_uri(base_remote_uri)
            + "?"
            + cls.build_query(token, deployment_id, current_path, build_query(message)),
        )


class LogoutUri(BaseProviderUri):
    def __new__(
        cls,
        token: Token,
        current_path: str,
        deployment_id: str,
        base_remote_uri: str = BaseProviderUri.DEFAULT_BASE_REMOTE_URI,
        redirect_to: str | None = None,
    ):
        message = {"action": "logout"}
        if redirect_to is not None:
            message["redirectTo"] = str(redirect_to)
        return super().__new__(
            cls,
            cls.normalize_base_uri(base_remote_uri)
            + "?"
            + cls.build_query(token, deployment_id, current_path, build_query(message)),
        )


class AdminUri(BaseProviderUri):
    def __new__(cls, base_remote_uri: str):
        return super().__new__(cls, cls.normalize_base_uri(base_remote_uri) + "/admin/")
