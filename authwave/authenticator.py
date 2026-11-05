import json
import warnings
from urllib.parse import parse_qs, urlsplit, urlunsplit, quote
from .cipher import InitVector, CipherText, decrypt
from .errors import NotLoggedInException, RedirectHandler
from .session import GlobalSessionContainer, SessionData
from .token import Token
from .uri import Uri, LoginUri, LogoutUri, AdminUri, build_query
from .user import AuthUser, User, UserResponseData


class Authenticator:
    SESSION_STORE_KEY = "AUTHWAVE_CONSUMER_SESSION"
    RESPONSE_QUERY_PARAMETER = "AUTHWAVE_RESPONSE_DATA"
    FAKE_EMAIL = "fakelogin@authwave.com"

    def __init__(
        self,
        client_key: str,
        current_uri_path: str,
        authwave_host: str = "login.authwave.com",
        session=None,
        redirect_handler=None,
        on_authenticated=None,
    ):
        self._deployment_id, separator, self._secret = client_key.rpartition("_")
        if not separator:
            self._secret = ""
        self._session = session if session is not None else GlobalSessionContainer()
        self._redirect = (
            redirect_handler if redirect_handler is not None else RedirectHandler()
        )
        self._host = authwave_host
        self._callback = on_authenticated
        self._current_uri = Uri(str(current_uri_path))
        self._return_uri = None
        self._user = None
        self._session_data = self._session.get(SessionData.STORE_KEY)
        if self._session_data:
            try:
                data = self._session_data.get_data()
                if isinstance(data, UserResponseData):
                    self._user = User(data.id, data.email)
            except NotLoggedInException:
                pass
        self._complete_auth()

    def set_return_uri(self, uri: str) -> None:
        self._return_uri = Uri(uri)

    def is_logged_in(self) -> bool:
        return self._user is not None

    def get_auth_user(self) -> AuthUser:
        if self._user is None:
            raise NotLoggedInException()
        return self._user

    def get_user(self) -> User:
        warnings.warn(
            "get_user() is deprecated; use get_auth_user()",
            DeprecationWarning,
            stacklevel=2,
        )
        return self.get_auth_user()

    def login(self, token: Token | None = None) -> None:
        if self.is_logged_in():
            return
        token = token if token is not None else Token(self._secret)
        self._session_data = SessionData(
            token,
            return_query=(
                self._return_uri if self._return_uri is not None else self._current_uri
            ).get_query(),
        )
        self._session.set(SessionData.STORE_KEY, self._session_data)
        self._redirect.redirect(self.get_login_uri(token))

    def logout(
        self, redirect_to: str | None = None, token: Token | None = None
    ) -> None:
        fake = self._user is not None and self._user.email == self.FAKE_EMAIL
        self._session.remove(SessionData.STORE_KEY)
        self._user = self._session_data = None
        if fake:
            return
        token = token if token is not None else Token(self._secret)
        destination = redirect_to if redirect_to is not None else self._return_uri
        if isinstance(destination, str) and destination.startswith("?"):
            destination = self._current_uri.with_query(destination[1:])
        self._redirect.redirect(
            LogoutUri(
                token,
                str(
                    self._return_uri
                    if self._return_uri is not None
                    else self._current_uri
                ),
                self._deployment_id,
                self._host,
                destination,
            )
        )

    def fake_login(
        self, user_id: str, email: str | None = None, redirect_to: str = "/"
    ) -> None:
        iv = InitVector()
        token = Token(self._secret, iv)
        self._session.set(SessionData.STORE_KEY, SessionData(token))
        data = UserResponseData(
            user_id, email if email is not None else self.FAKE_EMAIL
        )
        self._session.set(SessionData.STORE_KEY, SessionData(token, data))
        cipher = CipherText(
            json.dumps({"id": data.id, "email": data.email}, separators=(",", ":")),
            iv,
            self._secret,
        )
        self._redirect.redirect(
            Uri(
                redirect_to
                + "?"
                + build_query({self.RESPONSE_QUERY_PARAMETER: str(cipher)})
            )
        )

    def get_login_uri(self, token: Token) -> LoginUri:
        return LoginUri(
            token,
            str(
                self._return_uri if self._return_uri is not None else self._current_uri
            ),
            self._deployment_id,
            self._host,
        )

    def get_admin_uri(self) -> AdminUri:
        return AdminUri(self._host)

    def _complete_auth(self) -> None:
        values = parse_qs(self._current_uri.get_query(), keep_blank_values=True).get(
            self.RESPONSE_QUERY_PARAMETER, []
        )
        query = values[-1].replace(" ", "+") if values else None
        if not query or query == "0":
            return
        if self._session_data is None:
            self._tidy_response_data()
            return
        token = self._session_data.get_token()
        return_query = self._session_data.get_return_query()
        plain = decrypt(query, token.get_secret_iv(), self._secret)
        try:
            data = json.loads(plain)
        except ValueError as error:
            raise TypeError("Invalid authentication response") from error

        def scalar(value):
            if isinstance(value, bool):
                return "1" if value else ""
            if isinstance(value, (str, int, float)):
                return str(value)
            raise TypeError("Expected user id/email scalar")

        if not isinstance(data, dict):
            raise TypeError("Expected authentication object")
        user_data = UserResponseData(scalar(data.get("id")), scalar(data.get("email")))
        self._user = User(user_data.id, user_data.email)
        was_invoked = self._session_data.has_invoked_authentication_callback()
        next_data = SessionData(token, user_data, return_query)
        if was_invoked or self._callback is not None:
            next_data.mark_authentication_callback_invoked()
        self._session.set(SessionData.STORE_KEY, next_data)
        if self._callback is not None and not was_invoked:
            self._callback(self._user)
        self._tidy_response_data(return_query)

    def _tidy_response_data(self, return_query: str | None = None) -> None:
        parts = urlsplit(self._current_uri)
        path = "/" + parts.path.lstrip("/")
        path = quote(path, safe="/%:@!$&'()*+,;=-._~")
        uri = Uri(urlunsplit(("", "", path, parts.query, parts.fragment)))
        if return_query is not None:
            uri = uri.with_query(return_query)
        self._redirect.redirect(uri.without_query_value(self.RESPONSE_QUERY_PARAMETER))
