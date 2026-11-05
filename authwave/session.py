from .errors import (
    NotLoggedInException,
    SessionNotStartedException,
    SessionRegenerationException,
)
from .token import Token
from .user import UserResponseData, BaseResponseData


class SessionData:
    STORE_KEY = "Authwave\\SessionData"

    def __init__(
        self,
        token: Token | None = None,
        data: BaseResponseData | None = None,
        return_query: str | None = None,
    ):
        self._token, self._data, self._return_query = token, data, return_query
        self._callback_invoked = False

    def get_token(self) -> Token:
        if self._token is None:
            raise NotLoggedInException()
        return self._token

    def get_data(self) -> BaseResponseData:
        if self._data is None:
            raise NotLoggedInException()
        return self._data

    def get_return_query(self) -> str | None:
        return self._return_query

    def has_invoked_authentication_callback(self) -> bool:
        return self._callback_invoked

    def mark_authentication_callback_invoked(self) -> None:
        self._callback_invoked = True

    def to_dict(self) -> dict:
        return {
            "token": self._token.to_dict() if self._token else None,
            "data": {
                "id": self._data.id,
                "email": self._data.email,
                "message": self._data.message,
            }
            if isinstance(self._data, UserResponseData)
            else None,
            "return_query": self._return_query,
            "callback_invoked": self._callback_invoked,
        }

    @classmethod
    def from_dict(cls, value: dict) -> "SessionData":
        result = cls(
            Token.from_dict(value["token"]) if value["token"] else None,
            UserResponseData(**value["data"]) if value["data"] else None,
            value["return_query"],
        )
        result._callback_invoked = value["callback_invoked"]
        return result


class GlobalSessionContainer:
    """Wrap an existing request-scoped mapping, never a process global."""

    def __init__(self, data=None, regenerate=None):
        if data is None:
            raise SessionNotStartedException()
        self.data = data
        self._regenerate = regenerate

    def get(self, key: str):
        value = self.data.get(key)
        if key == SessionData.STORE_KEY and isinstance(value, dict):
            return SessionData.from_dict(value)
        return value

    def set(self, key: str, value) -> None:
        self.data[key] = value.to_dict() if isinstance(value, SessionData) else value

    def contains(self, key: str) -> bool:
        return key in self.data

    def remove(self, key: str) -> None:
        self.data.pop(key, None)

    def regenerate(self) -> None:
        if self._regenerate is None:
            raise SessionRegenerationException("Supply a session regeneration callback")
        self._regenerate()


SessionArrayWrapper = GlobalSessionContainer
