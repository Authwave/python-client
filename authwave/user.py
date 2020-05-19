"""Identity snapshots returned by Authwave."""

from dataclasses import dataclass


@dataclass(frozen=True)
class AuthUser:
    id: str
    email: str


class User(AuthUser):
    """Deprecated compatibility name; use AuthUser."""


@dataclass(frozen=True)
class BaseResponseData:
    message: str | None = None

    def get_message(self) -> str | None:
        return self.message


@dataclass(frozen=True, init=False)
class UserResponseData(BaseResponseData):
    id: str
    email: str

    def __init__(self, id: str, email: str, message: str | None = None):
        object.__setattr__(self, "id", id)
        object.__setattr__(self, "email", email)
        object.__setattr__(self, "message", message)

    def get_id(self) -> str:
        return self.id

    def get_email(self) -> str:
        return self.email
