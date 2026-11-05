"""Opaque-cookie server sessions shared by framework adapters."""

import copy
import json
import re
import secrets
import threading
import time
from dataclasses import dataclass
from http.cookies import SimpleCookie
from typing import Protocol
from .authenticator import Authenticator
from .session import GlobalSessionContainer


class SessionStore(Protocol):
    def load(self, id: str) -> dict | None: ...
    def save(self, id: str, data: dict, expires_at: float) -> None: ...
    def delete(self, id: str) -> None: ...


class MemorySessionStore:
    """Development store. Production applications supply shared persistent storage."""

    def __init__(self):
        self._entries = {}
        self._lock = threading.RLock()

    def load(self, id: str) -> dict | None:
        with self._lock:
            entry = self._entries.get(id)
            if entry is None:
                return None
            if entry[0] <= time.time():
                del self._entries[id]
                return None
            return copy.deepcopy(entry[1])

    def delete(self, id: str) -> None:
        with self._lock:
            self._entries.pop(id, None)

    def save(self, id: str, data: dict, expires_at: float) -> None:
        # Reject non-JSON session values before committing anything.
        value = json.loads(json.dumps(data))
        with self._lock:
            now = time.time()
            self._entries = {k: v for k, v in self._entries.items() if v[0] > now}
            self._entries[id] = (expires_at, value)


@dataclass(frozen=True)
class SessionOptions:
    store: SessionStore
    cookie_name: str = "authwave.sid"
    secure_cookie: bool = True
    ttl_seconds: int = 86400


class RequestSession:
    def __init__(self, cookie_header: str, options: SessionOptions):
        if not re.fullmatch(r"[\w.-]+", options.cookie_name, re.ASCII):
            raise ValueError("Invalid cookie name")
        if type(options.ttl_seconds) is not int or options.ttl_seconds < 1:
            raise ValueError("ttl_seconds must be a positive integer")
        self.options = options
        cookie = SimpleCookie()
        cookie.load(cookie_header)
        candidate = cookie.get(options.cookie_name)
        candidate = candidate.value if candidate else ""
        stored = (
            options.store.load(candidate)
            if re.fullmatch("[a-f0-9]{64}", candidate)
            else None
        )
        self.id = candidate if stored is not None else secrets.token_hex(32)
        self.data = copy.deepcopy(stored) if stored is not None else {}
        self._previous_ids = []
        self.container = GlobalSessionContainer(self.data, self.regenerate)

    def authenticator(self, path: str, auth_options: dict) -> Authenticator:
        return Authenticator(
            current_uri_path=path, session=self.container, **auth_options
        )

    def regenerate(self) -> None:
        new_id = secrets.token_hex(32)
        self._previous_ids.append(self.id)
        self.id = new_id

    def commit(self) -> None:
        for old_id in self._previous_ids:
            self.options.store.delete(old_id)
        self.options.store.save(
            self.id, self.data, time.time() + self.options.ttl_seconds
        )

    def cookie(self) -> str:
        o = self.options
        return (
            f"{o.cookie_name}={self.id}; Path=/; HttpOnly; SameSite=Lax; Max-Age={o.ttl_seconds}"
            + ("; Secure" if o.secure_cookie else "")
        )
