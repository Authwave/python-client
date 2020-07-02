import json
import time
from dataclasses import FrozenInstanceError
import pytest
from authwave import *
from authwave.runtime import MemorySessionStore, SessionOptions, RequestSession

SECRET = "s" * 32
KEY = "deployment_" + SECRET


class Record(RedirectHandler):
    def __init__(self):
        self.destinations = []

    def redirect(self, uri, code=303):
        self.destinations.append((str(uri), code))


def test_user_models():
    u = AuthUser("id", "email")
    with pytest.raises(FrozenInstanceError):
        u.id = "other"
    assert isinstance(User("id", "email"), AuthUser)
    d = UserResponseData("id", "email", "Welcome")
    assert (d.get_id(), d.get_email(), d.get_message()) == ("id", "email", "Welcome")


def test_missing_state():
    with pytest.raises(SessionNotStartedException):
        Authenticator(KEY, "/")
    with pytest.raises(NotLoggedInException):
        SessionData().get_token()
    with pytest.raises(NotLoggedInException):
        SessionData().get_data()
    auth = Authenticator(KEY, "/", session=GlobalSessionContainer({}))
    with pytest.raises(NotLoggedInException):
        auth.get_auth_user()
    with pytest.warns(DeprecationWarning), pytest.raises(NotLoggedInException):
        auth.get_user()


def test_tokens_and_decoding():
    token = Token(SECRET)
    assert str(token.generate_request_cipher()) == str(token.generate_request_cipher())
    assert str(token.generate_request_cipher()) != str(
        Token(SECRET).generate_request_cipher()
    )
    for id_name in ["id", "uuid"]:
        cipher = str(
            CipherText(
                json.dumps({id_name: "id", "email": "email"}), token.get_iv(), SECRET
            )
        )
        assert token.decode(cipher).id == "id"
    for value in [
        "bad",
        "null",
        "[]",
        "{}",
        '{"id":12,"email":"email"}',
        '{"id":"id","email":null}',
    ]:
        cipher = str(CipherText(value, token.get_iv(), SECRET))
        with pytest.raises(InvalidUserDataSerializationException):
            token.decode(cipher)
    with pytest.raises(DecryptionFailureException):
        token.decode("invalid")
    with pytest.raises(EncryptionFailureException):
        Token("").generate_request_cipher()
    with pytest.raises(ValueError):
        InitVector(0)


def test_session_roundtrip_and_callback_failure():
    token = Token(SECRET)
    session = {}
    container = GlobalSessionContainer(session)
    container.set(SessionData.STORE_KEY, SessionData(token, return_query="x=%7e&flag"))
    calls = []

    def callback(user):
        calls.append(user.id)
        raise RuntimeError("application failed")

    cipher = str(
        CipherText('{"id":"user","email":"email"}', token.get_secret_iv(), SECRET)
    )
    from urllib.parse import quote_plus

    path = "/?AUTHWAVE_RESPONSE_DATA=" + quote_plus(cipher)
    with pytest.raises(RuntimeError):
        Authenticator(KEY, path, session=container, on_authenticated=callback)
    restored = GlobalSessionContainer(json.loads(json.dumps(session)))
    assert restored.get(SessionData.STORE_KEY).has_invoked_authentication_callback()
    record = Record()
    auth = Authenticator(
        KEY, path, session=restored, on_authenticated=callback, redirect_handler=record
    )
    assert calls == ["user"]
    assert auth.get_auth_user().id == "user"
    assert record.destinations == [("/?x=%7e&flag", 303)]
    with pytest.warns(DeprecationWarning):
        assert auth.get_user() is auth.get_auth_user()
    assert restored.contains(SessionData.STORE_KEY)
    restored.remove(SessionData.STORE_KEY)
    assert not restored.contains(SessionData.STORE_KEY)


def test_fake_login_and_logout():
    session = {}
    record = Record()
    auth = Authenticator(
        KEY,
        "/current?old=1",
        session=GlobalSessionContainer(session),
        redirect_handler=record,
    )
    auth.fake_login("dev")
    assert not auth.is_logged_in()
    next_auth = Authenticator(
        KEY,
        record.destinations[0][0],
        session=GlobalSessionContainer(session),
        redirect_handler=record,
    )
    assert next_auth.get_auth_user().email == Authenticator.FAKE_EMAIL
    next_auth.logout()
    assert not next_auth.is_logged_in()
    assert len(record.destinations) == 2
    assert SessionData.STORE_KEY not in session


def test_default_redirect_and_admin():
    auth = Authenticator(KEY, "/", session=GlobalSessionContainer({}))
    assert str(auth.get_admin_uri()) == "https://login.authwave.com/admin/"
    with pytest.raises(RedirectSignal) as result:
        auth.login()
    assert result.value.code == 303
    with pytest.raises(RedirectSignal):
        auth.logout()


def test_session_store_cookies_and_expiry():
    store = MemorySessionStore()
    options = SessionOptions(store)
    context = RequestSession("authwave.sid=" + "f" * 64, options)
    assert context.id != "f" * 64
    assert context.cookie().endswith("; Secure")
    assert "HttpOnly; SameSite=Lax" in context.cookie()
    context.data["basket"] = ["tea"]
    context.commit()
    restored = RequestSession("authwave.sid=" + context.id, options)
    assert restored.data["basket"] == ["tea"]
    store.save("expired", {}, time.time() - 1)
    assert store.load("expired") is None
    with pytest.raises(ValueError):
        RequestSession("", SessionOptions(store, cookie_name="bad;name"))
    with pytest.raises(ValueError):
        RequestSession("", SessionOptions(store, ttl_seconds=0))
