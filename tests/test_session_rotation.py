import json
import time
from urllib.parse import quote_plus
import pytest
from authwave import (
    Authenticator,
    Token,
    SessionData,
    GlobalSessionContainer,
    CipherText,
    RedirectSignal,
    SessionRegenerationException,
    NotLoggedInException,
    UserResponseData,
)
from authwave.runtime import RequestSession, SessionOptions, MemorySessionStore

KEY = "deployment_" + "s" * 32


def pending():
    token = Token("s" * 32)
    state = {}
    GlobalSessionContainer(state).set(SessionData.STORE_KEY, SessionData(token))
    state["basket"] = ["tea"]
    cipher = CipherText(
        '{"id":"user-id","email":"person@example.com"}', token.get_secret_iv(), "s" * 32
    )
    return state, "/callback?AUTHWAVE_RESPONSE_DATA=" + quote_plus(str(cipher))


def test_core_rotates_before_storing_user():
    state, uri = pending()
    events = []

    def rotate():
        with pytest.raises(NotLoggedInException):
            session.get(SessionData.STORE_KEY).get_data()
        events.append("rotate")

    session = GlobalSessionContainer(state, rotate)

    def callback(user):
        assert events == ["rotate"]
        events.append("callback")

    with pytest.raises(RedirectSignal):
        Authenticator(KEY, uri, session=session, on_authenticated=callback)
    assert events == ["rotate", "callback"]


def test_missing_or_failed_rotation_stops_authentication():
    state, uri = pending()
    session = GlobalSessionContainer(state)
    with pytest.raises(SessionRegenerationException):
        Authenticator(KEY, uri, session=session)
    with pytest.raises(NotLoggedInException):
        session.get(SessionData.STORE_KEY).get_data()

    def fail():
        raise RuntimeError("rotation failed")

    session = GlobalSessionContainer(state, fail)
    with pytest.raises(RuntimeError, match="rotation failed"):
        Authenticator(KEY, uri, session=session)
    with pytest.raises(NotLoggedInException):
        session.get(SessionData.STORE_KEY).get_data()
    fresh = {}
    auth = Authenticator(KEY, "/", session=GlobalSessionContainer(fresh))
    with pytest.raises(SessionRegenerationException):
        auth.fake_login("dev")
    assert fresh == {}


def test_runtime_deletes_old_id_before_saving_identity_and_blocks_replay():
    store = MemorySessionStore()
    state, uri = pending()
    old_id = "a" * 64
    store.save(old_id, state, time.time() + 60)
    context = RequestSession("authwave.sid=" + old_id, SessionOptions(store))
    with pytest.raises(RedirectSignal):
        context.authenticator(uri, {"client_key": KEY})
    assert context.id != old_id
    assert store.load(old_id)[SessionData.STORE_KEY]["data"] is None
    context.commit()
    assert store.load(old_id) is None
    assert store.load(context.id)["basket"] == ["tea"]
    restored = RequestSession("authwave.sid=" + context.id, SessionOptions(store))
    assert (
        restored.authenticator("/", {"client_key": KEY}).get_auth_user().id == "user-id"
    )
    assert restored.id == context.id
    replay = RequestSession("authwave.sid=" + old_id, SessionOptions(store))
    with pytest.raises(RedirectSignal):
        replay.authenticator(uri, {"client_key": KEY})
    assert not replay.container.contains(SessionData.STORE_KEY)


def test_failed_invalidation_never_persists_identity():
    class Store(MemorySessionStore):
        def delete(self, id):
            raise RuntimeError("delete failed")

    store = Store()
    state, uri = pending()
    old_id = "a" * 64
    store.save(old_id, state, time.time() + 60)
    context = RequestSession("authwave.sid=" + old_id, SessionOptions(store))
    with pytest.raises(RedirectSignal):
        context.authenticator(uri, {"client_key": KEY})
    with pytest.raises(RuntimeError, match="delete failed"):
        context.commit()
    assert store.load(old_id)[SessionData.STORE_KEY]["data"] is None
    assert store.load(context.id) is None


def test_fake_login_rotates_before_its_identity_is_saved():
    store = MemorySessionStore()
    options = SessionOptions(store)
    original = RequestSession("", options)
    original.data["basket"] = ["tea"]
    original.commit()
    old_id = original.id
    with pytest.raises(RedirectSignal):
        original.authenticator("/", {"client_key": KEY}).fake_login("dev")
    assert original.id != old_id
    original.commit()
    assert store.load(old_id) is None
    assert store.load(original.id)["basket"] == ["tea"]
