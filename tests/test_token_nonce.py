import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor
import pytest
from authwave import (
    Authenticator,
    Token,
    TokenReuseException,
    SessionData,
    GlobalSessionContainer,
    CipherText,
    EncryptionFailureException,
    LoginUri,
    LogoutUri,
    RedirectSignal,
    decrypt,
)

SECRET = "s" * 32
KEY = "deployment_" + SECRET


@pytest.mark.parametrize(
    "first,second",
    [
        ("action=login", "action=logout"),
        ("", "action=login"),
        ("action=login", ""),
        ("action=login&returnQuery=page%3D1", "action=login&returnQuery=page%3D2"),
    ],
)
def test_changed_requests_are_rejected(first, second):
    token = Token(SECRET)
    iv = token.get_iv().get_bytes()
    cipher = str(token.generate_request_cipher(first))
    with pytest.raises(TokenReuseException):
        token.generate_request_cipher(second)
    assert token.get_iv().get_bytes() == iv
    assert str(token.generate_request_cipher(first)) == cipher
    assert decrypt(cipher, token.get_iv(), SECRET) == first + "&secretIv=" + str(
        token.get_secret_iv()
    )


def test_session_serialisation_keeps_binding():
    token = Token(SECRET)
    cipher = str(token.generate_request_cipher("action=login"))
    restored = SessionData.from_dict(
        json.loads(json.dumps(SessionData(token).to_dict()))
    ).get_token()
    assert str(restored.generate_request_cipher("action=login")) == cipher
    with pytest.raises(TokenReuseException):
        restored.generate_request_cipher("action=logout")


def test_unused_tokens_can_be_restored():
    token = Token.from_dict(Token(SECRET).to_dict())
    assert str(token.generate_request_cipher("action=login"))


def test_legacy_tokens_can_decrypt_but_not_encrypt_with_unknown_binding():
    token = Token(SECRET)
    legacy = token.to_dict()
    del legacy["request_plaintext"]
    restored = Token.from_dict(legacy)
    cipher = CipherText(
        '{"id":"user-id","email":"person@example.com"}', token.get_iv(), SECRET
    )
    assert restored.decode(str(cipher)).get_id() == "user-id"
    with pytest.raises(TokenReuseException):
        restored.generate_request_cipher("action=login")


def test_failed_encryption_does_not_bind_token():
    token = Token("")
    for message in ["action=login", "action=logout"]:
        with pytest.raises(EncryptionFailureException):
            token.generate_request_cipher(message)


def test_uri_builders_require_separate_tokens():
    token = Token(SECRET)
    login = LoginUri(token, "/callback", "deployment")
    assert LoginUri(token, "/callback", "deployment") == login
    with pytest.raises(TokenReuseException):
        LogoutUri(token, "/callback", "deployment")
    assert LogoutUri(Token(SECRET), "/callback", "deployment")


def test_rejected_login_preserves_pending_exchange():
    pending = SessionData(Token(SECRET))
    state = {}
    session = GlobalSessionContainer(state)
    session.set(SessionData.STORE_KEY, pending)
    state["basket"] = ["tea"]
    before = json.loads(json.dumps(state))
    used = Token(SECRET)
    used.generate_request_cipher("action=logout")
    auth = Authenticator(KEY, "/callback", session=session)
    with pytest.raises(TokenReuseException):
        auth.login(used)
    assert state == before


def test_login_saves_bound_token():
    state = {}
    session = GlobalSessionContainer(state)
    auth = Authenticator(KEY, "/callback", session=session)
    with pytest.raises(RedirectSignal):
        auth.login()
    restored = (
        GlobalSessionContainer(json.loads(json.dumps(state)))
        .get(SessionData.STORE_KEY)
        .get_token()
    )
    with pytest.raises(TokenReuseException):
        restored.generate_request_cipher("action=logout")


def test_concurrent_changed_requests_cannot_both_encrypt(monkeypatch):
    import authwave.token as token_module

    real_cipher = token_module.CipherText

    def slow_cipher(*args):
        time.sleep(0.02)
        return real_cipher(*args)

    monkeypatch.setattr(token_module, "CipherText", slow_cipher)
    barrier = threading.Barrier(2)
    token = Token(SECRET)

    def generate(message):
        barrier.wait()
        try:
            return ("cipher", str(token.generate_request_cipher(message)))
        except TokenReuseException:
            return ("rejected", None)

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(generate, ["action=login", "action=logout"]))
    assert sorted(result[0] for result in results) == ["cipher", "rejected"]
