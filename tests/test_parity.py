import json
import os
import subprocess
from pathlib import Path
import pytest
from authwave import (
    Authenticator,
    Token,
    InitVector,
    SessionData,
    GlobalSessionContainer,
    UserResponseData,
    CipherText,
    InsecureProtocolException,
)

FIXTURES = json.loads((Path(__file__).parent / "fixtures/parity.json").read_text())
SECRET = "s" * 32


class RecordingRedirect:
    def __init__(self):
        self.redirects = []

    def redirect(self, uri, code=303):
        self.redirects.append([str(uri), code])


@pytest.mark.parametrize("fixture", FIXTURES, ids=lambda f: str(f["case"]))
def test_php_parity(fixture):
    c = fixture["case"]
    token = Token(
        SECRET, InitVector().with_bytes(b"a" * 24), InitVector().with_bytes(b"f" * 24)
    )
    state = {"basket": ["tea"]}
    session = GlobalSessionContainer(state, lambda: None)
    if c.get("state") == "pending":
        session.set(
            SessionData.STORE_KEY, SessionData(token, return_query=c.get("returnQuery"))
        )
    if c.get("state") == "user":
        session.set(
            SessionData.STORE_KEY,
            SessionData(
                token, UserResponseData("user-id", c.get("email", "person@example.com"))
            ),
        )
    uri = c.get("uri", "/account?tab=security")
    if "response" in c:
        from urllib.parse import quote_plus

        cipher = str(
            CipherText(
                json.dumps(c["response"], separators=(",", ":")),
                token.get_secret_iv(),
                SECRET,
            )
        )
        uri += (
            ("&" if "?" in uri else "?")
            + "AUTHWAVE_RESPONSE_DATA="
            + (cipher if c.get("rawPlus") else quote_plus(cipher))
        )
    redirect = RecordingRedirect()
    calls = 0

    def callback(user):
        nonlocal calls
        calls += 1
        if c.get("throwCallback"):
            raise RuntimeError("callback")

    auth = error = None
    try:
        auth = Authenticator(
            "deployment_with_underscores_" + SECRET,
            uri,
            authwave_host=c.get("host", "login.authwave.com"),
            session=session,
            redirect_handler=redirect,
            on_authenticated=callback if c.get("callback") else None,
        )
        if c.get("returnUri") is not None:
            auth.set_return_uri(c["returnUri"])
        if c.get("action") == "login":
            auth.login(token)
        if c.get("action") == "logout":
            auth.logout(c.get("redirectTo"), token)
    except Exception as exception:
        error = (
            "RuntimeException"
            if str(exception) == "callback"
            else type(exception).__name__
        )
    stored = session.get(SessionData.STORE_KEY)
    data = None
    if stored:
        try:
            d = stored.get_data()
            data = [d.id, d.email]
        except Exception:
            pass
    user = auth.get_auth_user() if auth and auth.is_logged_in() else None
    assert {
        "redirects": redirect.redirects,
        "calls": calls,
        "error": error,
        "user": [user.id, user.email] if user else None,
        "stored": stored is not None,
        "data": data,
        "returnQuery": stored.get_return_query() if stored else None,
        "invoked": stored.has_invoked_authentication_callback() if stored else None,
        "basket": state["basket"],
    } == fixture["expected"]


def test_live_php_reference():
    reference = os.environ.get("AUTHWAVE_PHP_REFERENCE")
    if not reference:
        return
    result = subprocess.run(
        ["php", str(Path(__file__).parent / "fixtures/php-oracle.php"), reference],
        input=json.dumps([f["case"] for f in FIXTURES]),
        capture_output=True,
        text=True,
        check=True,
        timeout=20,
    )
    assert json.loads(result.stdout) == [f["expected"] for f in FIXTURES]
