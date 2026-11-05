import asyncio
from urllib.parse import quote_plus, urlsplit
import pytest
from authwave import (
    Authenticator,
    GlobalSessionContainer,
    SessionData,
    Token,
    CipherText,
    RedirectSignal,
)
from authwave.runtime import MemorySessionStore, SessionOptions
from authwave.integrations.wsgi import AuthwaveWSGI
from authwave.integrations.asgi import AuthwaveASGI

KEY = "deployment_" + "s" * 32


class MemorySession(GlobalSessionContainer):
    def regenerate(self):
        pass


@pytest.mark.parametrize(
    "input,expected",
    [
        ("//evil.example/path", "/path"),
        ("//evil.example", "/"),
        ("https://evil.example/path", "/path"),
        ("https://user:pass@evil.example/path", "/path"),
        ("https://app.example//evil.example/path", "/evil.example/path"),
        ("/%2F%2Fevil.example/path", "/%2F%2Fevil.example/path"),
        ("/members/a%2Fb", "/members/a%2Fb"),
        ("/members/orders", "/members/orders"),
    ],
)
def test_unsolicited_response_cleanup_stays_local(input, expected):
    with pytest.raises(RedirectSignal) as result:
        Authenticator(
            KEY,
            input + "?keep=%7e&flag&AUTHWAVE_RESPONSE_DATA=anything#details",
            session=MemorySession({}),
        )
    uri = result.value.uri
    assert result.value.code == 303
    assert uri == expected + "?keep=%7e&flag#details"
    assert urlsplit(uri).scheme == "" and urlsplit(uri).netloc == ""
    assert uri.startswith("/") and not uri.startswith("//")


@pytest.mark.parametrize("input", ["/\\evil.example/path", "x:/\\evil.example/path"])
def test_backslash_cleanup_is_safe(input):
    with pytest.raises(RedirectSignal) as result:
        Authenticator(
            KEY, input + "?AUTHWAVE_RESPONSE_DATA=anything", session=MemorySession({})
        )
    uri = result.value.uri
    assert uri.startswith("/") and not uri.startswith("//")
    assert "\\" not in uri
    assert urlsplit(uri).netloc == ""


def test_authenticated_cleanup_preserves_saved_query_and_encoded_path():
    token = Token("s" * 32)
    session = MemorySession({})
    session.set(
        SessionData.STORE_KEY,
        SessionData(token, return_query="filter=original&flag&encoded=%7e"),
    )
    cipher = CipherText(
        '{"id":"user-id","email":"person@example.com"}', token.get_secret_iv(), "s" * 32
    )
    with pytest.raises(RedirectSignal) as result:
        Authenticator(
            KEY,
            "https://user:pass@evil.example//members/a%2Fb?AUTHWAVE_RESPONSE_DATA="
            + quote_plus(str(cipher))
            + "#details",
            session=session,
        )
    assert result.value.uri == "/members/a%2Fb?filter=original&flag&encoded=%7e#details"
    assert session.get(SessionData.STORE_KEY).get_data().id == "user-id"


def test_duplicate_response_parameters_are_removed():
    with pytest.raises(RedirectSignal) as result:
        Authenticator(
            KEY,
            "//evil.example/path?AUTHWAVE_RESPONSE_DATA=one&flag&AUTHWAVE_RESPONSE_DATA=two&next=https://evil.example",
            session=MemorySession({}),
        )
    assert result.value.uri == "/path?flag&next=https://evil.example"


def test_wsgi_cleanup_header_cannot_redirect_to_another_host():
    def app(environ, start_response):
        pytest.fail("cleanup should redirect before the app")

    wrapped = AuthwaveWSGI(app, SessionOptions(MemorySessionStore()), client_key=KEY)
    recorded = {}

    def start(status, headers, exc_info=None):
        recorded.update(status=status, headers=dict(headers))

    list(
        wrapped(
            {
                "PATH_INFO": "//evil.example/path",
                "QUERY_STRING": "keep=1&AUTHWAVE_RESPONSE_DATA=anything",
            },
            start,
        )
    )
    assert recorded["status"] == "303 See Other"
    assert recorded["headers"]["Location"] == "/path?keep=1"


def test_asgi_cleanup_header_cannot_redirect_to_another_host():
    async def app(scope, receive, send):
        pytest.fail("cleanup should redirect before the app")

    async def receive():
        pytest.fail("receive is not needed")

    messages = []

    async def send(message):
        messages.append(message)

    wrapped = AuthwaveASGI(app, SessionOptions(MemorySessionStore()), client_key=KEY)
    asyncio.run(
        wrapped(
            {
                "type": "http",
                "path": "//evil.example/path",
                "query_string": b"keep=1&AUTHWAVE_RESPONSE_DATA=anything",
                "headers": [],
            },
            receive,
            send,
        )
    )
    assert messages[0]["status"] == 303
    assert dict(messages[0]["headers"])[b"location"] == b"/path?keep=1"
