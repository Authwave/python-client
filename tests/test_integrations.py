import base64
from urllib.parse import urlsplit, parse_qs, quote_plus
import pytest
from authwave import CipherText, InitVector, decrypt
from authwave.runtime import MemorySessionStore, SessionOptions

KEY = "deployment_" + "s" * 32


def provider_response(location):
    q = parse_qs(urlsplit(location).query)
    plain = decrypt(
        q["c"][0], InitVector().with_bytes(base64.b64decode(q["i"][0])), "s" * 32
    )
    iv = plain.rsplit("&secretIv=", 1)[1]
    cipher = CipherText(
        '{"id":"user-id","email":"person@example.com"}',
        InitVector().with_bytes(base64.b64decode(iv)),
        "s" * 32,
    )
    return "/callback?AUTHWAVE_RESPONSE_DATA=" + quote_plus(str(cipher))


def action(auth, path):
    if path == "/login":
        auth.set_return_uri("/callback")
        auth.login()
    if path == "/logout":
        auth.logout("/signed-out")
    return {
        "loggedIn": auth.is_logged_in(),
        "id": auth.get_auth_user().id if auth.is_logged_in() else None,
    }


@pytest.mark.parametrize("framework", ["flask", "django", "fastapi", "wsgi"])
def test_roundtrip(framework):
    store = MemorySessionStore()
    options = SessionOptions(store, secure_cookie=False)
    if framework == "flask":
        from flask import Flask, request
        from authwave.integrations.flask import authwave_handler

        app = Flask(__name__)

        @app.route("/<path:path>")
        @authwave_handler(options, client_key=KEY)
        def view(auth, path):
            return action(auth, request.path)

        client = app.test_client()
        invoke = lambda path: client.get(path)
        body = lambda response: response.json
    elif framework == "django":
        from django.conf import settings

        if not settings.configured:
            settings.configure(
                SECRET_KEY="test", DEFAULT_CHARSET="utf-8", ALLOWED_HOSTS=["testserver"]
            )
        from django.test import RequestFactory
        from django.http import JsonResponse
        from authwave.integrations.django import authwave_handler

        @authwave_handler(options, client_key=KEY)
        def view(request):
            return JsonResponse(action(request.authwave, request.path))

        jar = {}

        def invoke(path):
            response = view(
                RequestFactory().get(
                    path, HTTP_COOKIE="; ".join(f"{k}={v}" for k, v in jar.items())
                )
            )
            for k, v in response.cookies.items():
                jar[k] = v.value
            return response

        import json

        body = lambda response: json.loads(response.content)
    elif framework == "fastapi":
        from fastapi import FastAPI, Request
        from fastapi.testclient import TestClient
        from authwave.integrations.fastapi import AuthwaveMiddleware

        app = FastAPI()
        app.add_middleware(AuthwaveMiddleware, session_options=options, client_key=KEY)

        @app.get("/{path:path}")
        def view(request: Request):
            return action(request.state.authwave, request.url.path)

        client = TestClient(app)
        invoke = lambda path: client.get(path, follow_redirects=False)
        body = lambda response: response.json()
    else:
        import json
        from werkzeug.test import Client
        from werkzeug.wrappers import Response
        from authwave.integrations.wsgi import AuthwaveWSGI

        def app(environ, start_response):
            result = action(environ["authwave.auth"], environ["PATH_INFO"])
            start_response("200 OK", [("Content-Type", "application/json")])
            return [json.dumps(result).encode()]

        client = Client(AuthwaveWSGI(app, options, client_key=KEY), Response)
        invoke = lambda path: client.get(path)
        body = lambda response: response.json
    initial = invoke("/login")
    assert initial.status_code == 303
    completed = invoke(provider_response(initial.headers["Location"]))
    assert completed.status_code == 303
    restored = invoke("/callback")
    assert body(restored) == {"loggedIn": True, "id": "user-id"}
    assert restored.headers["Cache-Control"] == "no-store"
    assert invoke("/logout").status_code == 303
    assert body(invoke("/signed-out")) == {"loggedIn": False, "id": None}


def test_asgi_callback_exception_persists_marker():
    from fastapi import FastAPI, Request
    from fastapi.testclient import TestClient
    from authwave.integrations.fastapi import AuthwaveMiddleware

    calls = []

    def callback(user):
        calls.append(user.id)
        raise RuntimeError("app failed")

    app = FastAPI()
    app.add_middleware(
        AuthwaveMiddleware,
        session_options=SessionOptions(MemorySessionStore(), secure_cookie=False),
        client_key=KEY,
        on_authenticated=callback,
    )

    @app.get("/{path:path}")
    def view(request: Request):
        return action(request.state.authwave, request.url.path)

    client = TestClient(app)
    initial = client.get("/login", follow_redirects=False)
    path = provider_response(initial.headers["Location"])
    with pytest.raises(RuntimeError, match="app failed"):
        client.get(path, follow_redirects=False)
    assert client.get(path, follow_redirects=False).status_code == 303
    assert calls == ["user-id"]


def test_wsgi_preserves_write_and_yield_order():
    from authwave.integrations.wsgi import AuthwaveWSGI
    from werkzeug.test import Client
    from werkzeug.wrappers import Response

    def app(environ, start_response):
        write = start_response("200 OK", [])
        write(b"first")
        yield b"second"
        write(b"third")
        yield b"fourth"

    client = Client(
        AuthwaveWSGI(app, SessionOptions(MemorySessionStore()), client_key=KEY),
        Response,
    )
    assert client.get("/").data == b"firstsecondthirdfourth"


def test_store_failure_prevents_wsgi_output():
    from authwave.integrations.wsgi import AuthwaveWSGI

    class FailingStore:
        def load(self, id):
            return None

        def save(self, id, data, expires_at):
            raise RuntimeError("save failed")

    def app(environ, start_response):
        environ["authwave.auth"].login()

    sent = []
    wrapped = AuthwaveWSGI(app, SessionOptions(FailingStore()), client_key=KEY)
    with pytest.raises(RuntimeError, match="save failed"):
        wrapped({"PATH_INFO": "/login"}, lambda *args: sent.append(args))
    assert sent == []


def test_asgi_passes_lifespan_through():
    import asyncio
    from authwave.integrations.asgi import AuthwaveASGI

    received = []

    async def app(scope, receive, send):
        received.append(scope["type"])

    async def unused():
        raise AssertionError("Unexpected receive")

    wrapped = AuthwaveASGI(app, SessionOptions(MemorySessionStore()), client_key=KEY)
    asyncio.run(wrapped({"type": "lifespan"}, unused, unused))
    assert received == ["lifespan"]
